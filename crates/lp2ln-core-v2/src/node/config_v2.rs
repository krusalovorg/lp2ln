//! Config schema v2 helpers (P3-07/P3-08).
//!
//! Public surface prefers intention fields (`topology_profile`, listen/seed/IPC/…).
//! Full `topology_tuning` remains loadable as advanced override with soft diagnostics.
//! Missing `schema_version` is treated as v1 and can be migrated in place.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use super::autonomy::{ValidationReport, validate_options};
use super::options::NodeOptions;

/// Current public config schema version.
pub const CONFIG_SCHEMA_VERSION: u32 = 2;

/// Keys recommended for operators (documented public surface).
pub const PUBLIC_CONFIG_KEYS: &[&str] = &[
    "schema_version",
    "listens",
    "advertise_addrs",
    "default_nodes",
    "bootstrap_nodes",
    "seed_nodes",
    "bootstrap_peer_hints",
    "private_key_hex",
    "allow_unsigned_packets",
    "node_role",
    "topology_profile",
    "peer_connection_policy",
    "lan_discovery",
    "app_plane_ipc",
    "logger_options",
    "database_dir",
    "experimental",
    "debug_server",
    "ipc_tcp",
];

/// Keys accepted but considered advanced / internal for v2 operators.
pub const ADVANCED_CONFIG_KEYS: &[&str] = &[
    "topology_tuning",
    "peer_score_weights",
    "dial_policy",
    "quic",
    "transport_obfuscation",
    "transport_obfuscation_enabled",
    "catalog_max_peers",
    "peer_discovery_random_fraction",
    "flow_trace",
    "direct_upgrade",
    "router_incoming_queue_cap",
    "router_broadcast_cap",
    "router_process_concurrency",
    "signature_format",
    "enable_topology_maintenance",
    "event_bus_broadcast_cap",
    "stop_on_permanent_degradation",
    "topology_react_to_session_events",
    "log_peer_score_snapshot",
    "session_join_timeout_secs",
    "supervisor_shutdown_timeout_secs",
];

#[derive(Debug, Clone, Default)]
pub struct ConfigLoadReport {
    pub schema_version: u32,
    pub unknown_fields: Vec<String>,
    pub advanced_fields: Vec<String>,
    pub deprecated_notes: Vec<String>,
    pub soft_warnings: Vec<String>,
    pub migrated_from_v1: bool,
}

impl ConfigLoadReport {
    pub fn all_soft_messages(&self) -> Vec<String> {
        let mut out = Vec::new();
        out.extend(self.soft_warnings.iter().cloned());
        for f in &self.unknown_fields {
            out.push(format!("soft.unknown_field: '{f}' is not a known config key"));
        }
        for f in &self.advanced_fields {
            out.push(format!(
                "soft.advanced_field: '{f}' is advanced; prefer public surface / topology_profile"
            ));
        }
        out.extend(self.deprecated_notes.iter().cloned());
        out
    }
}

#[derive(Debug, Clone)]
pub struct ConfigCheckResult {
    pub load: ConfigLoadReport,
    pub validation: ValidationReport,
}

impl ConfigCheckResult {
    pub fn is_ok(&self) -> bool {
        self.validation.is_strict_ok() && self.load.unknown_fields.is_empty()
    }

    pub fn exit_message(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "schema_version={} (current={CONFIG_SCHEMA_VERSION})",
            self.load.schema_version
        ));
        if self.load.migrated_from_v1 {
            lines.push("note: file had no schema_version (treated as v1)".into());
        }
        for e in &self.validation.strict_errors {
            lines.push(format!("ERROR: {e}"));
        }
        for w in self.load.all_soft_messages() {
            lines.push(format!("WARN: {w}"));
        }
        for w in &self.validation.soft_warnings {
            lines.push(format!("WARN: {w}"));
        }
        if self.is_ok() && self.validation.soft_warnings.is_empty() && self.load.all_soft_messages().is_empty()
        {
            lines.push("ok".into());
        } else if self.validation.is_strict_ok() {
            lines.push("ok (with warnings)".into());
        } else {
            lines.push("failed".into());
        }
        lines.join("\n")
    }
}

/// Parse JSON into options + diagnostics (unknown / advanced / deprecated).
pub fn load_json_with_report(raw: &str) -> Result<(NodeOptions, ConfigLoadReport), String> {
    let value: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    let report = diagnose_value(&value);
    let opts = NodeOptions::from_json(raw)?;
    Ok((opts, report))
}

pub fn diagnose_value(value: &Value) -> ConfigLoadReport {
    let mut report = ConfigLoadReport::default();
    let obj = match value.as_object() {
        Some(o) => o,
        None => {
            report
                .soft_warnings
                .push("soft.schema: root must be a JSON object".into());
            return report;
        }
    };

    let schema = obj
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    match schema {
        Some(v) => {
            report.schema_version = v;
            if v > CONFIG_SCHEMA_VERSION {
                report.soft_warnings.push(format!(
                    "soft.schema_version: file is v{v}, runtime knows up to v{CONFIG_SCHEMA_VERSION}"
                ));
            }
        }
        None => {
            report.schema_version = 1;
            report.migrated_from_v1 = true;
            report.deprecated_notes.push(
                "soft.schema_version: missing (v1); run `lp2lnd config migrate` for schema v2"
                    .into(),
            );
        }
    }

    let public: BTreeSet<&str> = PUBLIC_CONFIG_KEYS.iter().copied().collect();
    let advanced: BTreeSet<&str> = ADVANCED_CONFIG_KEYS.iter().copied().collect();

    for key in obj.keys() {
        if public.contains(key.as_str()) {
            continue;
        }
        if advanced.contains(key.as_str()) {
            if report.schema_version >= 2 || report.migrated_from_v1 {
                report.advanced_fields.push(key.clone());
            }
            continue;
        }
        report.unknown_fields.push(key.clone());
    }

    if obj.contains_key("topology_tuning") && !obj.contains_key("topology_profile") {
        report.deprecated_notes.push(
            "soft.topology_profile: prefer topology_profile (conservative|balanced|aggressive); topology_tuning is advanced"
                .into(),
        );
    }

    if obj
        .get("node_role")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s == "bootstrap_join")
    {
        report.deprecated_notes.push(
            "soft.node_role: bootstrap_join is deprecated (treated as regular)".into(),
        );
    }

    report
}

/// Rewrite JSON to schema v2: set schema_version, ensure topology_profile.
pub fn migrate_json_to_v2(raw: &str) -> Result<String, String> {
    let mut value: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    let obj = value
        .as_object_mut()
        .ok_or_else(|| "root must be a JSON object".to_string())?;

    obj.insert("schema_version".into(), json!(CONFIG_SCHEMA_VERSION));

    if !obj.contains_key("topology_profile") {
        let profile = obj
            .get("topology_tuning")
            .and_then(|t| t.get("adaptive_profile"))
            .cloned()
            .unwrap_or_else(|| json!("balanced"));
        obj.insert("topology_profile".into(), profile);
    }

    // Prefer seed_nodes alias documentation: keep bootstrap_nodes if present.
    serde_json::to_string_pretty(&value).map_err(|e| e.to_string())
}

pub fn check_file(path: impl AsRef<Path>) -> Result<ConfigCheckResult, String> {
    let raw = fs::read_to_string(path.as_ref()).map_err(|e| e.to_string())?;
    let (opts, load) = load_json_with_report(&raw)?;
    let validation = validate_options(&opts);
    Ok(ConfigCheckResult { load, validation })
}

pub fn migrate_file(path: impl AsRef<Path>) -> Result<String, String> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let migrated = migrate_json_to_v2(&raw)?;
    // Validate migrated content still loads.
    let _ = load_json_with_report(&migrated)?;
    fs::write(path, &migrated).map_err(|e| e.to_string())?;
    Ok(migrated)
}

/// Minimal documented public example (schema v2).
pub fn public_example_json() -> String {
    let example = json!({
        "schema_version": CONFIG_SCHEMA_VERSION,
        "listens": {
            "tcp": "0.0.0.0:18090",
            "udp": "0.0.0.0:18190"
        },
        "advertise_addrs": null,
        "seed_nodes": [],
        "default_nodes": [],
        "private_key_hex": null,
        "allow_unsigned_packets": true,
        "node_role": "regular",
        "topology_profile": "balanced",
        "peer_connection_policy": {
            "min_active_peers": 2,
            "target_active_peers": 6,
            "max_active_peers": 14
        },
        "lan_discovery": {
            "enabled": true
        },
        "app_plane_ipc": {
            "path": if cfg!(windows) { r"\\.\pipe\lp2ln-app" } else { "/tmp/lp2ln-app.sock" },
            "dev_tcp_bind": null,
            "app_token": null,
            "allowed_protocol_ids": []
        },
        "logger_options": {
            "log_dir": "./logs",
            "file_enabled": true,
            "show_debug": true,
            "show_info": true,
            "show_warning": true,
            "show_error": true
        },
        "database_dir": "./db",
        "experimental": {
            "dht": false,
            "content": false,
            "repair": false,
            "app_plane": false
        }
    });
    serde_json::to_string_pretty(&example).expect("example json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_missing_schema_is_diagnosed() {
        let raw = r#"{
            "listens": {"tcp": "127.0.0.1:0"},
            "topology_tuning": {"dial_retry_cooldown_ms": 5000}
        }"#;
        let (_opts, report) = load_json_with_report(raw).unwrap();
        assert_eq!(report.schema_version, 1);
        assert!(report.migrated_from_v1);
        assert!(report.advanced_fields.iter().any(|f| f == "topology_tuning"));
    }

    #[test]
    fn migrate_adds_schema_and_profile() {
        let raw = r#"{"listens":{"tcp":"127.0.0.1:9"},"topology_tuning":{"adaptive_profile":"aggressive"}}"#;
        let out = migrate_json_to_v2(raw).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["schema_version"], CONFIG_SCHEMA_VERSION);
        assert_eq!(v["topology_profile"], "aggressive");
    }

    #[test]
    fn unknown_field_reported() {
        let raw = r#"{"schema_version":2,"listens":{"tcp":"127.0.0.1:1"},"not_a_real_field":true}"#;
        let (_o, report) = load_json_with_report(raw).unwrap();
        assert!(report.unknown_fields.iter().any(|f| f == "not_a_real_field"));
    }

    #[test]
    fn topology_profile_applies() {
        let raw = r#"{
            "schema_version": 2,
            "listens": {"tcp": "127.0.0.1:2"},
            "topology_profile": "conservative"
        }"#;
        let (opts, report) = load_json_with_report(raw).unwrap();
        assert_eq!(report.schema_version, 2);
        assert_eq!(
            opts.topology_profile,
            crate::node::options::AdaptiveTopologyProfile::Conservative
        );
        assert_eq!(
            opts.topology_tuning.adaptive_profile,
            crate::node::options::AdaptiveTopologyProfile::Conservative
        );
    }

    #[test]
    fn public_example_loads() {
        let raw = public_example_json();
        let (opts, report) = load_json_with_report(&raw).unwrap();
        assert_eq!(report.schema_version, CONFIG_SCHEMA_VERSION);
        assert!(report.unknown_fields.is_empty());
        assert!(!opts.listens.is_empty());
    }
}
