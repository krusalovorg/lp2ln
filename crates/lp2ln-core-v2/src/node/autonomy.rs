use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde_json::json;

use super::{NodeOptions, NodeRole, NodeRuntime};

#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub strict_errors: Vec<String>,
    pub soft_warnings: Vec<String>,
}

impl ValidationReport {
    pub fn is_strict_ok(&self) -> bool {
        self.strict_errors.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupConfigSource {
    PrimaryConfig,
    LastKnownGood,
    DeveloperDefaults,
}

#[derive(Clone)]
pub struct StartupConfigResult {
    pub options: NodeOptions,
    pub source: StartupConfigSource,
    pub degraded_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RecoveryJournal {
    path: PathBuf,
}

impl RecoveryJournal {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn append_event(&self, stage: &str, payload: serde_json::Value) {
        let line = json!({
            "ts_ms": now_ms(),
            "stage": stage,
            "payload": payload,
        });
        if let Some(parent) = self.path.parent().map(Path::to_path_buf) {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(f, "{}", line);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfigAutonomy {
    options_path: Option<PathBuf>,
    lkg_path: Option<PathBuf>,
    pub journal: RecoveryJournal,
}

impl ConfigAutonomy {
    pub fn new(options_path: Option<PathBuf>) -> Self {
        let lkg_path = options_path
            .as_ref()
            .map(|p| p.with_extension("last-known-good.json"));
        let journal_path = options_path
            .as_ref()
            .map(|p| p.with_extension("recovery.journal.jsonl"))
            .unwrap_or_else(|| PathBuf::from("./logs/recovery.journal.jsonl"));
        Self {
            options_path,
            lkg_path,
            journal: RecoveryJournal::new(journal_path),
        }
    }

    pub fn load_startup(
        &self,
        developer_options: impl FnOnce() -> NodeOptions,
    ) -> anyhow::Result<StartupConfigResult> {
        let Some(path) = self.options_path.as_ref() else {
            self.journal
                .append_event("prepare", json!({"source": "developer_defaults"}));
            return Ok(StartupConfigResult {
                options: developer_options(),
                source: StartupConfigSource::DeveloperDefaults,
                degraded_reason: None,
            });
        };

        self.journal
            .append_event("prepare", json!({"path": path.display().to_string()}));
        let raw = match fs::read_to_string(path) {
            Ok(v) => v,
            Err(err) => {
                self.journal.append_event(
                    "rollback",
                    json!({"reason": "read_failed", "error": err.to_string()}),
                );
                return Ok(self.fallback_result(
                    "config read failed; using fallback".to_string(),
                    developer_options,
                ));
            }
        };
        let candidate = match NodeOptions::from_json(&raw) {
            Ok(v) => v,
            Err(err) => {
                self.journal
                    .append_event("rollback", json!({"reason": "parse_failed", "error": err}));
                return Ok(self.fallback_result(
                    "config parse failed; using fallback".to_string(),
                    developer_options,
                ));
            }
        };

        let report = validate_options(&candidate);
        self.journal.append_event(
            "validate",
            json!({
                "strict_errors": report.strict_errors,
                "soft_warnings": report.soft_warnings,
            }),
        );
        if report.is_strict_ok() {
            self.dry_run(&candidate)?;
            self.commit_last_known_good(&candidate)?;
            self.journal
                .append_event("commit", json!({"result": "ok", "source": "config"}));
            return Ok(StartupConfigResult {
                options: candidate,
                source: StartupConfigSource::PrimaryConfig,
                degraded_reason: None,
            });
        }

        if let Some(lkg) = self.try_load_lkg() {
            let reason = "strict validation failed; rolled back to last-known-good".to_string();
            self.journal.append_event(
                "rollback",
                json!({
                    "reason": reason,
                    "strict_errors": report.strict_errors,
                    "using_lkg": true,
                }),
            );
            return Ok(StartupConfigResult {
                options: lkg,
                source: StartupConfigSource::LastKnownGood,
                degraded_reason: Some(reason),
            });
        }

        self.journal.append_event(
            "rollback",
            json!({
                "strict_errors": report.strict_errors,
                "using_lkg": false,
                "fallback": "developer_defaults",
            }),
        );
        Ok(StartupConfigResult {
            options: developer_options(),
            source: StartupConfigSource::DeveloperDefaults,
            degraded_reason: Some("strict validation failed; LKG missing".to_string()),
        })
    }

    pub fn spawn_runtime_config_watcher(
        &self,
        node: Arc<NodeRuntime>,
        applied_options: Arc<RwLock<NodeOptions>>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let Some(path) = self.options_path.clone() else {
            return None;
        };
        let lkg_path = self.lkg_path.clone();
        let journal = self.journal.clone();
        Some(tokio::spawn(async move {
            let mut last_mtime: Option<std::time::SystemTime> = None;
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let metadata = match fs::metadata(&path) {
                    Ok(v) => v,
                    Err(err) => {
                        journal.append_event(
                            "observe",
                            json!({"status": "config_missing", "error": err.to_string()}),
                        );
                        continue;
                    }
                };
                let modified = metadata.modified().ok();
                if modified.is_some() && modified == last_mtime {
                    continue;
                }
                last_mtime = modified;

                let raw = match fs::read_to_string(&path) {
                    Ok(v) => v,
                    Err(err) => {
                        journal.append_event(
                            "prepare",
                            json!({"status": "read_failed", "error": err.to_string()}),
                        );
                        continue;
                    }
                };
                let candidate = match NodeOptions::from_json(&raw) {
                    Ok(v) => v,
                    Err(err) => {
                        journal.append_event(
                            "validate",
                            json!({"status": "parse_failed", "error": err}),
                        );
                        continue;
                    }
                };
                let report = validate_options(&candidate);
                if !report.is_strict_ok() {
                    journal.append_event(
                        "validate",
                        json!({"status": "strict_failed", "strict_errors": report.strict_errors}),
                    );
                    if let (Some(lkg_path), Ok(current)) =
                        (lkg_path.as_ref(), applied_options.read().map(|o| o.clone()))
                    {
                        let _ = current.save(lkg_path);
                    }
                    continue;
                }

                let mut changed = false;
                if let Ok(mut active) = applied_options.write() {
                    let strict_changes = strict_changes(&active, &candidate);
                    if !strict_changes.is_empty() {
                        journal.append_event(
                            "apply",
                            json!({
                                "status": "rejected_runtime_strict_change",
                                "changes": strict_changes,
                            }),
                        );
                        continue;
                    }
                    if active.peer_connection_policy != candidate.peer_connection_policy {
                        let applied = node
                            .set_peer_connection_policy(candidate.peer_connection_policy.clone());
                        active.peer_connection_policy = applied;
                        changed = true;
                    }
                }
                if changed {
                    journal.append_event(
                        "commit",
                        json!({"status": "runtime_soft_apply_ok", "path": path.display().to_string()}),
                    );
                }
            }
        }))
    }

    fn fallback_result(
        &self,
        reason: String,
        developer_options: impl FnOnce() -> NodeOptions,
    ) -> StartupConfigResult {
        if let Some(lkg) = self.try_load_lkg() {
            self.journal
                .append_event("rollback", json!({"reason": reason, "using_lkg": true}));
            return StartupConfigResult {
                options: lkg,
                source: StartupConfigSource::LastKnownGood,
                degraded_reason: Some(
                    "rolled back to last-known-good after config failure".to_string(),
                ),
            };
        }
        StartupConfigResult {
            options: developer_options(),
            source: StartupConfigSource::DeveloperDefaults,
            degraded_reason: Some(reason),
        }
    }

    fn dry_run(&self, options: &NodeOptions) -> anyhow::Result<()> {
        if options.listens.is_empty() {
            return Err(anyhow::anyhow!(
                "dry-run failed: no listener transports configured"
            ));
        }
        let _ = options.effective_peer_connection_policy();
        self.journal
            .append_event("dry-run", json!({"result": "ok"}));
        Ok(())
    }

    fn commit_last_known_good(&self, options: &NodeOptions) -> anyhow::Result<()> {
        if let Some(path) = self.lkg_path.as_ref() {
            options.save(path).map_err(anyhow::Error::msg)?;
        }
        Ok(())
    }

    fn try_load_lkg(&self) -> Option<NodeOptions> {
        let path = self.lkg_path.as_ref()?;
        NodeOptions::from_file(path).ok()
    }
}

pub fn validate_options(options: &NodeOptions) -> ValidationReport {
    let mut strict_errors = Vec::new();
    let mut soft_warnings = Vec::new();

    if options.keypair.is_none() {
        soft_warnings.push(
            "soft.keypair: private_key_hex is missing, runtime will load/generate keypair"
                .to_string(),
        );
    }
    if options.listens.is_empty() {
        strict_errors.push("critical.listens: at least one listener is required".to_string());
    }
    if options
        .database_dir
        .as_ref()
        .is_some_and(|p| p.as_os_str().is_empty())
    {
        strict_errors.push("critical.database_dir: empty path".to_string());
    }
    if matches!(options.node_role, NodeRole::BootstrapJoin)
        && options.bootstrap_nodes.is_empty()
        && options.default_nodes.is_empty()
    {
        strict_errors.push(
            "critical.bootstrap: bootstrap node requires bootstrap_nodes/default_nodes".to_string(),
        );
    }
    let p = options.peer_connection_policy.normalized();
    if p.max_active_peers > 128 {
        soft_warnings
            .push("soft.peer_connection_policy: max_active_peers is high (>128)".to_string());
    }
    if options.topology_tuning.dial_retry_cooldown_ms < 1_000 {
        soft_warnings
            .push("soft.topology_tuning: dial_retry_cooldown_ms is too small (<1000)".to_string());
    }

    ValidationReport {
        strict_errors,
        soft_warnings,
    }
}

pub fn strict_changes(old: &NodeOptions, new: &NodeOptions) -> Vec<String> {
    let mut out = Vec::new();
    if old.allow_unsigned_packets != new.allow_unsigned_packets {
        out.push("critical.allow_unsigned_packets".to_string());
    }
    if old.node_role != new.node_role {
        out.push("critical.node_role".to_string());
    }
    if old.database_dir != new.database_dir {
        out.push("critical.database_dir".to_string());
    }
    if dashmap_to_btree(&old.listens) != dashmap_to_btree(&new.listens) {
        out.push("critical.listens".to_string());
    }
    if old.transport_obfuscation != new.transport_obfuscation {
        out.push("critical.transport_obfuscation".to_string());
    }
    out
}

fn dashmap_to_btree(
    map: &dashmap::DashMap<String, std::net::SocketAddr>,
) -> BTreeMap<String, std::net::SocketAddr> {
    map.iter()
        .map(|e| (e.key().clone(), *e.value()))
        .collect::<BTreeMap<_, _>>()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn strict_validation_does_not_fail_when_key_missing() {
        let mut opts = NodeOptions::new();
        opts.keypair = None;
        let report = validate_options(&opts);
        assert!(report.strict_errors.is_empty());
        assert!(!report.soft_warnings.is_empty());
    }

    #[test]
    fn strict_changes_detects_listener_update() {
        let a = NodeOptions::new();
        let b = NodeOptions::new().with_listen("tcp", "127.0.0.1:3010".parse().expect("addr"));
        let changes = strict_changes(&a, &b);
        assert!(changes.iter().any(|v| v == "critical.listens"));
    }

    #[test]
    fn startup_uses_lkg_after_parse_failure() {
        let path = temp_test_path("core-autonomy-parse-fail");
        let engine = ConfigAutonomy::new(Some(path.clone()));
        let valid = NodeOptions::new();
        valid.save(&path).expect("save valid config");
        let first = engine
            .load_startup(NodeOptions::new)
            .expect("initial load must work");
        assert_eq!(first.source, StartupConfigSource::PrimaryConfig);

        fs::write(&path, "{broken json").expect("write malformed json");
        let second = engine
            .load_startup(NodeOptions::new)
            .expect("must fallback to lkg");
        assert_eq!(second.source, StartupConfigSource::LastKnownGood);
    }

    fn temp_test_path(name: &str) -> PathBuf {
        let ts = now_ms();
        std::env::temp_dir().join(format!("{}-{}.json", name, ts))
    }
}
