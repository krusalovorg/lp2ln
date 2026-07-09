use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::crypto::NodeKeypair;
use crate::logger::LoggerOptions;
use crate::peer_score::{PeerConnectionPolicy, PeerScoreWeights};
use crate::transport::obfuscation::ObfuscationConfig;
use crate::types::PeerId;

use super::options::{
    BootstrapNode, DebugServerOptions, DirectUpgradeConfig, FlowTraceOptions, IpcTcpOptions,
    NodeOptions, NodeRole, TopologyTuning, default_transport_obfuscation,
};

pub(super) fn from_file(path: impl AsRef<Path>) -> Result<NodeOptions, String> {
    let data = fs::read_to_string(path.as_ref()).map_err(|e| e.to_string())?;
    from_json(&data)
}

pub(super) fn from_json(s: &str) -> Result<NodeOptions, String> {
    let file: NodeOptionsFile = serde_json::from_str(s).map_err(|e| e.to_string())?;
    file.try_into()
}

pub(super) fn save(opts: &NodeOptions, path: impl AsRef<Path>) -> Result<(), String> {
    let file: NodeOptionsFile = opts.into();
    let data = serde_json::to_string_pretty(&file).map_err(|e| e.to_string())?;
    fs::write(path.as_ref(), data).map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoggerOptionsFile {
    #[serde(default, alias = "file_path")]
    log_dir: Option<String>,
    #[serde(default = "super::options::default_true")]
    file_enabled: bool,
    #[serde(default = "super::options::default_true")]
    show_debug: bool,
    #[serde(default = "super::options::default_true")]
    show_info: bool,
    #[serde(default = "super::options::default_true")]
    show_warning: bool,
    #[serde(default = "super::options::default_true")]
    show_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeOptionsFile {
    #[serde(default)]
    listens: HashMap<String, String>,
    #[serde(default)]
    advertise_addrs: Option<HashMap<String, String>>,
    #[serde(default)]
    default_nodes: Vec<String>,
    private_key_hex: Option<String>,
    #[serde(default = "default_allow_unsigned")]
    allow_unsigned_packets: bool,
    #[serde(default)]
    logger_options: Option<LoggerOptionsFile>,
    #[serde(default)]
    peer_connection_policy: Option<PeerConnectionPolicy>,
    #[serde(default)]
    peer_score_weights: Option<PeerScoreWeights>,
    /// `"addr" -> peer_id` strings for JSON maps.
    #[serde(default)]
    bootstrap_peer_hints: Option<HashMap<String, String>>,
    #[serde(default)]
    bootstrap_nodes: Option<Vec<BootstrapNodeFile>>,
    #[serde(default)]
    database_dir: Option<String>,
    #[serde(default)]
    log_peer_score_snapshot: bool,
    #[serde(default)]
    node_role: NodeRole,
    #[serde(default)]
    catalog_max_peers: Option<u64>,
    #[serde(default = "default_peer_discovery_random_fraction")]
    peer_discovery_random_fraction: f32,
    #[serde(default)]
    transport_obfuscation: HashMap<String, ObfuscationConfig>,
    #[serde(default)]
    transport_obfuscation_enabled: HashMap<String, bool>,
    #[serde(default)]
    topology_tuning: TopologyTuning,
    #[serde(default)]
    flow_trace: FlowTraceOptions,
    #[serde(default)]
    debug_server: DebugServerOptions,
    #[serde(default)]
    ipc_tcp: IpcTcpOptions,
    #[serde(default)]
    direct_upgrade: DirectUpgradeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BootstrapNodeFile {
    addr: String,
    #[serde(default)]
    protocols: Vec<String>,
    #[serde(default)]
    peer_id_hint: Option<String>,
}

fn default_allow_unsigned() -> bool {
    true
}

fn default_peer_discovery_random_fraction() -> f32 {
    0.33
}

impl From<LoggerOptionsFile> for LoggerOptions {
    fn from(f: LoggerOptionsFile) -> Self {
        let log_dir = f.log_dir.map(|s| {
            let p = PathBuf::from(&s);
            if p.extension().is_some() {
                p.parent().unwrap_or(&p).to_path_buf()
            } else {
                p
            }
        });
        Self {
            log_dir,
            file_enabled: f.file_enabled,
            show_debug: f.show_debug,
            show_info: f.show_info,
            show_warning: f.show_warning,
            show_error: f.show_error,
        }
    }
}

impl From<&LoggerOptions> for LoggerOptionsFile {
    fn from(o: &LoggerOptions) -> Self {
        Self {
            log_dir: o.log_dir.as_ref().map(|p| p.to_string_lossy().into_owned()),
            file_enabled: o.file_enabled,
            show_debug: o.show_debug,
            show_info: o.show_info,
            show_warning: o.show_warning,
            show_error: o.show_error,
        }
    }
}

impl TryFrom<NodeOptionsFile> for NodeOptions {
    type Error = String;

    fn try_from(file: NodeOptionsFile) -> Result<Self, String> {
        let mut options = Self {
            listens: DashMap::new(),
            advertise_addrs: HashMap::new(),
            default_nodes: vec![],
            keypair: None,
            allow_unsigned_packets: file.allow_unsigned_packets,
            logger_options: file.logger_options.map(LoggerOptions::from),
            peer_connection_policy: file.peer_connection_policy.unwrap_or_default(),
            peer_score_weights: file.peer_score_weights.unwrap_or_default(),
            bootstrap_peer_hints: HashMap::new(),
            bootstrap_nodes: vec![],
            database_dir: file.database_dir.map(PathBuf::from),
            log_peer_score_snapshot: file.log_peer_score_snapshot,
            node_role: file.node_role,
            catalog_max_peers: file
                .catalog_max_peers
                .map(|n| (n as usize).min(1_000_000).max(128)),
            peer_discovery_random_fraction: file.peer_discovery_random_fraction.clamp(0.0, 0.9),
            transport_obfuscation: {
                let mut map = default_transport_obfuscation();
                map.extend(
                    file.transport_obfuscation
                        .into_iter()
                        .map(|(k, v): (String, ObfuscationConfig)| (k.to_ascii_lowercase(), v)),
                );
                for (proto, enabled) in file.transport_obfuscation_enabled {
                    if !enabled {
                        map.remove(&proto.to_ascii_lowercase());
                    }
                }
                map
            },
            topology_tuning: file.topology_tuning,
            flow_trace: file.flow_trace,
            debug_server: file.debug_server,
            ipc_tcp: file.ipc_tcp,
            direct_upgrade: file.direct_upgrade,
            session_join_timeout_secs: 2,
            supervisor_shutdown_timeout_secs: 10,
        };
        for (protocol, addr_str) in file.listens {
            let addr: SocketAddr = addr_str
                .parse()
                .map_err(|e: std::net::AddrParseError| e.to_string())?;
            options.listens.insert(protocol, addr);
        }
        if let Some(map) = file.advertise_addrs {
            for (protocol, addr_str) in map {
                let addr: SocketAddr = addr_str
                    .parse()
                    .map_err(|e: std::net::AddrParseError| e.to_string())?;
                options.advertise_addrs.insert(protocol, addr);
            }
        }
        for addr_str in file.default_nodes {
            let addr: SocketAddr = addr_str
                .parse()
                .map_err(|e: std::net::AddrParseError| e.to_string())?;
            options.default_nodes.push(addr);
        }
        if let Some(map) = file.bootstrap_peer_hints {
            for (addr_s, peer_s) in map {
                let addr: SocketAddr = addr_s
                    .parse()
                    .map_err(|e: std::net::AddrParseError| e.to_string())?;
                options
                    .bootstrap_peer_hints
                    .insert(addr, PeerId::from(peer_s.as_str()));
            }
        }
        if let Some(nodes) = file.bootstrap_nodes {
            for n in nodes {
                let addr: SocketAddr = n
                    .addr
                    .parse()
                    .map_err(|e: std::net::AddrParseError| e.to_string())?;
                let protocols = if n.protocols.is_empty() {
                    vec!["tcp".to_string()]
                } else {
                    n.protocols
                };
                let peer_id_hint = n.peer_id_hint.as_deref().map(PeerId::from);
                if let Some(ref pid) = peer_id_hint {
                    options.bootstrap_peer_hints.insert(addr, pid.clone());
                }
                options.bootstrap_nodes.push(BootstrapNode {
                    addr,
                    protocols,
                    peer_id_hint,
                });
            }
        }
        if let Some(hex) = file.private_key_hex {
            options.keypair = Some(NodeKeypair::from_hex(&hex)?);
        }
        Ok(options)
    }
}

impl From<&NodeOptions> for NodeOptionsFile {
    fn from(opts: &NodeOptions) -> Self {
        let listens: HashMap<String, String> = opts
            .listens
            .iter()
            .map(|r| (r.key().clone(), r.value().to_string()))
            .collect();
        let default_nodes: Vec<String> = opts
            .default_nodes
            .iter()
            .map(SocketAddr::to_string)
            .collect();
        let advertise_addrs = if opts.advertise_addrs.is_empty() {
            None
        } else {
            Some(
                opts.advertise_addrs
                    .iter()
                    .map(|(p, a)| (p.clone(), a.to_string()))
                    .collect(),
            )
        };
        let private_key_hex = opts.keypair.as_ref().map(|k| k.to_hex());
        let logger_options = Some(
            opts.logger_options
                .as_ref()
                .map(LoggerOptionsFile::from)
                .unwrap_or_else(|| LoggerOptionsFile::from(&LoggerOptions::default())),
        );
        let bootstrap_peer_hints = if opts.bootstrap_peer_hints.is_empty() {
            None
        } else {
            Some(
                opts.bootstrap_peer_hints
                    .iter()
                    .map(|(a, p)| (a.to_string(), p.as_str().to_string()))
                    .collect(),
            )
        };
        let bootstrap_nodes = if opts.bootstrap_nodes.is_empty() {
            None
        } else {
            Some(
                opts.bootstrap_nodes
                    .iter()
                    .map(|n| BootstrapNodeFile {
                        addr: n.addr.to_string(),
                        protocols: n.protocols.clone(),
                        peer_id_hint: n.peer_id_hint.as_ref().map(|p| p.as_str().to_string()),
                    })
                    .collect(),
            )
        };
        Self {
            listens,
            advertise_addrs,
            default_nodes,
            private_key_hex,
            allow_unsigned_packets: opts.allow_unsigned_packets,
            logger_options,
            peer_connection_policy: Some(opts.peer_connection_policy.clone()),
            peer_score_weights: Some(opts.peer_score_weights.clone()),
            bootstrap_peer_hints,
            bootstrap_nodes,
            database_dir: opts
                .database_dir
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            log_peer_score_snapshot: opts.log_peer_score_snapshot,
            node_role: opts.node_role,
            catalog_max_peers: opts.catalog_max_peers.map(|n| n as u64),
            peer_discovery_random_fraction: opts.peer_discovery_random_fraction,
            transport_obfuscation: opts.transport_obfuscation.clone(),
            transport_obfuscation_enabled: opts
                .transport_obfuscation
                .keys()
                .map(|k| (k.clone(), true))
                .collect(),
            topology_tuning: opts.topology_tuning.clone(),
            flow_trace: opts.flow_trace.clone(),
            debug_server: opts.debug_server.clone(),
            ipc_tcp: opts.ipc_tcp.clone(),
            direct_upgrade: opts.direct_upgrade.clone(),
        }
    }
}
