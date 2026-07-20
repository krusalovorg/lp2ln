pub mod debug;
pub mod experimental;
pub mod topology;
pub mod transport;

pub use debug::{DebugServerOptions, FlowTraceOptions, IpcTcpOptions};
pub use experimental::{AppPlaneIpcOptions, ExperimentalOptions, default_app_plane_path};
pub use topology::{AdaptiveTopologyProfile, TopologyTuning};
pub use transport::{DialPolicy, DirectUpgradeConfig, LanDiscoveryOptions};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::crypto::NodeKeypair;
use crate::crypto::signature::SignatureFormat;
use crate::logger::LoggerOptions;
use crate::peer_score::{PeerConnectionPolicy, PeerScoreWeights};
use crate::transport::obfuscation::ObfuscationConfig;
use crate::transport::quic::QuicTransportOptions;
use crate::types::PeerId;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    #[default]
    Regular,
    BootstrapJoin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapNode {
    pub addr: SocketAddr,
    pub protocols: Vec<String>,
    pub peer_id_hint: Option<PeerId>,
}

impl BootstrapNode {
    pub fn new(
        addr: SocketAddr,
        protocols: impl IntoIterator<Item = impl Into<String>>,
        peer_id_hint: Option<PeerId>,
    ) -> Self {
        let mut protocols: Vec<String> = protocols.into_iter().map(Into::into).collect();
        if protocols.is_empty() {
            protocols.push("tcp".to_string());
        }
        Self { addr, protocols, peer_id_hint }
    }
}

#[derive(Clone)]
pub struct NodeOptions {
    pub listens: DashMap<String, SocketAddr>,
    pub advertise_addrs: HashMap<String, SocketAddr>,
    pub default_nodes: Vec<SocketAddr>,
    pub keypair: Option<NodeKeypair>,
    pub allow_unsigned_packets: bool,
    pub logger_options: Option<LoggerOptions>,
    pub peer_connection_policy: PeerConnectionPolicy,
    pub peer_score_weights: PeerScoreWeights,
    pub bootstrap_peer_hints: HashMap<SocketAddr, PeerId>,
    pub bootstrap_nodes: Vec<BootstrapNode>,
    pub database_dir: Option<PathBuf>,
    pub log_peer_score_snapshot: bool,
    pub node_role: NodeRole,
    pub catalog_max_peers: Option<usize>,
    pub peer_discovery_random_fraction: f32,
    pub transport_obfuscation: HashMap<String, ObfuscationConfig>,
    pub quic: QuicTransportOptions,
    pub topology_tuning: TopologyTuning,
    pub flow_trace: FlowTraceOptions,
    pub debug_server: DebugServerOptions,
    pub ipc_tcp: IpcTcpOptions,
    /// Local App Plane IPC path / optional dev TCP (see [`AppPlaneIpcOptions`]).
    pub app_plane_ipc: AppPlaneIpcOptions,
    pub direct_upgrade: DirectUpgradeConfig,
    pub session_join_timeout_secs: u64,
    pub supervisor_shutdown_timeout_secs: u64,
    pub router_incoming_queue_cap: usize,
    pub router_broadcast_cap: usize,
    /// Concurrent packet processor workers (bounded pool).
    pub router_process_concurrency: usize,
    /// Outgoing packet signature format (only `v3_hash` is supported).
    pub signature_format: SignatureFormat,
    /// Experimental DHT/content/repair/App Plane opt-ins (default all off).
    pub experimental: ExperimentalOptions,
    /// When false the topology-maintenance task is not started (useful for test nodes).
    pub enable_topology_maintenance: bool,
    /// Broadcast capacity for the internal CoreBus observer channel.
    pub event_bus_broadcast_cap: usize,
    /// When true, permanent subsystem degradation triggers graceful `stop()`.
    pub stop_on_permanent_degradation: bool,
    /// When true, topology reacts to session-close events via CoreBus handlers.
    pub topology_react_to_session_events: bool,
    pub dial_policy: DialPolicy,
    pub lan_discovery: LanDiscoveryOptions,
    /// Config schema version (P3-07). Missing on disk ⇒ treated as 1 at load.
    pub schema_version: u32,
    /// Named topology profile (public surface). Synced into `topology_tuning.adaptive_profile`.
    pub topology_profile: AdaptiveTopologyProfile,
    /// Compressed-point hex of the trusted release signing key (P5).
    pub trusted_release_key: Option<String>,
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeOptions {
    pub fn new() -> Self {
        let mut options = Self {
            listens: DashMap::new(),
            advertise_addrs: HashMap::new(),
            default_nodes: vec![],
            keypair: Some(NodeKeypair::generate()),
            allow_unsigned_packets: false,
            peer_connection_policy: PeerConnectionPolicy::default(),
            peer_score_weights: PeerScoreWeights::default(),
            bootstrap_peer_hints: HashMap::new(),
            bootstrap_nodes: vec![],
            database_dir: None,
            log_peer_score_snapshot: false,
            node_role: NodeRole::Regular,
            catalog_max_peers: None,
            peer_discovery_random_fraction: 0.33,
            transport_obfuscation: default_transport_obfuscation(),
            quic: QuicTransportOptions::default(),
            topology_tuning: TopologyTuning::default(),
            flow_trace: FlowTraceOptions::default(),
            debug_server: DebugServerOptions::default(),
            ipc_tcp: IpcTcpOptions::default(),
            app_plane_ipc: AppPlaneIpcOptions::default(),
            direct_upgrade: DirectUpgradeConfig::default(),
            session_join_timeout_secs: 2,
            supervisor_shutdown_timeout_secs: 10,
            router_incoming_queue_cap: 16384,
            router_broadcast_cap: 4096,
            router_process_concurrency: crate::router::ROUTER_PROCESS_SEMAPHORE_PERMITS,
            signature_format: SignatureFormat::V3Hash,
            experimental: ExperimentalOptions::default(),
            enable_topology_maintenance: true,
            event_bus_broadcast_cap: 4096,
            stop_on_permanent_degradation: false,
            topology_react_to_session_events: false,
            dial_policy: DialPolicy::default(),
            lan_discovery: LanDiscoveryOptions::default(),
            schema_version: super::config_v2::CONFIG_SCHEMA_VERSION,
            topology_profile: AdaptiveTopologyProfile::default(),
            trusted_release_key: None,
            logger_options: Some(LoggerOptions {
                log_dir: Some(PathBuf::from("./logs")),
                file_enabled: true,
                show_debug: true,
                show_info: true,
                show_warning: true,
                show_error: true,
            }),
        };
        options.default_listens();
        options
    }

    pub fn empty() -> Self {
        Self {
            listens: DashMap::new(),
            advertise_addrs: HashMap::new(),
            default_nodes: vec![],
            keypair: None,
            allow_unsigned_packets: true,
            peer_connection_policy: PeerConnectionPolicy::default(),
            peer_score_weights: PeerScoreWeights::default(),
            bootstrap_peer_hints: HashMap::new(),
            bootstrap_nodes: vec![],
            database_dir: None,
            log_peer_score_snapshot: false,
            node_role: NodeRole::Regular,
            catalog_max_peers: None,
            peer_discovery_random_fraction: 0.33,
            transport_obfuscation: HashMap::new(),
            quic: QuicTransportOptions::default(),
            topology_tuning: TopologyTuning::default(),
            flow_trace: FlowTraceOptions::default(),
            debug_server: DebugServerOptions::default(),
            ipc_tcp: IpcTcpOptions::default(),
            app_plane_ipc: AppPlaneIpcOptions::default(),
            direct_upgrade: DirectUpgradeConfig::default(),
            session_join_timeout_secs: 2,
            supervisor_shutdown_timeout_secs: 10,
            router_incoming_queue_cap: 16384,
            router_broadcast_cap: 4096,
            router_process_concurrency: crate::router::ROUTER_PROCESS_SEMAPHORE_PERMITS,
            signature_format: SignatureFormat::V3Hash,
            experimental: ExperimentalOptions::default(),
            enable_topology_maintenance: true,
            event_bus_broadcast_cap: 4096,
            stop_on_permanent_degradation: false,
            topology_react_to_session_events: false,
            dial_policy: DialPolicy::default(),
            lan_discovery: LanDiscoveryOptions::default(),
            schema_version: super::config_v2::CONFIG_SCHEMA_VERSION,
            topology_profile: AdaptiveTopologyProfile::default(),
            trusted_release_key: None,
            logger_options: Some(LoggerOptions::default()),
        }
    }

    pub fn effective_peer_connection_policy_for(
        peer_connection_policy: PeerConnectionPolicy,
        _role: NodeRole,
    ) -> PeerConnectionPolicy {
        // BootstrapJoin is deprecated and treated identically to Regular.
        peer_connection_policy.normalized()
    }

    pub fn effective_peer_connection_policy(&self) -> PeerConnectionPolicy {
        Self::effective_peer_connection_policy_for(
            self.peer_connection_policy.clone(),
            self.node_role,
        )
    }

    pub fn with_peer_connection_policy(mut self, policy: PeerConnectionPolicy) -> Self {
        self.peer_connection_policy = policy;
        self
    }

    pub fn with_peer_score_weights(mut self, weights: PeerScoreWeights) -> Self {
        self.peer_score_weights = weights;
        self
    }

    pub fn with_bootstrap_peer_hints(mut self, hints: HashMap<SocketAddr, PeerId>) -> Self {
        self.bootstrap_peer_hints = hints;
        self
    }

    pub fn with_bootstrap_nodes(mut self, nodes: Vec<BootstrapNode>) -> Self {
        self.bootstrap_nodes = nodes;
        self
    }

    pub fn add_bootstrap_node(
        mut self,
        addr: SocketAddr,
        protocols: impl IntoIterator<Item = impl Into<String>>,
        peer_id_hint: Option<PeerId>,
    ) -> Self {
        self.bootstrap_nodes
            .push(BootstrapNode::new(addr, protocols, peer_id_hint.clone()));
        if let Some(peer_id) = peer_id_hint {
            self.bootstrap_peer_hints.insert(addr, peer_id);
        }
        self
    }

    pub fn keypair(mut self, keypair: NodeKeypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    pub fn keypair_from_hex(mut self, hex: &str) -> Result<Self, String> {
        self.keypair = Some(NodeKeypair::from_hex(hex)?);
        Ok(self)
    }

    pub fn keypair_generate(mut self) -> Self {
        self.keypair = Some(NodeKeypair::generate());
        self
    }

    pub fn allow_unsigned_packets(mut self, allow: bool) -> Self {
        self.allow_unsigned_packets = allow;
        self
    }

    pub fn default_listens(&mut self) -> &mut Self {
        self.set_listen("tcp".to_string(), "0.0.0.0:8080".parse::<SocketAddr>().unwrap());
        self.set_listen("udp".to_string(), "0.0.0.0:8081".parse::<SocketAddr>().unwrap());
        self.set_listen("quic".to_string(), "0.0.0.0:8082".parse::<SocketAddr>().unwrap());
        self
    }

    pub fn set_listen(&mut self, protocol: String, addr: SocketAddr) -> &mut Self {
        self.listens.insert(protocol, addr);
        self
    }

    pub fn with_listen(self, protocol: impl Into<String>, addr: SocketAddr) -> Self {
        self.listens.insert(protocol.into(), addr);
        self
    }

    pub fn set_advertise(&mut self, protocol: String, addr: SocketAddr) -> &mut Self {
        self.advertise_addrs.insert(protocol, addr);
        self
    }

    pub fn with_advertise(mut self, protocol: impl Into<String>, addr: SocketAddr) -> Self {
        self.advertise_addrs.insert(protocol.into(), addr);
        self
    }

    pub fn with_default_nodes(mut self, nodes: Vec<SocketAddr>) -> Self {
        self.default_nodes = nodes;
        self
    }

    pub fn with_transport_obfuscation(
        mut self,
        protocol: impl Into<String>,
        config: ObfuscationConfig,
    ) -> Self {
        self.transport_obfuscation
            .insert(protocol.into().to_ascii_lowercase(), config);
        self
    }

    pub fn set_transport_obfuscation(
        &mut self,
        protocol: impl Into<String>,
        config: ObfuscationConfig,
    ) -> &mut Self {
        self.transport_obfuscation
            .insert(protocol.into().to_ascii_lowercase(), config);
        self
    }

    pub fn disable_transport_obfuscation(&mut self, protocol: &str) -> &mut Self {
        self.transport_obfuscation.remove(&protocol.to_ascii_lowercase());
        self
    }

    pub fn transport_obfuscation_for(&self, protocol: &str) -> Option<ObfuscationConfig> {
        self.transport_obfuscation
            .get(&protocol.to_ascii_lowercase())
            .cloned()
    }

    pub fn with_logger_options(mut self, opts: LoggerOptions) -> Self {
        self.logger_options = Some(opts);
        self
    }

    pub fn add_node(&mut self, node: SocketAddr) -> &mut Self {
        self.default_nodes.push(node);
        self
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        super::options_file::from_file(path)
    }

    pub fn from_json(s: &str) -> Result<Self, String> {
        super::options_file::from_json(s)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), String> {
        super::options_file::save(self, path)
    }
}

pub(super) fn default_true() -> bool {
    true
}

pub(super) fn default_transport_obfuscation() -> HashMap<String, ObfuscationConfig> {
    HashMap::from([
        ("tcp".to_string(), ObfuscationConfig::default()),
        ("udp".to_string(), ObfuscationConfig::default()),
        ("quic".to_string(), ObfuscationConfig::default()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn experimental_defaults() {
        // dht + content are on by default; repair + app_plane remain opt-in.
        let opts = NodeOptions::empty();
        assert!(opts.experimental.dht);
        assert!(opts.experimental.content);
        assert!(!opts.experimental.repair);
        assert!(!opts.experimental.app_plane);
        assert!(opts.experimental.any_enabled());

        // serde: missing fields get their defaults (dht/content → true).
        let parsed: ExperimentalOptions = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed, ExperimentalOptions::default());
        assert!(parsed.dht);
        assert!(parsed.content);

        // explicit false is honoured.
        let disabled: ExperimentalOptions =
            serde_json::from_str(r#"{"dht":false,"content":false}"#).unwrap();
        assert!(!disabled.dht);
        assert!(!disabled.content);
    }
}
