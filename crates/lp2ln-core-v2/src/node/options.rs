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
        Self {
            addr,
            protocols,
            peer_id_hint,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum AdaptiveTopologyProfile {
    Conservative,
    #[default]
    Balanced,
    Aggressive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyTuning {
    #[serde(default = "default_regular_auto_target_min")]
    pub regular_auto_target_min: usize,
    #[serde(default = "default_regular_auto_target_max")]
    pub regular_auto_target_max: usize,
    #[serde(default = "default_regular_bootstrap_min_keep")]
    pub regular_bootstrap_min_keep: usize,
    #[serde(default = "default_regular_bootstrap_rejoin_interval_ms")]
    pub regular_bootstrap_rejoin_interval_ms: u64,
    #[serde(default = "default_regular_exploration_interval_ms")]
    pub regular_exploration_interval_ms: u64,
    #[serde(default = "default_dial_retry_cooldown_ms")]
    pub dial_retry_cooldown_ms: u64,
    #[serde(default = "default_prune_redial_cooldown_ms")]
    pub prune_redial_cooldown_ms: u64,
    #[serde(default = "default_bootstrap_stable_peer_threshold")]
    pub bootstrap_stable_peer_threshold: usize,
    #[serde(default = "default_true")]
    pub avoid_reseed_when_stable_bootstrap: bool,
    #[serde(default)]
    pub adaptive_topology_enabled: bool,
    #[serde(default)]
    pub adaptive_profile: AdaptiveTopologyProfile,
    #[serde(default = "default_adaptive_target_min_floor")]
    pub adaptive_target_min_floor: usize,
    #[serde(default = "default_adaptive_target_max_ceil")]
    pub adaptive_target_max_ceil: usize,
    #[serde(default = "default_adaptive_bootstrap_hard_max")]
    pub adaptive_bootstrap_hard_max: usize,
    #[serde(default = "default_adaptive_bootstrap_top_k")]
    pub adaptive_bootstrap_top_k: usize,
    #[serde(default = "default_adaptive_exploration_interval_min_ms")]
    pub adaptive_exploration_interval_min_ms: u64,
    #[serde(default = "default_adaptive_exploration_interval_max_ms")]
    pub adaptive_exploration_interval_max_ms: u64,
    #[serde(default = "default_adaptive_rejoin_cooldown_min_ms")]
    pub adaptive_rejoin_cooldown_min_ms: u64,
    #[serde(default = "default_adaptive_rejoin_cooldown_max_ms")]
    pub adaptive_rejoin_cooldown_max_ms: u64,
    #[serde(default = "default_adaptive_redirect_memory_ms")]
    pub adaptive_redirect_memory_ms: u64,
}

impl Default for TopologyTuning {
    fn default() -> Self {
        Self {
            regular_auto_target_min: default_regular_auto_target_min(),
            regular_auto_target_max: default_regular_auto_target_max(),
            regular_bootstrap_min_keep: default_regular_bootstrap_min_keep(),
            regular_bootstrap_rejoin_interval_ms: default_regular_bootstrap_rejoin_interval_ms(),
            regular_exploration_interval_ms: default_regular_exploration_interval_ms(),
            dial_retry_cooldown_ms: default_dial_retry_cooldown_ms(),
            prune_redial_cooldown_ms: default_prune_redial_cooldown_ms(),
            bootstrap_stable_peer_threshold: default_bootstrap_stable_peer_threshold(),
            avoid_reseed_when_stable_bootstrap: true,
            adaptive_topology_enabled: false,
            adaptive_profile: AdaptiveTopologyProfile::default(),
            adaptive_target_min_floor: default_adaptive_target_min_floor(),
            adaptive_target_max_ceil: default_adaptive_target_max_ceil(),
            adaptive_bootstrap_hard_max: default_adaptive_bootstrap_hard_max(),
            adaptive_bootstrap_top_k: default_adaptive_bootstrap_top_k(),
            adaptive_exploration_interval_min_ms: default_adaptive_exploration_interval_min_ms(),
            adaptive_exploration_interval_max_ms: default_adaptive_exploration_interval_max_ms(),
            adaptive_rejoin_cooldown_min_ms: default_adaptive_rejoin_cooldown_min_ms(),
            adaptive_rejoin_cooldown_max_ms: default_adaptive_rejoin_cooldown_max_ms(),
            adaptive_redirect_memory_ms: default_adaptive_redirect_memory_ms(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowTraceOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub json_packets: bool,
    #[serde(default = "default_flow_trace_payload_preview_bytes")]
    pub payload_preview_bytes: usize,
}

impl Default for FlowTraceOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            json_packets: false,
            payload_preview_bytes: default_flow_trace_payload_preview_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugServerOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_debug_server_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_debug_server_push_interval_ms")]
    pub push_interval_ms: u64,
}

impl Default for DebugServerOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: default_debug_server_bind_addr(),
            push_interval_ms: default_debug_server_push_interval_ms(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcTcpOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ipc_tcp_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_true")]
    pub push_incoming_packets: bool,
    #[serde(default = "default_ipc_tcp_max_frame_bytes")]
    pub max_frame_bytes: u32,
}

impl Default for IpcTcpOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: default_ipc_tcp_bind_addr(),
            push_incoming_packets: true,
            max_frame_bytes: default_ipc_tcp_max_frame_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectUpgradeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_du_min_packets_per_window")]
    pub min_packets_per_window: usize,
    #[serde(default = "default_du_min_bytes_per_window")]
    pub min_bytes_per_window: u64,
    #[serde(default = "default_du_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_du_cooldown_secs")]
    pub cooldown_secs: u64,
    #[serde(default = "default_du_max_parallel_attempts")]
    pub max_parallel_attempts: usize,
    #[serde(default = "default_true")]
    pub prefer_lan_addrs: bool,
    #[serde(default)]
    pub try_nat_traversal: bool,
    #[serde(default = "default_du_direct_dial_timeout_ms")]
    pub direct_dial_timeout_ms: u64,
    #[serde(default = "default_du_event_queue_cap")]
    pub event_queue_cap: usize,
    #[serde(default = "default_du_tick_interval_ms")]
    pub tick_interval_ms: u64,
    #[serde(default = "default_du_max_tracker_peers")]
    pub max_tracker_peers: usize,
}

fn default_du_min_packets_per_window() -> usize {
    8
}

fn default_du_min_bytes_per_window() -> u64 {
    512
}

fn default_du_window_secs() -> u64 {
    30
}

fn default_du_cooldown_secs() -> u64 {
    60
}

fn default_du_max_parallel_attempts() -> usize {
    2
}

fn default_du_direct_dial_timeout_ms() -> u64 {
    5000
}

fn default_du_event_queue_cap() -> usize {
    4096
}

fn default_du_tick_interval_ms() -> u64 {
    500
}

fn default_du_max_tracker_peers() -> usize {
    2048
}

impl Default for DirectUpgradeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_packets_per_window: default_du_min_packets_per_window(),
            min_bytes_per_window: default_du_min_bytes_per_window(),
            window_secs: default_du_window_secs(),
            cooldown_secs: default_du_cooldown_secs(),
            max_parallel_attempts: default_du_max_parallel_attempts(),
            prefer_lan_addrs: true,
            try_nat_traversal: false,
            direct_dial_timeout_ms: default_du_direct_dial_timeout_ms(),
            event_queue_cap: default_du_event_queue_cap(),
            tick_interval_ms: default_du_tick_interval_ms(),
            max_tracker_peers: default_du_max_tracker_peers(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DialPolicy {
    /// Preferred transport order when dialing a peer. First matching transport wins.
    #[serde(default = "default_dial_policy_transport_order")]
    pub transport_order: Vec<String>,
    #[serde(default = "default_quic_connect_timeout_secs")]
    pub quic_connect_timeout_secs: u64,
    /// When true, QUIC transport degradation triggers session close + redial via fallback.
    #[serde(default = "default_true")]
    pub fallback_on_transport_degraded: bool,
}

fn default_dial_policy_transport_order() -> Vec<String> {
    vec!["quic".into(), "udp".into(), "tcp".into()]
}

fn default_quic_connect_timeout_secs() -> u64 {
    5
}

impl Default for DialPolicy {
    fn default() -> Self {
        Self {
            transport_order: default_dial_policy_transport_order(),
            quic_connect_timeout_secs: default_quic_connect_timeout_secs(),
            fallback_on_transport_degraded: true,
        }
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
    pub direct_upgrade: DirectUpgradeConfig,
    pub session_join_timeout_secs: u64,
    pub supervisor_shutdown_timeout_secs: u64,
    pub router_incoming_queue_cap: usize,
    pub router_broadcast_cap: usize,
    /// Concurrent packet processor workers (bounded pool).
    pub router_process_concurrency: usize,
    /// Outgoing packet signature format (`v1_json` legacy, `v2_hash` fast).
    pub signature_format: SignatureFormat,
    /// When false the topology-maintenance task is not started (useful for test nodes).
    pub enable_topology_maintenance: bool,
    /// Broadcast capacity for the internal CoreBus observer channel.
    pub event_bus_broadcast_cap: usize,
    /// When true, permanent subsystem degradation triggers graceful `stop()`.
    pub stop_on_permanent_degradation: bool,
    /// When true, topology reacts to session-close events via CoreBus handlers.
    pub topology_react_to_session_events: bool,
    pub dial_policy: DialPolicy,
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
            direct_upgrade: DirectUpgradeConfig::default(),
            session_join_timeout_secs: 2,
            supervisor_shutdown_timeout_secs: 10,
            router_incoming_queue_cap: 16384,
            router_broadcast_cap: 4096,
            router_process_concurrency: crate::router::ROUTER_PROCESS_SEMAPHORE_PERMITS,
            signature_format: SignatureFormat::V2Hash,
            enable_topology_maintenance: true,
            event_bus_broadcast_cap: 4096,
            stop_on_permanent_degradation: false,
            topology_react_to_session_events: false,
            dial_policy: DialPolicy::default(),
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
            direct_upgrade: DirectUpgradeConfig::default(),
            session_join_timeout_secs: 2,
            supervisor_shutdown_timeout_secs: 10,
            router_incoming_queue_cap: 16384,
            router_broadcast_cap: 4096,
            router_process_concurrency: crate::router::ROUTER_PROCESS_SEMAPHORE_PERMITS,
            signature_format: SignatureFormat::V2Hash,
            enable_topology_maintenance: true,
            event_bus_broadcast_cap: 4096,
            stop_on_permanent_degradation: false,
            topology_react_to_session_events: false,
            dial_policy: DialPolicy::default(),
            logger_options: Some(LoggerOptions::default()),
        }
    }

    pub fn effective_peer_connection_policy_for(
        peer_connection_policy: PeerConnectionPolicy,
        role: NodeRole,
    ) -> PeerConnectionPolicy {
        let p = peer_connection_policy.normalized();
        match role {
            NodeRole::Regular => p,
            NodeRole::BootstrapJoin => {
                let target = p.target_active_peers.clamp(1, 8);
                let max = p.max_active_peers.min(24).max(target);
                PeerConnectionPolicy {
                    min_active_peers: p.min_active_peers.clamp(1, 2),
                    target_active_peers: target,
                    max_active_peers: max,
                }
                .normalized()
            }
        }
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
        self.set_listen(
            "tcp".to_string(),
            "0.0.0.0:8080".parse::<SocketAddr>().unwrap(),
        );
        self.set_listen(
            "udp".to_string(),
            "0.0.0.0:8081".parse::<SocketAddr>().unwrap(),
        );
        self.set_listen(
            "quic".to_string(),
            "0.0.0.0:8082".parse::<SocketAddr>().unwrap(),
        );
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
        self.transport_obfuscation
            .remove(&protocol.to_ascii_lowercase());
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

fn default_regular_auto_target_min() -> usize {
    4
}

fn default_regular_auto_target_max() -> usize {
    12
}

fn default_regular_bootstrap_min_keep() -> usize {
    // В steady state regular peer не держит bootstrap: мост остаётся доступным
    // через `bootstrap_nodes` и `missing_bootstrap_bridge` rejoin при изоляции.
    0
}

fn default_regular_bootstrap_rejoin_interval_ms() -> u64 {
    20_000
}

fn default_regular_exploration_interval_ms() -> u64 {
    12_000
}

fn default_dial_retry_cooldown_ms() -> u64 {
    30_000
}

fn default_prune_redial_cooldown_ms() -> u64 {
    45_000
}

fn default_bootstrap_stable_peer_threshold() -> usize {
    4
}

fn default_adaptive_target_min_floor() -> usize {
    3
}

fn default_adaptive_target_max_ceil() -> usize {
    16
}

fn default_adaptive_bootstrap_hard_max() -> usize {
    8
}

fn default_adaptive_bootstrap_top_k() -> usize {
    2
}

fn default_adaptive_exploration_interval_min_ms() -> u64 {
    8_000
}

fn default_adaptive_exploration_interval_max_ms() -> u64 {
    120_000
}

fn default_adaptive_rejoin_cooldown_min_ms() -> u64 {
    20_000
}

fn default_adaptive_rejoin_cooldown_max_ms() -> u64 {
    180_000
}

fn default_adaptive_redirect_memory_ms() -> u64 {
    12_000
}

fn default_flow_trace_payload_preview_bytes() -> usize {
    32
}

fn default_debug_server_bind_addr() -> String {
    "127.0.0.1:9090".to_string()
}

fn default_debug_server_push_interval_ms() -> u64 {
    1000
}

fn default_ipc_tcp_bind_addr() -> String {
    "127.0.0.1:9091".to_string()
}

fn default_ipc_tcp_max_frame_bytes() -> u32 {
    16 * 1024 * 1024
}

pub(super) fn default_transport_obfuscation() -> HashMap<String, ObfuscationConfig> {
    HashMap::from([
        ("tcp".to_string(), ObfuscationConfig::default()),
        ("udp".to_string(), ObfuscationConfig::default()),
        ("quic".to_string(), ObfuscationConfig::default()),
    ])
}
