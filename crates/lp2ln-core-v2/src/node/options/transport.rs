use serde::{Deserialize, Serialize};

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

fn default_true() -> bool { true }
fn default_du_min_packets_per_window() -> usize { 8 }
fn default_du_min_bytes_per_window() -> u64 { 512 }
fn default_du_window_secs() -> u64 { 30 }
fn default_du_cooldown_secs() -> u64 { 60 }
fn default_du_max_parallel_attempts() -> usize { 2 }
fn default_du_direct_dial_timeout_ms() -> u64 { 5000 }
fn default_du_event_queue_cap() -> usize { 4096 }
fn default_du_tick_interval_ms() -> u64 { 500 }
fn default_du_max_tracker_peers() -> usize { 2048 }

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

impl Default for DialPolicy {
    fn default() -> Self {
        Self {
            transport_order: default_dial_policy_transport_order(),
            quic_connect_timeout_secs: default_quic_connect_timeout_secs(),
            fallback_on_transport_degraded: true,
        }
    }
}

fn default_dial_policy_transport_order() -> Vec<String> {
    vec!["quic".into(), "udp".into(), "tcp".into()]
}
fn default_quic_connect_timeout_secs() -> u64 { 5 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanDiscoveryOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_lan_port")]
    pub port: u16,
    /// How often to multicast a LanHello (ms).
    #[serde(default = "default_lan_announce_interval_ms")]
    pub announce_interval_ms: u64,
    /// Lifetime of a LanHello's endpoints in PeerDirectory (ms).
    #[serde(default = "default_lan_hello_ttl_ms")]
    pub hello_ttl_ms: u64,
    /// Per-peer rate limit: drop hellos beyond this many per second.
    #[serde(default = "default_lan_max_hellos_per_peer_per_sec")]
    pub max_hellos_per_peer_per_sec: u32,
}

impl Default for LanDiscoveryOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            port: default_lan_port(),
            announce_interval_ms: default_lan_announce_interval_ms(),
            hello_ttl_ms: default_lan_hello_ttl_ms(),
            max_hellos_per_peer_per_sec: default_lan_max_hellos_per_peer_per_sec(),
        }
    }
}

fn default_lan_port() -> u16 { 42500 }
fn default_lan_announce_interval_ms() -> u64 { 15_000 }
fn default_lan_hello_ttl_ms() -> u64 { 60_000 }
fn default_lan_max_hellos_per_peer_per_sec() -> u32 { 5 }
