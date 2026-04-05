use serde::{Deserialize, Serialize};

use crate::types::PeerId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerHealthSnapshot {
    pub peer_id: PeerId,
    pub sessions_count: u16,
    pub active_sessions_count: u16,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub total_errors: u64,
    pub avg_last_activity_secs_ago: u64,
}

impl Default for PeerHealthSnapshot {
    fn default() -> Self {
        Self {
            peer_id: PeerId::from(""),
            sessions_count: 0,
            active_sessions_count: 0,
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            total_errors: 0,
            avg_last_activity_secs_ago: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeHealthSnapshot {
    pub active_connections: u16,
    pub active_peers: u16,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub total_errors: u64,
    pub cpu_load_estimate: f32,
    pub memory_pressure_estimate: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AggregatedMetricsSnapshot {
    pub collected_at_ms: u64,
    pub node: NodeHealthSnapshot,
    pub peers: Vec<PeerHealthSnapshot>,
}
