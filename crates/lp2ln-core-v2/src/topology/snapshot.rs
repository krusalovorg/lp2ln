use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use crate::node::options::{NodeRole, TopologyTuning};
use crate::peer_score::{PeerConnectionPolicy, PeerScoreWeights};
use crate::topology::{CapacityBudget, NodeDescriptor};
use crate::types::PeerId;

/// Self-contained view of the network at a single point in time.
/// Built by the maintenance loop; consumed by `TopologyPlanner::plan()` as a pure input.
/// All external state (scores, catalog, cooldowns) is pre-gathered here so planners
/// are pure functions with no side-effects or I/O.
#[derive(Clone)]
pub struct TopologySnapshot {
    pub our_peer_id: PeerId,
    pub node_role: NodeRole,
    pub policy: PeerConnectionPolicy,
    pub weights: PeerScoreWeights,
    pub topology_tuning: TopologyTuning,

    /// Currently connected peer IDs (from `Router::connected_peers()`).
    pub connected_peers: Vec<PeerId>,
    /// How many of `connected_peers` are bootstrap entries.
    pub connected_bootstrap_count: usize,
    /// Total number of known peers in the catalog (not just connected).
    pub known_peer_count: usize,

    /// Pre-computed total weighted score per known peer.
    pub peer_total_scores: HashMap<PeerId, f32>,
    /// Which known peers are bootstrap entries.
    pub bootstrap_peer_ids: HashSet<PeerId>,
    /// `active_connections` from each peer's descriptor (for drop prioritization).
    pub descriptor_active_conns: HashMap<PeerId, u16>,
    /// Subset of known descriptors (for passing to admission redirect, etc.).
    pub catalog_descriptors: Vec<NodeDescriptor>,

    /// Current node resource utilization.
    pub capacity: CapacityBudget,

    /// Known dial endpoints per peer (proto, addr).
    pub dial_book: HashMap<PeerId, Vec<(String, SocketAddr)>>,
    /// Peers that are in a dial cooldown period: peer_id → ready_at_ms.
    pub dial_cooldowns: HashMap<PeerId, u64>,
    /// How long each currently-connected peer has been connected (ms). Used for residency guards.
    pub peer_age_ms: HashMap<PeerId, u64>,

    /// Number of configured bootstrap target nodes (for reseed guard heuristics).
    pub bootstrap_targets_count: usize,
    /// Timestamp of the last bootstrap reseed attempt (ms since epoch).
    pub last_bootstrap_reseed_ms: u64,
    pub now_ms: u64,
}

impl TopologySnapshot {
    pub fn connected_non_bootstrap_count(&self) -> usize {
        self.connected_peers.len().saturating_sub(self.connected_bootstrap_count)
    }

    pub fn total_score_of(&self, peer_id: &PeerId) -> f32 {
        self.peer_total_scores.get(peer_id).copied().unwrap_or(0.0)
    }

    pub fn is_bootstrap(&self, peer_id: &PeerId) -> bool {
        self.bootstrap_peer_ids.contains(peer_id)
    }

    pub fn active_conns_of(&self, peer_id: &PeerId) -> u16 {
        self.descriptor_active_conns.get(peer_id).copied().unwrap_or(0)
    }

    pub fn in_cooldown(&self, peer_id: &PeerId) -> bool {
        self.dial_cooldowns
            .get(peer_id)
            .is_some_and(|&until| self.now_ms < until)
    }
}
