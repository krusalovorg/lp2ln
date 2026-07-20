use std::net::SocketAddr;

use crate::topology::NodeDescriptor;
use crate::topology::snapshot::TopologySnapshot;
use crate::types::PeerId;

// ── Output types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DialIntent {
    pub peer_id: PeerId,
    pub addrs: Vec<(String, SocketAddr)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    Overloaded,
    Bootstrap,
    Rotation,
    Admission,
}

#[derive(Debug, Clone)]
pub struct DropIntent {
    pub peer_id: PeerId,
    pub reason: DropReason,
    /// Peer must not be re-dialed until this timestamp (ms since epoch).
    pub cooldown_until_ms: u64,
}

#[derive(Debug, Clone)]
pub struct DiscoveryNeed {
    /// Send `RequestPeers` to these currently-connected peers.
    pub request_from: Vec<PeerId>,
}

#[derive(Debug, Clone, Default)]
pub struct TopologyPlan {
    /// Peers that are explicitly confirmed healthy — no action needed.
    pub keep: Vec<PeerId>,
    pub dial: Vec<DialIntent>,
    pub drop: Vec<DropIntent>,
    pub discovery: Vec<DiscoveryNeed>,
}

// ── Admission ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PeerCandidate {
    pub peer_id: PeerId,
    pub is_bootstrap_entry: bool,
}

#[derive(Debug, Clone)]
pub enum AdmissionDecision {
    Accept,
    /// Redirect newcomer to alternative peers; caller closes the session.
    Redirect {
        descriptors: Vec<NodeDescriptor>,
    },
    Reject,
}

// ── Trait ─────────────────────────────────────────────────────────────────────

pub trait TopologyPlanner: Send + Sync {
    /// Compute what to keep, dial, drop, and discover given the current snapshot.
    fn plan(&self, snapshot: &TopologySnapshot) -> TopologyPlan;

    /// Decide whether to accept, redirect, or reject an incoming connection.
    fn evaluate_incoming(
        &self,
        snapshot: &TopologySnapshot,
        candidate: &PeerCandidate,
    ) -> AdmissionDecision;
}
