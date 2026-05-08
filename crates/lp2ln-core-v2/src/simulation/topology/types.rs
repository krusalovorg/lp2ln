use std::collections::{BTreeMap, BTreeSet};

pub type SimNodeId = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimPeerView {
    pub peer_id: SimNodeId,
    pub connected: bool,
    pub latency_ms: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimNodeState {
    pub node_id: SimNodeId,
    pub online: bool,
    pub peers: BTreeMap<SimNodeId, SimPeerView>,
}

impl SimNodeState {
    pub fn new(node_id: SimNodeId) -> Self {
        Self {
            node_id,
            online: true,
            peers: BTreeMap::new(),
        }
    }

    pub fn connected_peers_count(&self) -> usize {
        self.peers.values().filter(|peer| peer.connected).count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SimEdge {
    pub a: SimNodeId,
    pub b: SimNodeId,
}

impl SimEdge {
    pub fn new(node_a: SimNodeId, node_b: SimNodeId) -> Self {
        let (a, b) = if node_a <= node_b {
            (node_a, node_b)
        } else {
            (node_b, node_a)
        };
        Self { a, b }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologySnapshot {
    pub now_ms: u64,
    pub nodes: BTreeMap<SimNodeId, SimNodeState>,
    pub edges: BTreeSet<SimEdge>,
}

impl TopologySnapshot {
    pub fn with_node_count(node_count: usize) -> Self {
        let mut nodes = BTreeMap::new();
        for raw_id in 0..node_count {
            let node_id = raw_id as SimNodeId;
            nodes.insert(node_id, SimNodeState::new(node_id));
        }
        Self {
            now_ms: 0,
            nodes,
            edges: BTreeSet::new(),
        }
    }

    pub fn node_ids(&self) -> impl Iterator<Item = SimNodeId> + '_ {
        self.nodes.keys().copied()
    }
}
