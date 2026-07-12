use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::simulation::topology::{SimNodeId, TopologySnapshot};

use super::graph::adjacency;

#[derive(Debug, Default)]
struct TableInner {
    peer_to_node: HashMap<String, SimNodeId>,
    node_to_peer: HashMap<SimNodeId, String>,
    next_hop: HashMap<(SimNodeId, SimNodeId), SimNodeId>,
}

#[derive(Debug, Default, Clone)]
pub struct SimRoutingTable {
    inner: Arc<Mutex<TableInner>>,
}

impl SimRoutingTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_peer(&self, node_id: SimNodeId, peer_id: impl Into<String>) {
        let peer_id = peer_id.into();
        let mut inner = self.inner.lock().expect("routing table lock");
        inner.peer_to_node.insert(peer_id.clone(), node_id);
        inner.node_to_peer.insert(node_id, peer_id);
    }

    pub fn build_from_snapshot(&self, snapshot: &TopologySnapshot) {
        let mut inner = self.inner.lock().expect("routing table lock");
        inner.next_hop.clear();
        let adj = adjacency(snapshot);
        for &from in adj.keys() {
            for &to in adj.keys() {
                if from == to {
                    continue;
                }
                if let Some(next) = bfs_next_hop(from, to, &adj) {
                    inner.next_hop.insert((from, to), next);
                }
            }
        }
    }

    pub fn resolver(
        self: &Arc<Self>,
        node_id: SimNodeId,
    ) -> Arc<dyn Fn(&str, &str) -> Option<String> + Send + Sync> {
        let table = self.clone();
        Arc::new(move |_our_peer_id: &str, destination_peer: &str| {
            table.next_hop_peer(node_id, destination_peer)
        })
    }

    fn next_hop_peer(&self, from_node: SimNodeId, destination_peer: &str) -> Option<String> {
        let inner = self.inner.lock().expect("routing table lock");
        let to_node = inner.peer_to_node.get(destination_peer)?;
        let next_node = inner.next_hop.get(&(from_node, *to_node))?;
        inner.node_to_peer.get(next_node).cloned()
    }
}

fn bfs_next_hop(
    from: SimNodeId,
    to: SimNodeId,
    adj: &HashMap<SimNodeId, Vec<SimNodeId>>,
) -> Option<SimNodeId> {
    if from == to {
        return None;
    }
    let mut parent: HashMap<SimNodeId, SimNodeId> = HashMap::new();
    let mut queue = VecDeque::from([from]);
    while let Some(current) = queue.pop_front() {
        for &next in adj.get(&current).into_iter().flatten() {
            if parent.contains_key(&next) {
                continue;
            }
            parent.insert(next, current);
            if next == to {
                let mut step = to;
                while parent.get(&step).copied()? != from {
                    step = parent[&step];
                }
                return Some(step);
            }
            queue.push_back(next);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simulation::network::line_snapshot;

    #[test]
    fn next_hop_follows_shortest_path_on_line() {
        let snapshot = line_snapshot(5);
        let table = SimRoutingTable::new();
        for node_id in 0..5u64 {
            table.register_peer(node_id, format!("peer-{node_id}"));
        }
        table.build_from_snapshot(&snapshot);
        assert_eq!(table.next_hop_peer(0, "peer-4").as_deref(), Some("peer-1"));
        assert_eq!(table.next_hop_peer(2, "peer-4").as_deref(), Some("peer-3"));
    }
}
