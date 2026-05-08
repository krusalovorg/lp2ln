use std::collections::{BTreeSet, VecDeque};

use super::types::{SimNodeId, TopologySnapshot};

#[derive(Debug, Clone, PartialEq)]
pub struct SimulationMetrics {
    pub node_count: usize,
    pub online_nodes: usize,
    pub online_ratio: f64,
    pub edge_count: usize,
    pub average_degree: f64,
    pub degree_p95: usize,
    pub isolated_nodes: usize,
    pub connected_components: usize,
    pub largest_component_size: usize,
    pub largest_component_ratio: f64,
}

impl SimulationMetrics {
    pub fn from_snapshot(snapshot: &TopologySnapshot) -> Self {
        let node_count = snapshot.nodes.len();
        let online_nodes = snapshot.nodes.values().filter(|node| node.online).count();
        let online_ratio = if node_count == 0 {
            0.0
        } else {
            online_nodes as f64 / node_count as f64
        };
        let edge_count = snapshot.edges.len();
        let average_degree = if node_count == 0 {
            0.0
        } else {
            (edge_count as f64 * 2.0) / node_count as f64
        };
        let degree_p95 = degree_percentile(snapshot, 95);
        let isolated_nodes = snapshot
            .nodes
            .values()
            .filter(|node| node.online && node.connected_peers_count() == 0)
            .count();
        let (connected_components, largest_component_size) = component_stats(snapshot);
        let largest_component_ratio = if online_nodes == 0 {
            0.0
        } else {
            largest_component_size as f64 / online_nodes as f64
        };

        Self {
            node_count,
            online_nodes,
            online_ratio,
            edge_count,
            average_degree,
            degree_p95,
            isolated_nodes,
            connected_components,
            largest_component_size,
            largest_component_ratio,
        }
    }
}

fn degree_percentile(snapshot: &TopologySnapshot, percentile: usize) -> usize {
    let mut degrees: Vec<usize> = snapshot
        .nodes
        .values()
        .filter(|node| node.online)
        .map(|node| node.connected_peers_count())
        .collect();
    if degrees.is_empty() {
        return 0;
    }
    degrees.sort_unstable();
    let idx = ((degrees.len().saturating_sub(1)) * percentile.min(100)) / 100;
    degrees[idx]
}

fn component_stats(snapshot: &TopologySnapshot) -> (usize, usize) {
    let online_nodes: BTreeSet<SimNodeId> = snapshot
        .nodes
        .values()
        .filter(|node| node.online)
        .map(|node| node.node_id)
        .collect();
    if online_nodes.is_empty() {
        return (0, 0);
    }

    let mut visited: BTreeSet<SimNodeId> = BTreeSet::new();
    let mut components = 0usize;
    let mut largest_component_size = 0usize;

    for node_id in online_nodes.iter().copied() {
        if visited.contains(&node_id) {
            continue;
        }
        components = components.saturating_add(1);
        let mut queue = VecDeque::from([node_id]);
        visited.insert(node_id);
        let mut component_size = 0usize;

        while let Some(current) = queue.pop_front() {
            component_size = component_size.saturating_add(1);
            let Some(node) = snapshot.nodes.get(&current) else {
                continue;
            };
            for peer in node.peers.values().filter(|peer| peer.connected) {
                if !online_nodes.contains(&peer.peer_id) {
                    continue;
                }
                if visited.insert(peer.peer_id) {
                    queue.push_back(peer.peer_id);
                }
            }
        }
        largest_component_size = largest_component_size.max(component_size);
    }

    (components, largest_component_size)
}
