use std::collections::{HashMap, HashSet, VecDeque};

use super::super::topology::{SimEdge, SimNodeId, TopologySnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FarthestPair {
    pub source: SimNodeId,
    pub target: SimNodeId,
    pub distance: usize,
}

/// Build adjacency list from snapshot edges (online nodes only).
pub fn adjacency(snapshot: &TopologySnapshot) -> HashMap<SimNodeId, Vec<SimNodeId>> {
    let online: HashSet<SimNodeId> = snapshot
        .nodes
        .values()
        .filter(|n| n.online)
        .map(|n| n.node_id)
        .collect();
    let mut adj: HashMap<SimNodeId, Vec<SimNodeId>> = HashMap::new();
    for node_id in &online {
        adj.entry(*node_id).or_default();
    }
    for edge in &snapshot.edges {
        if online.contains(&edge.a) && online.contains(&edge.b) {
            adj.entry(edge.a).or_default().push(edge.b);
            adj.entry(edge.b).or_default().push(edge.a);
        }
    }
    for neighbors in adj.values_mut() {
        neighbors.sort_unstable();
        neighbors.dedup();
    }
    adj
}

pub fn largest_component(snapshot: &TopologySnapshot) -> Vec<SimNodeId> {
    let adj = adjacency(snapshot);
    let mut visited = HashSet::new();
    let mut best: Vec<SimNodeId> = Vec::new();

    for &start in adj.keys() {
        if visited.contains(&start) {
            continue;
        }
        let mut queue = VecDeque::from([start]);
        visited.insert(start);
        let mut component = Vec::new();
        while let Some(current) = queue.pop_front() {
            component.push(current);
            if let Some(neighbors) = adj.get(&current) {
                for &next in neighbors {
                    if visited.insert(next) {
                        queue.push_back(next);
                    }
                }
            }
        }
        if component.len() > best.len() {
            best = component;
        }
    }
    best.sort_unstable();
    best
}

pub fn bfs_distances(
    start: SimNodeId,
    adj: &HashMap<SimNodeId, Vec<SimNodeId>>,
) -> HashMap<SimNodeId, usize> {
    let mut dist = HashMap::new();
    let mut queue = VecDeque::from([(start, 0usize)]);
    dist.insert(start, 0);
    while let Some((node, d)) = queue.pop_front() {
        if let Some(neighbors) = adj.get(&node) {
            for &next in neighbors {
                if dist.insert(next, d + 1).is_none() {
                    queue.push_back((next, d + 1));
                }
            }
        }
    }
    dist
}

pub fn shortest_path_hops(
    snapshot: &TopologySnapshot,
    from: SimNodeId,
    to: SimNodeId,
) -> Option<usize> {
    if from == to {
        return Some(0);
    }
    let adj = adjacency(snapshot);
    let dist = bfs_distances(from, &adj);
    dist.get(&to).copied()
}

pub fn find_farthest_pair(snapshot: &TopologySnapshot) -> Option<FarthestPair> {
    let component = largest_component(snapshot);
    if component.len() < 2 {
        return None;
    }
    let adj = adjacency(snapshot);
    let start = component[0];
    let dist_a = bfs_distances(start, &adj);
    // tie-break by node id so two calls on the same graph always pick the same pair
    let (&far_a, _dist_a_max) = dist_a
        .iter()
        .filter(|(id, _)| component.contains(id))
        .max_by(|(id_a, d_a), (id_b, d_b)| d_a.cmp(d_b).then(id_a.cmp(id_b)))?;
    let dist_b = bfs_distances(far_a, &adj);
    let (&far_b, dist_b_max) = dist_b
        .iter()
        .filter(|(id, _)| component.contains(id) && **id != far_a)
        .max_by(|(id_a, d_a), (id_b, d_b)| d_a.cmp(d_b).then(id_a.cmp(id_b)))?;
    Some(FarthestPair {
        source: far_a,
        target: far_b,
        // ponytail: second sweep distance IS the diameter estimate; .max() was wrong
        distance: *dist_b_max,
    })
}

pub fn graph_diameter_estimate(snapshot: &TopologySnapshot) -> usize {
    find_farthest_pair(snapshot)
        .map(|p| p.distance)
        .unwrap_or(0)
}

/// Deterministic line topology for regression tests (0 — 1 — … — n-1).
pub fn line_snapshot(node_count: usize) -> TopologySnapshot {
    let mut snapshot = TopologySnapshot::with_node_count(node_count);
    for i in 0..node_count.saturating_sub(1) {
        let a = i as SimNodeId;
        let b = (i + 1) as SimNodeId;
        snapshot.edges.insert(SimEdge::new(a, b));
    }
    snapshot
}
