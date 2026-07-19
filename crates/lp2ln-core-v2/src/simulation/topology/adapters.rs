use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use super::types::{SimNodeId, SimNodeState, TopologySnapshot};
use crate::node::options::{NodeRole, TopologyTuning};
use crate::peer_score::{PeerConnectionPolicy, PeerScoreWeights};
use crate::topology::{CapacityBudget, SmartMeshPlanner, TopologyPlanner};
use crate::topology::snapshot::TopologySnapshot as RealSnapshot;
use crate::types::PeerId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimNodeObservation {
    pub node_id: SimNodeId,
    pub now_ms: u64,
    pub connected_peers: usize,
    pub known_peers: usize,
    pub node_state: SimNodeState,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NodeActionPlan {
    pub dial_candidates: Vec<SimNodeId>,
    pub drop_candidates: Vec<SimNodeId>,
    pub request_peer_exchange: bool,
}

pub trait TopologyDecisionAdapter {
    fn plan_actions(
        &self,
        observation: &SimNodeObservation,
        snapshot: &TopologySnapshot,
    ) -> NodeActionPlan;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicHeuristicAdapter {
    pub target_degree: usize,
    pub max_new_dials_per_tick: usize,
}

impl Default for BasicHeuristicAdapter {
    fn default() -> Self {
        Self {
            target_degree: 6,
            max_new_dials_per_tick: 2,
        }
    }
}

impl TopologyDecisionAdapter for BasicHeuristicAdapter {
    fn plan_actions(
        &self,
        observation: &SimNodeObservation,
        snapshot: &TopologySnapshot,
    ) -> NodeActionPlan {
        let mut plan = NodeActionPlan::default();
        let connected = observation.connected_peers;

        if connected < self.target_degree {
            let missing = self.target_degree.saturating_sub(connected);
            let dial_budget = missing.min(self.max_new_dials_per_tick);
            let mut best: Vec<(usize, SimNodeId)> = Vec::with_capacity(dial_budget.max(1));
            let candidates_ordered: Vec<SimNodeId> = snapshot.node_ids().collect();
            if candidates_ordered.is_empty() {
                plan.request_peer_exchange = true;
                return plan;
            }
            let start =
                (observation.node_id ^ observation.now_ms) as usize % candidates_ordered.len();

            for offset in 0..candidates_ordered.len() {
                let idx = (start + offset) % candidates_ordered.len();
                let candidate = candidates_ordered[idx];
                if candidate == observation.node_id {
                    continue;
                }
                let Some(candidate_state) = snapshot.nodes.get(&candidate) else {
                    continue;
                };
                if !candidate_state.online {
                    continue;
                }
                if observation
                    .node_state
                    .peers
                    .get(&candidate)
                    .is_some_and(|p| p.connected)
                {
                    continue;
                }

                let score = candidate_state.connected_peers_count();
                insert_best_candidate(&mut best, dial_budget, score, candidate);
            }

            for (_, candidate) in best {
                plan.dial_candidates.push(candidate);
            }
            let selected = plan.dial_candidates.len();
            plan.request_peer_exchange = selected == 0;
        } else if connected > self.target_degree.saturating_add(2) {
            let drop_count = connected.saturating_sub(self.target_degree);
            for peer in observation
                .node_state
                .peers
                .values()
                .filter(|peer| peer.connected)
                .take(drop_count)
            {
                plan.drop_candidates.push(peer.peer_id);
            }
        }

        plan
    }
}

/// Wraps `LegacyTopologyPlanner` so the simulator exercises the same planner as the runtime.
/// Converts SimNodeId ↔ PeerId via `u64.to_string()`, uses fake loopback addresses for
/// the dial book (simulator never connects to them; it only uses the PeerId round-trip).
#[derive(Debug, Clone, PartialEq)]
pub struct PlannerAdapter {
    pub policy: PeerConnectionPolicy,
    pub max_new_dials_per_tick: usize,
}

impl Default for PlannerAdapter {
    fn default() -> Self {
        Self {
            policy: PeerConnectionPolicy {
                min_active_peers: 4,
                target_active_peers: 6,
                max_active_peers: 10,
            },
            max_new_dials_per_tick: 2,
        }
    }
}

impl TopologyDecisionAdapter for PlannerAdapter {
    fn plan_actions(&self, observation: &SimNodeObservation, snapshot: &TopologySnapshot) -> NodeActionPlan {
        let to_pid = |id: SimNodeId| PeerId::from(id.to_string().as_str());

        let connected_set: HashSet<SimNodeId> = observation
            .node_state
            .peers
            .values()
            .filter(|p| p.connected)
            .map(|p| p.peer_id)
            .collect();

        let connected_peers: Vec<PeerId> =
            connected_set.iter().map(|id| to_pid(*id)).collect();

        // ponytail: fake loopback ports — simulator ignores addresses, only uses PeerId key
        let dial_book: HashMap<PeerId, Vec<(String, SocketAddr)>> = snapshot
            .nodes
            .iter()
            .filter(|(id, state)| {
                state.online && **id != observation.node_id && !connected_set.contains(*id)
            })
            .map(|(id, _)| {
                let port = (id % 60000 + 1024) as u16;
                (to_pid(*id), vec![("tcp".to_string(), ([127u8, 0, 0, 1], port).into())])
            })
            .collect();

        let real_snap = RealSnapshot {
            our_peer_id: to_pid(observation.node_id),
            node_role: NodeRole::Regular,
            policy: self.policy.clone(),
            weights: PeerScoreWeights::default(),
            topology_tuning: TopologyTuning::default(),
            connected_peers,
            connected_bootstrap_count: 0,
            known_peer_count: observation.known_peers,
            peer_total_scores: HashMap::new(),
            bootstrap_peer_ids: HashSet::new(),
            descriptor_active_conns: HashMap::new(),
            catalog_descriptors: Vec::new(),
            capacity: CapacityBudget::default(),
            dial_book,
            dial_cooldowns: HashMap::new(),
            bootstrap_targets_count: 0,
            last_bootstrap_reseed_ms: 0,
            now_ms: observation.now_ms,
        };

        let plan = SmartMeshPlanner.plan(&real_snap);

        let mut node_plan = NodeActionPlan::default();
        for intent in plan.dial.into_iter().take(self.max_new_dials_per_tick) {
            if let Ok(sim_id) = intent.peer_id.as_str().parse::<SimNodeId>() {
                node_plan.dial_candidates.push(sim_id);
            }
        }
        for intent in plan.drop {
            if let Ok(sim_id) = intent.peer_id.as_str().parse::<SimNodeId>() {
                node_plan.drop_candidates.push(sim_id);
            }
        }
        node_plan.request_peer_exchange = !plan.discovery.is_empty();
        node_plan
    }
}

fn insert_best_candidate(
    best: &mut Vec<(usize, SimNodeId)>,
    capacity: usize,
    score: usize,
    candidate: SimNodeId,
) {
    if capacity == 0 {
        return;
    }

    if best.len() < capacity {
        best.push((score, candidate));
        best.sort_unstable_by_key(|entry| entry.0);
        return;
    }

    if let Some((worst_idx, worst_score)) = best
        .iter()
        .enumerate()
        .max_by_key(|(_, (entry_score, _))| *entry_score)
        .map(|(idx, (entry_score, _))| (idx, *entry_score))
        && score < worst_score
    {
        best[worst_idx] = (score, candidate);
        best.sort_unstable_by_key(|entry| entry.0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationHook {
    pub source_path: &'static str,
    pub purpose: &'static str,
}

pub const RUNTIME_INTEGRATION_HOOKS: [IntegrationHook; 3] = [
    IntegrationHook {
        source_path: "src/node/topology_maintenance/mod.rs",
        purpose: "tick orchestration and dial plan execution flow",
    },
    IntegrationHook {
        source_path: "src/node/topology_maintenance/policy.rs",
        purpose: "policy snapshot classification and adaptive target shaping",
    },
    IntegrationHook {
        source_path: "src/node/topology_maintenance/state.rs",
        purpose: "mutable maintenance state fields that mirror simulator node state",
    },
];
