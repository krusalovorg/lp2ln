use std::collections::HashSet;
use std::net::SocketAddr;

use crate::node::distribution::{capacity_target_factor, dial_reserve_slots, regular_auto_dial_target};
use crate::node::incoming_sessions::REGULAR_INCOMING_HEADROOM;
use crate::node::options::{NodeRole, TopologyTuning};
use crate::node::topology_maintenance::compute_policy_snapshot;
use crate::topology::snapshot::TopologySnapshot;
use crate::topology::NodeDescriptor;
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
    Redirect { descriptors: Vec<NodeDescriptor> },
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

// ── LegacyTopologyPlanner ─────────────────────────────────────────────────────

/// Wraps the existing maintenance-loop heuristics as a pure `TopologyPlanner`.
/// Network behavior is identical to the pre-P1 loop; this planner is a bridge
/// until `SmartMeshPlanner` is stable and feature-gated in.
#[derive(Debug, Default, Clone, Copy)]
pub struct LegacyTopologyPlanner;

// ponytail: headroom constant mirrors topology_maintenance/mod.rs REGULAR_MAX_HEADROOM
const REGULAR_MAX_HEADROOM: usize = 2;

impl LegacyTopologyPlanner {
    /// Replicate `peers_to_drop_when_overloaded` as a pure function over snapshot data.
    fn select_drops(
        &self,
        snapshot: &TopologySnapshot,
        already_dropped: &HashSet<PeerId>,
        drop_n: usize,
    ) -> Vec<PeerId> {
        if drop_n == 0 {
            return vec![];
        }
        let connected: Vec<&PeerId> = snapshot
            .connected_peers
            .iter()
            .filter(|p| !already_dropped.contains(*p))
            .collect();

        let score = |p: &PeerId| snapshot.total_score_of(p);
        let boot_load = |p: &PeerId| snapshot.active_conns_of(p);

        let mut boot: Vec<PeerId> = connected
            .iter()
            .filter(|p| snapshot.is_bootstrap(p))
            .map(|p| (*p).clone())
            .collect();
        let mut regular: Vec<PeerId> = connected
            .iter()
            .filter(|p| !snapshot.is_bootstrap(p))
            .map(|p| (*p).clone())
            .collect();

        match snapshot.node_role {
            NodeRole::Regular => boot.sort_by(|a, b| {
                boot_load(b).cmp(&boot_load(a)).then_with(|| {
                    score(a).partial_cmp(&score(b)).unwrap_or(std::cmp::Ordering::Equal)
                })
            }),
            NodeRole::BootstrapJoin => boot.sort_by(|a, b| {
                score(a).partial_cmp(&score(b)).unwrap_or(std::cmp::Ordering::Equal)
            }),
        }
        regular.sort_by(|a, b| {
            score(a).partial_cmp(&score(b)).unwrap_or(std::cmp::Ordering::Equal)
        });

        let ordered: Vec<PeerId> = match snapshot.node_role {
            NodeRole::Regular => boot.into_iter().chain(regular).collect(),
            NodeRole::BootstrapJoin => regular.into_iter().chain(boot).collect(),
        };
        ordered.into_iter().take(drop_n).collect()
    }

    fn build_drop_intents(
        &self,
        snapshot: &TopologySnapshot,
        peers: Vec<PeerId>,
        reason: DropReason,
    ) -> Vec<DropIntent> {
        let cooldown = snapshot.topology_tuning.prune_redial_cooldown_ms;
        peers
            .into_iter()
            .map(|peer_id| DropIntent {
                peer_id,
                reason,
                cooldown_until_ms: snapshot.now_ms.saturating_add(cooldown),
            })
            .collect()
    }
}

impl TopologyPlanner for LegacyTopologyPlanner {
    fn plan(&self, snapshot: &TopologySnapshot) -> TopologyPlan {
        let policy = snapshot.policy.normalized();
        let adaptive = snapshot.capacity.recommend_policy(&policy);
        let n = snapshot.connected_peers.len();

        let self_capacity_factor = capacity_target_factor(
            snapshot.capacity.cpu_load,
            snapshot.capacity.memory_pressure,
            policy.max_active_peers.min(u16::MAX as usize) as u16,
        );
        let auto_target_regular =
            regular_auto_dial_target(snapshot.known_peer_count, &snapshot.topology_tuning, self_capacity_factor);

        let mut desired = adaptive
            .target_active_peers
            .max(adaptive.min_active_peers)
            .min(adaptive.max_active_peers);
        if matches!(snapshot.node_role, NodeRole::Regular) {
            desired = desired.min(auto_target_regular);
        }

        let reserve_slots = dial_reserve_slots(snapshot.node_role);
        let dial_target_base = desired
            .saturating_sub(reserve_slots)
            .max(adaptive.min_active_peers);

        let connected_non_bootstrap = snapshot.connected_non_bootstrap_count();
        let policy_snapshot = compute_policy_snapshot(
            &snapshot.topology_tuning,
            snapshot.node_role,
            snapshot.known_peer_count,
            n,
            snapshot.connected_bootstrap_count,
            connected_non_bootstrap,
            dial_target_base,
            desired,
            adaptive.min_active_peers,
            snapshot.bootstrap_targets_count,
            snapshot.last_bootstrap_reseed_ms,
            snapshot.now_ms,
        );

        let dial_target = policy_snapshot.dial_target;
        let dial_target_low = policy_snapshot.dial_target_low;
        let dial_target_high = policy_snapshot.dial_target_high;

        let mut drop_intents: Vec<DropIntent> = Vec::new();
        let mut dropped: HashSet<PeerId> = HashSet::new();
        let mut effective_n = n;

        // Pass 1: hard capacity ceiling
        if effective_n > adaptive.max_active_peers {
            let drop_n = effective_n.saturating_sub(adaptive.max_active_peers);
            let peers = self.select_drops(snapshot, &dropped, drop_n);
            effective_n = effective_n.saturating_sub(peers.len());
            for p in &peers {
                dropped.insert(p.clone());
            }
            drop_intents.extend(self.build_drop_intents(snapshot, peers, DropReason::Overloaded));
        }

        // Pass 2: headroom cap (Regular only)
        let max_allowed = if matches!(snapshot.node_role, NodeRole::Regular) {
            adaptive.max_active_peers.min(desired.saturating_add(REGULAR_MAX_HEADROOM))
        } else {
            adaptive.max_active_peers
        };
        if effective_n > max_allowed {
            let drop_n = effective_n.saturating_sub(max_allowed);
            let peers = self.select_drops(snapshot, &dropped, drop_n);
            effective_n = effective_n.saturating_sub(peers.len());
            for p in &peers {
                dropped.insert(p.clone());
            }
            drop_intents.extend(self.build_drop_intents(snapshot, peers, DropReason::Overloaded));
        }

        // Pass 3: dial_target_high (Regular only)
        if matches!(snapshot.node_role, NodeRole::Regular) && effective_n > dial_target_high {
            let drop_n = effective_n.saturating_sub(dial_target);
            let peers = self.select_drops(snapshot, &dropped, drop_n);
            effective_n = effective_n.saturating_sub(peers.len());
            for p in &peers {
                dropped.insert(p.clone());
            }
            drop_intents.extend(self.build_drop_intents(snapshot, peers, DropReason::Overloaded));
        }

        // Pass 4: shed bootstrap entries once we have enough mesh peers (Regular only)
        if matches!(snapshot.node_role, NodeRole::Regular) {
            let non_boot = snapshot
                .connected_peers
                .iter()
                .filter(|p| !dropped.contains(*p) && !snapshot.is_bootstrap(p))
                .count();
            let min_keep = adaptive.min_active_peers;
            if non_boot >= min_keep.max(1) {
                let min_boot_keep = snapshot.topology_tuning.regular_bootstrap_min_keep;
                let mut boot_connected: Vec<PeerId> = snapshot
                    .connected_peers
                    .iter()
                    .filter(|p| !dropped.contains(*p) && snapshot.is_bootstrap(p))
                    .cloned()
                    .collect();
                if boot_connected.len() > min_boot_keep {
                    let drop_n = boot_connected.len().saturating_sub(min_boot_keep);
                    // sort ascending by score so lowest-score bootstrap dropped first
                    boot_connected.sort_by(|a, b| {
                        snapshot
                            .total_score_of(a)
                            .partial_cmp(&snapshot.total_score_of(b))
                            .unwrap_or(std::cmp::Ordering::Equal)
                    });
                    let to_drop: Vec<PeerId> = boot_connected.into_iter().take(drop_n).collect();
                    let boot_cooldown = snapshot
                        .topology_tuning
                        .regular_bootstrap_rejoin_interval_ms
                        .saturating_mul(2);
                    drop_intents.extend(to_drop.iter().map(|p| DropIntent {
                        peer_id: p.clone(),
                        reason: DropReason::Bootstrap,
                        cooldown_until_ms: snapshot.now_ms.saturating_add(boot_cooldown),
                    }));
                    for p in to_drop {
                        dropped.insert(p);
                    }
                    effective_n = effective_n.saturating_sub(dropped.len().saturating_sub(n - effective_n));
                }
            }
        }

        // Dial and discovery when under target
        let mut dial_intents: Vec<DialIntent> = Vec::new();
        let mut discovery: Vec<DiscoveryNeed> = Vec::new();
        let connected_set: HashSet<&PeerId> = snapshot.connected_peers.iter().collect();

        if effective_n < dial_target_low {
            // Discovery: ask all connected peers for more peers
            let request_from: Vec<PeerId> = snapshot
                .connected_peers
                .iter()
                .filter(|p| !dropped.contains(*p))
                .cloned()
                .collect();
            if !request_from.is_empty() {
                discovery.push(DiscoveryNeed { request_from });
            }

            // Dial: candidates from dial_book not already connected/dropped/in-cooldown
            // ponytail: mirrors REGULAR/BOOTSTRAP_DIAL_ATTEMPT_BUDGET_MAX (pub(super) in maintenance)
            let budget = 8usize;
            let mut dial_budget = dial_target_low.saturating_sub(effective_n).max(1).min(budget);

            // Simple ranking by total score (descending); full `rank_dial_candidates` is
            // applied by the reconciler which has access to peer_store/desc_by_peer.
            let mut candidates: Vec<(&PeerId, f32)> = snapshot
                .dial_book
                .keys()
                .filter(|p| {
                    p.as_str() != snapshot.our_peer_id.as_str()
                        && !connected_set.contains(p)
                        && !dropped.contains(p)
                        && !snapshot.in_cooldown(p)
                })
                .map(|p| (p, snapshot.total_score_of(p)))
                .collect();
            candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

            for (peer_id, _) in candidates {
                if dial_budget == 0 {
                    break;
                }
                if let Some(addrs) = snapshot.dial_book.get(peer_id) {
                    dial_intents.push(DialIntent {
                        peer_id: peer_id.clone(),
                        addrs: addrs.clone(),
                    });
                    dial_budget -= 1;
                }
            }
        }

        // Keep = connected peers not in the drop set
        let keep: Vec<PeerId> = snapshot
            .connected_peers
            .iter()
            .filter(|p| !dropped.contains(p))
            .cloned()
            .collect();

        TopologyPlan { keep, dial: dial_intents, drop: drop_intents, discovery }
    }

    fn evaluate_incoming(
        &self,
        snapshot: &TopologySnapshot,
        candidate: &PeerCandidate,
    ) -> AdmissionDecision {
        let connected_now = snapshot.connected_peers.len();
        let policy = snapshot.policy.normalized();
        let known_peers = snapshot.known_peer_count.max(1);

        let hard_limit = if matches!(snapshot.node_role, NodeRole::BootstrapJoin) {
            adaptive_bootstrap_hard_limit(&snapshot.topology_tuning, &policy, known_peers)
        } else {
            policy
                .target_active_peers
                .saturating_add(REGULAR_INCOMING_HEADROOM)
                .min(policy.max_active_peers)
        };
        let soft_limit = if matches!(snapshot.node_role, NodeRole::BootstrapJoin) {
            hard_limit
                .saturating_sub(1)
                .max(policy.target_active_peers)
        } else {
            policy.max_active_peers
        };

        let redirect_descriptors = || -> Vec<NodeDescriptor> {
            use crate::topology::select_peers_for_discovery_response;
            use crate::topology::descriptor_ok_for_discovery_redirect;
            select_peers_for_discovery_response(
                snapshot
                    .catalog_descriptors
                    .iter()
                    .filter(|d| d.peer_id != candidate.peer_id.as_str())
                    .filter(|d| descriptor_ok_for_discovery_redirect(d))
                    .cloned()
                    .collect(),
                Some(candidate.peer_id.as_str()),
                24,
                0.35,
            )
        };

        if connected_now >= hard_limit {
            return AdmissionDecision::Redirect { descriptors: redirect_descriptors() };
        }
        if connected_now >= soft_limit && matches!(snapshot.node_role, NodeRole::BootstrapJoin) {
            return AdmissionDecision::Redirect { descriptors: redirect_descriptors() };
        }

        AdmissionDecision::Accept
    }
}

/// Mirrors `incoming_sessions::adaptive_bootstrap_hard_limit`.
fn adaptive_bootstrap_hard_limit(
    tuning: &TopologyTuning,
    policy: &crate::peer_score::PeerConnectionPolicy,
    known_peers: usize,
) -> usize {
    use crate::node::distribution::BOOTSTRAP_INCOMING_HEADROOM;
    if !tuning.adaptive_topology_enabled {
        return policy
            .target_active_peers
            .saturating_add(BOOTSTRAP_INCOMING_HEADROOM)
            .min(policy.max_active_peers);
    }
    let base = policy.target_active_peers.max(1);
    let cap = tuning.adaptive_bootstrap_hard_max.max(4);
    let candidate = if known_peers <= 24 {
        base.saturating_add(3)
    } else if known_peers <= 96 {
        base.saturating_add(2)
    } else {
        base.saturating_add(1)
    };
    candidate.min(cap).min(policy.max_active_peers.max(base))
}
