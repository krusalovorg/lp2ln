use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use rand::seq::SliceRandom;

use crate::dht::records::{leading_zeros, node_id_of, xor_distance};
use crate::node::incoming_sessions::REGULAR_INCOMING_HEADROOM;
use crate::node::options::NodeRole;
use crate::topology::parse_observed_addr_line;
use crate::topology::planner::{
    adaptive_bootstrap_hard_limit, AdmissionDecision, DialIntent, DiscoveryNeed, DropIntent,
    DropReason, PeerCandidate, TopologyPlan, TopologyPlanner,
};
use crate::topology::snapshot::TopologySnapshot;
use crate::topology::{descriptor_ok_for_discovery_redirect, select_peers_for_discovery_response};
use crate::types::{NodeId, PeerId};

// Slot budget fractions (of target_active_peers); sum ≤ 1.0 so ~10 % goes to best-available fill.
// ponytail: step 8 adds per-slot rotation budgets + minimum residency guards.
const STRUCTURED_FRAC: f32 = 0.25;
const UTILITY_FRAC: f32 = 0.40;
const DIVERSITY_FRAC: f32 = 0.20;
const EXPLORATION_FRAC: f32 = 0.10;

// Small bonus for already-connected peers to reduce unnecessary rotation churn.
const CONNECTED_SCORE_BONUS: f32 = 0.05;

// Maximum peers from the same /16 subnet in the diversity slot.
const DIVERSITY_SUBNET_CAP: usize = 2;

/// SmartMesh v1 topology planner.
///
/// Builds the desired peer set by marginal gain across four orthogonal slot types:
///   structured  — logarithmic XOR-bucket coverage for DHT routing progress
///   utility     — best composite RTT/stability/score workhorses
///   diversity   — /16-subnet + reachability spread
///   exploration — bounded random rotation
///
/// `plan()` derives keep/dial/drop from the diff between desired and connected.
/// `evaluate_incoming()` accepts when a candidate fills an open slot.
pub struct SmartMeshPlanner;

impl SmartMeshPlanner {
    /// Extract /16 prefix from a SocketAddr.
    fn subnet16(addr: &std::net::SocketAddr) -> Option<[u8; 2]> {
        match addr.ip() {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                Some([o[0], o[1]])
            }
            // ponytail: IPv6 /48 diversity — step 8
            IpAddr::V6(_) => None,
        }
    }

    /// Build peer → known /16 subnets from dial_book + catalog observed addresses.
    fn peer_subnets(snapshot: &TopologySnapshot) -> HashMap<PeerId, HashSet<[u8; 2]>> {
        let mut map: HashMap<PeerId, HashSet<[u8; 2]>> = HashMap::new();

        for (peer, addrs) in &snapshot.dial_book {
            let entry = map.entry(peer.clone()).or_default();
            for (_, addr) in addrs {
                if let Some(s) = Self::subnet16(addr) {
                    entry.insert(s);
                }
            }
        }
        for desc in &snapshot.catalog_descriptors {
            let peer = PeerId::from(desc.peer_id.as_str());
            let entry = map.entry(peer).or_default();
            for addr_str in &desc.observed_addrs {
                if let Some((_, addr)) = parse_observed_addr_line(addr_str) {
                    if let Some(s) = Self::subnet16(&addr) {
                        entry.insert(s);
                    }
                }
            }
        }
        map
    }

    /// XOR-bucket index for `peer` relative to `our_id` (low = farther region of keyspace).
    fn bucket_for(our_id: &NodeId, peer: &PeerId) -> usize {
        let peer_nid = node_id_of(peer.as_str());
        let dist = xor_distance(our_id, &peer_nid);
        leading_zeros(&dist).min(255)
    }

    /// Greedy marginal-gain peer set selection across the four slot types.
    fn select_peer_set(
        &self,
        snapshot: &TopologySnapshot,
        our_node_id: &NodeId,
        subnets: &HashMap<PeerId, HashSet<[u8; 2]>>,
    ) -> HashSet<PeerId> {
        let policy = snapshot.policy.normalized();
        let target = policy.target_active_peers.max(1);

        let structured_n = ((target as f32 * STRUCTURED_FRAC).ceil() as usize).max(1);
        let utility_n = ((target as f32 * UTILITY_FRAC).ceil() as usize).max(1);
        let diversity_n = ((target as f32 * DIVERSITY_FRAC).ceil() as usize).max(1);
        let exploration_n = ((target as f32 * EXPLORATION_FRAC).ceil() as usize).max(1);

        let connected_set: HashSet<&PeerId> = snapshot.connected_peers.iter().collect();

        // All candidates (connected ∪ dial_book), excluding self, deduped.
        let mut seen = HashSet::new();
        let all_candidates: Vec<PeerId> = snapshot
            .connected_peers
            .iter()
            .chain(snapshot.dial_book.keys())
            .filter(|p| p.as_str() != snapshot.our_peer_id.as_str())
            .filter(|p| seen.insert((*p).clone()))
            .cloned()
            .collect();

        let score_of = |p: &PeerId| -> f32 {
            let base = snapshot.total_score_of(p);
            if connected_set.contains(p) { base + CONNECTED_SCORE_BONUS } else { base }
        };

        let mut selected: HashSet<PeerId> = HashSet::new();

        // ── Phase 1: structured — one peer per XOR bucket ────────────────────
        // Covers distinct regions of the keyspace; ensures routing progress.
        {
            let mut buckets: HashMap<usize, Vec<(PeerId, f32)>> = HashMap::new();
            for p in &all_candidates {
                let b = Self::bucket_for(our_node_id, p);
                buckets.entry(b).or_default().push((p.clone(), score_of(p)));
            }
            for v in buckets.values_mut() {
                v.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            }
            // Sort by bucket index asc so far regions are covered first; tie-break by score.
            let mut best_per_bucket: Vec<(usize, PeerId, f32)> = buckets
                .iter()
                .filter_map(|(&b, v)| v.first().map(|(p, s)| (b, p.clone(), *s)))
                .collect();
            best_per_bucket
                .sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal)));
            for (_, peer, _) in best_per_bucket.into_iter().take(structured_n) {
                selected.insert(peer);
            }
        }

        // ── Phase 2: utility — top scorers not yet selected ──────────────────
        {
            let mut by_score: Vec<(PeerId, f32)> = all_candidates
                .iter()
                .filter(|p| !selected.contains(*p))
                .map(|p| (p.clone(), score_of(p)))
                .collect();
            by_score.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            for (peer, _) in by_score.into_iter().take(utility_n) {
                selected.insert(peer);
            }
        }

        // ── Phase 3: diversity — /16-subnet spread ───────────────────────────
        {
            let mut subnet_counts: HashMap<[u8; 2], usize> = HashMap::new();
            for p in &selected {
                for s in subnets.get(p).into_iter().flatten() {
                    *subnet_counts.entry(*s).or_default() += 1;
                }
            }
            let mut candidates: Vec<(PeerId, f32)> = all_candidates
                .iter()
                .filter(|p| !selected.contains(*p))
                .map(|p| (p.clone(), score_of(p)))
                .collect();
            candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

            let mut added = 0usize;
            // First pass: only accept if the peer adds at least one new /16.
            for (peer, _) in &candidates {
                if added >= diversity_n {
                    break;
                }
                let adds_new = subnets
                    .get(peer)
                    .into_iter()
                    .flatten()
                    .any(|s| subnet_counts.get(s).copied().unwrap_or(0) < DIVERSITY_SUBNET_CAP);
                let no_addr = subnets.get(peer).map(|s| s.is_empty()).unwrap_or(true);
                if adds_new || no_addr {
                    for s in subnets.get(peer).into_iter().flatten() {
                        *subnet_counts.entry(*s).or_default() += 1;
                    }
                    selected.insert(peer.clone());
                    added += 1;
                }
            }
            // Second pass: fill remaining diversity slots by score if first pass fell short.
            if added < diversity_n {
                let fill: Vec<PeerId> = candidates
                    .iter()
                    .filter(|(p, _)| !selected.contains(p))
                    .take(diversity_n - added)
                    .map(|(p, _)| p.clone())
                    .collect();
                added += fill.len();
                selected.extend(fill);
            }
            let _ = added;
        }

        // ── Phase 4: exploration — bounded random rotation ───────────────────
        {
            let mut remaining: Vec<PeerId> = all_candidates
                .into_iter()
                .filter(|p| !selected.contains(p))
                .collect();
            remaining.shuffle(&mut rand::rng());
            for peer in remaining.into_iter().take(exploration_n) {
                selected.insert(peer);
            }
        }

        selected
    }
}

impl TopologyPlanner for SmartMeshPlanner {
    fn plan(&self, snapshot: &TopologySnapshot) -> TopologyPlan {
        let subnets = Self::peer_subnets(snapshot);
        let our_node_id = node_id_of(snapshot.our_peer_id.as_str());
        let desired = self.select_peer_set(snapshot, &our_node_id, &subnets);

        let policy = snapshot.policy.normalized();
        let n = snapshot.connected_peers.len();
        let cooldown_ms = snapshot.topology_tuning.prune_redial_cooldown_ms;
        let mut drop_intents: Vec<DropIntent> = Vec::new();
        let mut dropped: HashSet<PeerId> = HashSet::new();
        let mut effective_n = n;

        // Pass 1: hard capacity ceiling — prefer non-desired peers.
        if effective_n > policy.max_active_peers {
            let drop_n = effective_n.saturating_sub(policy.max_active_peers);
            let mut candidates: Vec<PeerId> = snapshot
                .connected_peers
                .iter()
                .filter(|p| !desired.contains(*p))
                .cloned()
                .collect();
            candidates.sort_by(|a, b| {
                snapshot
                    .total_score_of(a)
                    .partial_cmp(&snapshot.total_score_of(b))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            if candidates.len() < drop_n {
                // Exhausted non-desired; dip into desired (lowest score first).
                let mut extra: Vec<PeerId> = snapshot
                    .connected_peers
                    .iter()
                    .filter(|p| desired.contains(*p))
                    .cloned()
                    .collect();
                extra.sort_by(|a, b| {
                    snapshot
                        .total_score_of(a)
                        .partial_cmp(&snapshot.total_score_of(b))
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                candidates.extend(extra);
            }
            for p in candidates.into_iter().take(drop_n) {
                effective_n = effective_n.saturating_sub(1);
                dropped.insert(p.clone());
                drop_intents.push(DropIntent {
                    peer_id: p,
                    reason: DropReason::Overloaded,
                    cooldown_until_ms: snapshot.now_ms.saturating_add(cooldown_ms),
                });
            }
        }

        // Pass 2: rotation — shed connected peers outside the desired set.
        // ponytail: step 8 adds minimum residency + per-tick rotation budget cap.
        if effective_n > policy.min_active_peers {
            let rotation_budget = (policy.target_active_peers / 4)
                .max(1)
                .min(effective_n.saturating_sub(policy.min_active_peers));
            let mut rotation_candidates: Vec<PeerId> = snapshot
                .connected_peers
                .iter()
                .filter(|p| !dropped.contains(*p) && !desired.contains(*p))
                .cloned()
                .collect();
            rotation_candidates.sort_by(|a, b| {
                snapshot
                    .total_score_of(a)
                    .partial_cmp(&snapshot.total_score_of(b))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            for p in rotation_candidates.into_iter().take(rotation_budget) {
                effective_n = effective_n.saturating_sub(1);
                dropped.insert(p.clone());
                drop_intents.push(DropIntent {
                    peer_id: p,
                    reason: DropReason::Rotation,
                    cooldown_until_ms: snapshot.now_ms.saturating_add(cooldown_ms / 2),
                });
            }
        }

        // Dial: desired peers not yet connected and not in cooldown.
        let connected_set: HashSet<&PeerId> = snapshot.connected_peers.iter().collect();
        let dial_budget = policy.target_active_peers.saturating_sub(effective_n).min(8);
        let mut dial_intents: Vec<DialIntent> = Vec::new();

        if effective_n < policy.target_active_peers {
            let mut dial_candidates: Vec<(&PeerId, f32)> = desired
                .iter()
                .filter(|p| {
                    !connected_set.contains(*p)
                        && !dropped.contains(*p)
                        && snapshot.dial_book.contains_key(*p)
                        && !snapshot.in_cooldown(*p)
                })
                .map(|p| (p, snapshot.total_score_of(p)))
                .collect();
            dial_candidates
                .sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            for (peer, _) in dial_candidates.into_iter().take(dial_budget) {
                if let Some(addrs) = snapshot.dial_book.get(peer) {
                    dial_intents.push(DialIntent { peer_id: peer.clone(), addrs: addrs.clone() });
                }
            }
        }

        // Discovery: request more peers if below target and dial candidates are thin.
        let mut discovery: Vec<DiscoveryNeed> = Vec::new();
        if effective_n + dial_intents.len() < policy.target_active_peers {
            let request_from: Vec<PeerId> = snapshot
                .connected_peers
                .iter()
                .filter(|p| !dropped.contains(*p))
                .cloned()
                .collect();
            if !request_from.is_empty() {
                discovery.push(DiscoveryNeed { request_from });
            }
        }

        let keep: Vec<PeerId> = snapshot
            .connected_peers
            .iter()
            .filter(|p| !dropped.contains(*p))
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

        let redirect_descriptors = || {
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

        // Under target or bootstrap entry: always accept.
        if connected_now < policy.target_active_peers || candidate.is_bootstrap_entry {
            return AdmissionDecision::Accept;
        }

        // Between target and hard_limit — apply marginal gain only for peers we already know.
        // Unknown peers (not in dial_book or connected) get a free pass: we have no score data
        // for them and they may fill an uncovered XOR bucket or diversity slot.
        let is_known = snapshot.connected_peers.contains(&candidate.peer_id)
            || snapshot.dial_book.contains_key(&candidate.peer_id);
        if !is_known {
            return AdmissionDecision::Accept;
        }

        // Known peer: accept only if the candidate would occupy a desired slot.
        let our_node_id = node_id_of(snapshot.our_peer_id.as_str());
        let subnets = Self::peer_subnets(snapshot);
        let desired = self.select_peer_set(snapshot, &our_node_id, &subnets);

        if desired.contains(&candidate.peer_id) {
            AdmissionDecision::Accept
        } else {
            AdmissionDecision::Redirect { descriptors: redirect_descriptors() }
        }
    }
}
