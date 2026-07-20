use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use rand::seq::SliceRandom;

use crate::dht::records::{leading_zeros, node_id_of, xor_distance};
use crate::node::incoming_sessions::REGULAR_INCOMING_HEADROOM;
use crate::topology::parse_observed_addr_line;
use crate::topology::planner::{
    AdmissionDecision, DialIntent, DiscoveryNeed, DropIntent, DropReason, PeerCandidate,
    TopologyPlan, TopologyPlanner,
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

// Maximum peers from the same /24 subnet in the diversity slot.
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
    /// Extract /24 prefix from a SocketAddr (IPv4). IPv6 uses /48.
    fn subnet_prefix(addr: &std::net::SocketAddr) -> Option<[u8; 3]> {
        match addr.ip() {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                Some([o[0], o[1], o[2]])
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                Some([o[0], o[1], o[2]])
            }
        }
    }

    /// Build peer → known /24 subnets from dial_book + catalog observed addresses.
    fn peer_subnets(snapshot: &TopologySnapshot) -> HashMap<PeerId, HashSet<[u8; 3]>> {
        let mut map: HashMap<PeerId, HashSet<[u8; 3]>> = HashMap::new();

        for (pid, addrs) in &snapshot.dial_book {
            let entry = map.entry(pid.clone()).or_default();
            for (_proto, addr) in addrs {
                if let Some(s) = Self::subnet_prefix(addr) {
                    entry.insert(s);
                }
            }
        }
        for d in &snapshot.catalog_descriptors {
            let pid = PeerId::from(d.peer_id.as_str());
            let entry = map.entry(pid).or_default();
            for addr_str in &d.observed_addrs {
                if let Some((_, addr)) = parse_observed_addr_line(addr_str) {
                    if let Some(s) = Self::subnet_prefix(&addr) {
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
    /// Returns `(all_desired, structured_peers)` — the structured subset is
    /// protected from rotation to preserve DHT bucket coverage.
    fn select_peer_set(
        &self,
        snapshot: &TopologySnapshot,
        our_node_id: &NodeId,
        subnets: &HashMap<PeerId, HashSet<[u8; 3]>>,
    ) -> (HashSet<PeerId>, HashSet<PeerId>) {
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
            if connected_set.contains(p) {
                base + CONNECTED_SCORE_BONUS
            } else {
                base
            }
        };

        let mut selected: HashSet<PeerId> = HashSet::new();
        let mut structured_peers: HashSet<PeerId> = HashSet::new();

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
            best_per_bucket.sort_by(|a, b| {
                a.0.cmp(&b.0)
                    .then_with(|| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal))
            });
            for (_, peer, _) in best_per_bucket.into_iter().take(structured_n) {
                structured_peers.insert(peer.clone());
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
            let mut subnet_counts: HashMap<[u8; 3], usize> = HashMap::new();
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

        (selected, structured_peers)
    }
}

impl TopologyPlanner for SmartMeshPlanner {
    fn plan(&self, snapshot: &TopologySnapshot) -> TopologyPlan {
        let subnets = Self::peer_subnets(snapshot);
        let our_node_id = node_id_of(snapshot.our_peer_id.as_str());
        let (desired, structured_peers) = self.select_peer_set(snapshot, &our_node_id, &subnets);

        let policy = snapshot.policy.normalized();
        let tuning = &snapshot.topology_tuning;
        let n = snapshot.connected_peers.len();
        let cooldown_ms = tuning.prune_redial_cooldown_ms;
        let residency_ms = tuning.min_peer_residency_ms;
        let epsilon = tuning.replacement_epsilon;
        let rotation_budget_frac = tuning.rotation_budget_frac.clamp(0.0, 1.0);
        // Emergency: high resource pressure — bypass residency and budget guards.
        let is_emergency = snapshot.capacity.overloaded();

        let mut drop_intents: Vec<DropIntent> = Vec::new();
        let mut dropped: HashSet<PeerId> = HashSet::new();
        let mut effective_n = n;

        // Pass 1: hard capacity ceiling — prefer non-desired, then non-structured.
        // No residency or epsilon guard: must shed regardless.
        if effective_n > policy.max_active_peers {
            let drop_n = effective_n.saturating_sub(policy.max_active_peers);
            let score_asc = |a: &PeerId, b: &PeerId| {
                snapshot
                    .total_score_of(a)
                    .partial_cmp(&snapshot.total_score_of(b))
                    .unwrap_or(std::cmp::Ordering::Equal)
            };
            // Order: non-desired non-structured → non-desired structured → desired
            let mut candidates: Vec<PeerId> = snapshot
                .connected_peers
                .iter()
                .filter(|p| !desired.contains(*p) && !structured_peers.contains(*p))
                .cloned()
                .collect();
            candidates.sort_by(score_asc);
            if candidates.len() < drop_n {
                let mut extra: Vec<PeerId> = snapshot
                    .connected_peers
                    .iter()
                    .filter(|p| !desired.contains(*p) && structured_peers.contains(*p))
                    .cloned()
                    .collect();
                extra.sort_by(score_asc);
                candidates.extend(extra);
            }
            if candidates.len() < drop_n {
                let mut extra: Vec<PeerId> = snapshot
                    .connected_peers
                    .iter()
                    .filter(|p| desired.contains(*p))
                    .cloned()
                    .collect();
                extra.sort_by(score_asc);
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
        // Guards: structured bucket protection, minimum residency, replacement epsilon.
        // All guards are bypassed in emergency (resource pressure).
        if effective_n > policy.min_active_peers {
            let rotation_budget =
                ((policy.target_active_peers as f32 * rotation_budget_frac).ceil() as usize)
                    .max(1)
                    .min(effective_n.saturating_sub(policy.min_active_peers));

            // Best unconnected candidate score — needed for epsilon guard.
            let connected_set: HashSet<&PeerId> = snapshot.connected_peers.iter().collect();
            let best_candidate_score = desired
                .iter()
                .filter(|p| {
                    !connected_set.contains(*p)
                        && snapshot.dial_book.contains_key(*p)
                        && !snapshot.in_cooldown(*p)
                })
                .map(|p| snapshot.total_score_of(p))
                .fold(f32::NEG_INFINITY, f32::max);

            let mut rotation_candidates: Vec<PeerId> = snapshot
                .connected_peers
                .iter()
                .filter(|p| {
                    if dropped.contains(*p) || desired.contains(*p) {
                        return false;
                    }
                    if !is_emergency {
                        // Structured bucket protection: keep DHT coverage stable.
                        if structured_peers.contains(*p) {
                            return false;
                        }
                        // Minimum residency: don't evict freshly-connected peers.
                        let age = snapshot.peer_age_ms.get(*p).copied().unwrap_or(0);
                        if age < residency_ms {
                            return false;
                        }
                        // Replacement epsilon: only rotate if the gain justifies it.
                        let peer_score = snapshot.total_score_of(*p);
                        if best_candidate_score <= peer_score + epsilon {
                            return false;
                        }
                    }
                    true
                })
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
        let dial_budget = policy
            .target_active_peers
            .saturating_sub(effective_n)
            .min(8);
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
                    dial_intents.push(DialIntent {
                        peer_id: peer.clone(),
                        addrs: addrs.clone(),
                    });
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

        TopologyPlan {
            keep,
            dial: dial_intents,
            drop: drop_intents,
            discovery,
        }
    }

    fn evaluate_incoming(
        &self,
        snapshot: &TopologySnapshot,
        candidate: &PeerCandidate,
    ) -> AdmissionDecision {
        let connected_now = snapshot.connected_peers.len();
        let policy = snapshot.policy.normalized();

        let hard_limit = policy
            .target_active_peers
            .saturating_add(REGULAR_INCOMING_HEADROOM)
            .min(policy.max_active_peers);

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
            return AdmissionDecision::Redirect {
                descriptors: redirect_descriptors(),
            };
        }

        // Under target: always accept. Seeds are not a privileged cast.
        if connected_now < policy.target_active_peers {
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
        let (desired, _) = self.select_peer_set(snapshot, &our_node_id, &subnets);

        if desired.contains(&candidate.peer_id) {
            AdmissionDecision::Accept
        } else {
            AdmissionDecision::Redirect {
                descriptors: redirect_descriptors(),
            }
        }
    }
}
