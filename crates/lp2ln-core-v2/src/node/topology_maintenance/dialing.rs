use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use dashmap::DashMap;

use crate::node::distribution::{
    DIAL_HUB_SOFT_CAP_EXTRA, REGULAR_SELF_HEAL_FLOOR, bootstrap_dial_quota, connectivity_selective,
    descriptor_prefix24, dial_endpoint_attempt_budget, rank_dial_candidates,
    should_skip_for_bootstrap_quota,
};
use crate::node::options::{NodeRole, TopologyTuning};
use crate::peer_score::{PeerScoreStore, PeerScoreWeights};
use crate::router::Router;
use crate::sessions::manager::SessionManager;
use crate::sessions::session::IncomingPacket;
use crate::topology::{NodeDescriptor, PeerCatalog};
use crate::transport::Transport;
use crate::types::{PeerId, SessionId};

use super::packet_helpers::handshake_packet;

const REGULAR_DIAL_ATTEMPT_BUDGET_MAX: usize = super::REGULAR_DIAL_ATTEMPT_BUDGET_MAX;
const BOOTSTRAP_DIAL_ATTEMPT_BUDGET_MAX: usize = super::BOOTSTRAP_DIAL_ATTEMPT_BUDGET_MAX;

pub(super) struct DialPlan {
    pub(super) candidates: Vec<PeerId>,
    pub(super) desc_by_peer: HashMap<PeerId, NodeDescriptor>,
    pub(super) connected_bootstrap: usize,
    pub(super) dial_limit: usize,
    pub(super) force_non_bootstrap: bool,
}

pub(super) struct DialExecutionResult {
    pub(super) dialed_any: bool,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_dial_plan(
    dial_book: &Arc<DashMap<PeerId, Vec<(String, SocketAddr)>>>,
    router_maint: &Arc<Router>,
    catalog: &Arc<PeerCatalog>,
    peer_store: &Arc<PeerScoreStore>,
    weights: &PeerScoreWeights,
    our_peer: &str,
    node_role: NodeRole,
    known_peers: usize,
    n: usize,
    desired: usize,
    dial_target: usize,
    dial_target_high: usize,
    adaptive_min_active_peers: usize,
    exploratory_slots: usize,
    topology_tuning: &TopologyTuning,
    should_explore: bool,
    now: u64,
) -> DialPlan {
    let mut candidates: Vec<PeerId> = dial_book.iter().map(|r| r.key().clone()).collect();
    let desc_by_peer: HashMap<PeerId, NodeDescriptor> = catalog
        .descriptors()
        .into_iter()
        .map(|d| (PeerId::from(d.peer_id.as_str()), d))
        .collect();
    let stale_descriptor_cutoff_ms = now.saturating_sub(90_000);
    candidates.retain(|pid| {
        desc_by_peer
            .get(pid)
            .map(|d| d.timestamp_ms >= stale_descriptor_cutoff_ms)
            .unwrap_or(true)
    });
    let connected_snapshot = router_maint.connected_peers();
    let connected_bootstrap = connected_snapshot
        .iter()
        .filter(|p| catalog.peer_is_bootstrap_entry(p))
        .count();
    let connected_non_bootstrap = connected_snapshot.len().saturating_sub(connected_bootstrap);
    let target_non_bootstrap = if matches!(node_role, NodeRole::Regular) {
        desired.saturating_sub(topology_tuning.regular_bootstrap_min_keep)
    } else {
        0
    };
    let force_non_bootstrap = matches!(node_role, NodeRole::Regular)
        && connected_bootstrap > 0
        && connected_non_bootstrap < target_non_bootstrap;
    let bootstrap_quota = bootstrap_dial_quota(node_role);
    let connected_prefix24: HashSet<[u8; 3]> = connected_snapshot
        .iter()
        .filter_map(|pid| catalog.descriptor_of(pid))
        .filter_map(|d| descriptor_prefix24(&d))
        .collect();
    rank_dial_candidates(
        &mut candidates,
        peer_store.as_ref(),
        weights,
        &desc_by_peer,
        our_peer,
        node_role,
        dial_target,
        connected_bootstrap,
        bootstrap_quota,
        true,
        n,
        adaptive_min_active_peers,
        &connected_prefix24,
        known_peers,
        exploratory_slots,
    );
    let dial_limit = if should_explore || force_non_bootstrap {
        dial_target_high
    } else {
        dial_target
    };
    DialPlan {
        candidates,
        desc_by_peer,
        connected_bootstrap,
        dial_limit,
        force_non_bootstrap,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn execute_dial_plan(
    plan: &mut DialPlan,
    n: usize,
    node_role: NodeRole,
    adaptive_min_active_peers: usize,
    dial_target: usize,
    dial_book: &Arc<DashMap<PeerId, Vec<(String, SocketAddr)>>>,
    catalog: &Arc<PeerCatalog>,
    sm: &Arc<SessionManager>,
    transports_maint: &[Arc<dyn Transport>],
    router_maint: &Arc<Router>,
    incoming_maint: &tokio::sync::mpsc::Sender<IncomingPacket>,
    our_peer_maint: &str,
    maintenance_handshake_payload: &[u8],
    dial_cooldown_until: &mut HashMap<PeerId, u64>,
    topology_tuning: &TopologyTuning,
    transport_order: &[String],
    now: u64,
) -> DialExecutionResult {
    let dial_deficit = plan.dial_limit.saturating_sub(n).max(1);
    let mut dial_attempts_left = if matches!(node_role, NodeRole::Regular) {
        dial_deficit.min(REGULAR_DIAL_ATTEMPT_BUDGET_MAX)
    } else {
        dial_deficit.min(BOOTSTRAP_DIAL_ATTEMPT_BUDGET_MAX)
    };
    let mut active_peers = n;
    let mut dialed_any = false;
    for pid in plan.candidates.clone() {
        if active_peers >= plan.dial_limit || dial_attempts_left == 0 {
            break;
        }
        if pid.as_str() == our_peer_maint || sm.is_connected_to_peer(&pid) {
            continue;
        }
        if matches!(node_role, NodeRole::Regular) {
            let mesh_peer = plan
                .desc_by_peer
                .get(&pid)
                .map(|d| !d.capabilities.bootstrap_entry)
                .unwrap_or(!catalog.peer_is_bootstrap_entry(&pid));
            if mesh_peer && our_peer_maint >= pid.as_str() {
                continue;
            }
        }
        if let Some(until) = dial_cooldown_until.get(&pid).copied() {
            if now < until {
                continue;
            }
        }
        if let Some(desc) = plan.desc_by_peer.get(&pid) {
            if plan.force_non_bootstrap && desc.capabilities.bootstrap_entry {
                continue;
            }
            if should_skip_for_bootstrap_quota(
                desc,
                node_role,
                plan.connected_bootstrap,
                bootstrap_dial_quota(node_role),
                active_peers,
                adaptive_min_active_peers,
            ) {
                continue;
            }
            if !desc.capabilities.bootstrap_entry {
                let selective =
                    connectivity_selective(active_peers, dial_target, adaptive_min_active_peers);
                if selective && !desc.dynamic_status.accepts_new_sessions {
                    continue;
                }
                let cap = desc.capabilities.base_session_limit.max(1) as usize;
                if selective
                    && active_peers >= REGULAR_SELF_HEAL_FLOOR
                    && desc.dynamic_status.active_connections as usize >= cap
                {
                    continue;
                }
                let soft_cap = dial_target.saturating_add(DIAL_HUB_SOFT_CAP_EXTRA);
                if selective
                    && active_peers >= REGULAR_SELF_HEAL_FLOOR
                    && desc.dynamic_status.active_connections as usize > soft_cap
                {
                    continue;
                }
            }
        }

        let Some(entry) = dial_book.get(&pid) else {
            continue;
        };
        let mut endpoints = entry.value().to_vec();
        drop(entry);
        // Sort by preferred transport order (quic > udp > tcp by default).
        endpoints.sort_by_key(|(proto, _)| {
            transport_order
                .iter()
                .position(|o| o == proto)
                .unwrap_or(usize::MAX)
        });
        let max_endpoints = dial_endpoint_attempt_budget(
            active_peers,
            dial_target,
            adaptive_min_active_peers,
            endpoints.len(),
        );
        let mut tried_endpoints: HashSet<(String, SocketAddr)> = HashSet::new();
        let mut endpoint_attempts = 0usize;
        for (transport_name, addr) in endpoints {
            if endpoint_attempts >= max_endpoints {
                break;
            }
            if !tried_endpoints.insert((transport_name.clone(), addr)) {
                continue;
            }
            if let Some(t) = transports_maint
                .iter()
                .find(|t| t.name() == transport_name.as_str())
            {
                if !t.is_listener() {
                    continue;
                }
                if sm.is_connected_to_peer(&pid) {
                    break;
                }
                endpoint_attempts = endpoint_attempts.saturating_add(1);
                dial_attempts_left = dial_attempts_left.saturating_sub(1);
                match t.dial(addr).await {
                    Ok(session) => {
                        let session_id = SessionId::from(session.id().to_string());
                        router_maint.register_session(
                            pid.clone(),
                            session_id.clone(),
                            session.clone(),
                        );
                        session.spawn_reader(incoming_maint.clone());
                        let handshake =
                            handshake_packet(our_peer_maint, maintenance_handshake_payload);
                        let _ = router_maint.send_to_session(session_id, handshake).await;
                        catalog.observe_success(&pid, 80);
                        if plan
                            .desc_by_peer
                            .get(&pid)
                            .is_some_and(|d| d.capabilities.bootstrap_entry)
                        {
                            plan.connected_bootstrap = plan.connected_bootstrap.saturating_add(1);
                        }
                        dial_cooldown_until.remove(&pid);
                        dialed_any = true;
                        active_peers = sm.distinct_peer_count();
                        break;
                    }
                    Err(_) => {
                        catalog.observe_failure(&pid);
                        dial_cooldown_until.insert(
                            pid.clone(),
                            now.saturating_add(topology_tuning.dial_retry_cooldown_ms),
                        );
                    }
                }
            }
        }
    }
    DialExecutionResult { dialed_any }
}
