use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use dashmap::DashMap;

use crate::node::distribution::{
    DIAL_HUB_SOFT_CAP_EXTRA, REGULAR_SELF_HEAL_FLOOR, bootstrap_dial_quota, connectivity_selective,
    dial_endpoint_attempt_budget, should_skip_for_bootstrap_quota,
};
use crate::node::options::{NodeRole, TopologyTuning};
use crate::router::Router;
use crate::sessions::manager::SessionManager;
use crate::sessions::session::IncomingPacket;
use crate::topology::{NodeDescriptor, PeerCatalog, PeerDirectory};
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
    peer_dir: &Arc<PeerDirectory>,
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
        if peer_dir.in_backoff(&pid, now) {
            continue;
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
                match t.dial_with_peer(addr, Some(pid.as_str())).await {
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
                        peer_dir.record_dial_success(&pid, now);
                        if plan
                            .desc_by_peer
                            .get(&pid)
                            .is_some_and(|d| d.capabilities.bootstrap_entry)
                        {
                            plan.connected_bootstrap = plan.connected_bootstrap.saturating_add(1);
                        }
                        dialed_any = true;
                        active_peers = sm.distinct_peer_count();
                        break;
                    }
                    Err(_) => {
                        catalog.observe_failure(&pid);
                        peer_dir.record_dial_failure(
                            &pid,
                            topology_tuning.dial_retry_cooldown_ms,
                            now,
                        );
                    }
                }
            }
        }
    }
    DialExecutionResult { dialed_any }
}
