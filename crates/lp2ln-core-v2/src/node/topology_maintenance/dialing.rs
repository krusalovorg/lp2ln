use super::packet_helpers::handshake_packet;
use crate::node::distribution::{
    DIAL_HUB_SOFT_CAP_EXTRA, REGULAR_SELF_HEAL_FLOOR, bootstrap_dial_quota, connectivity_selective,
    dial_endpoint_attempt_budget, should_skip_for_bootstrap_quota,
};
use crate::node::link_survival::{PathFailure, RaceCandidate, RaceConfig, race_verified_dial};
use crate::node::options::{BootstrapNode, NodeRole, TopologyTuning};
use crate::node::seed_book::is_local_seed_peer;
use crate::router::Router;
use crate::sessions::manager::SessionManager;
use crate::sessions::session::IncomingPacket;
use crate::topology::{NodeDescriptor, PeerCatalog, PeerDirectory};
use crate::transport::Transport;
use crate::types::{PeerId, SessionId};
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
const REGULAR_DIAL_ATTEMPT_BUDGET_MAX: usize = super::REGULAR_DIAL_ATTEMPT_BUDGET_MAX;
pub(super) struct DialPlan {
    pub(super) candidates: Vec<PeerId>,
    pub(super) desc_by_peer: HashMap<PeerId, NodeDescriptor>,
    pub(super) connected_bootstrap: usize,
    pub(super) dial_limit: usize,
    pub(super) force_non_bootstrap: bool,
}
/// Learns whether a mesh dial reached a live node: the hello goes out right
/// after this, so silence past the deadline means the path is filtered. The
/// link watchdog closes such a session; this only records the outcome.
fn spawn_path_verification(
    router: Arc<Router>,
    session_id: SessionId,
    transport: String,
    addr: SocketAddr,
) {
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        let deadline = RaceConfig::default().verify_timeout;
        while started.elapsed() < deadline {
            if router.session_has_received(&session_id) {
                let rtt = started.elapsed().as_millis() as u64;
                router.paths().record_success(&transport, addr, rtt);
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        router.paths().record_failure(
            &transport,
            addr,
            PathFailure::Silent,
            crate::topology::now_ms(),
        );
    });
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
    seed_targets: &[BootstrapNode],
    now: u64,
) -> DialExecutionResult {
    let dial_deficit = plan.dial_limit.saturating_sub(n).max(1);
    let mut dial_attempts_left = dial_deficit.min(REGULAR_DIAL_ATTEMPT_BUDGET_MAX);
    let mut active_peers = n;
    let mut dialed_any = false;
    for pid in plan.candidates.clone() {
        if active_peers >= plan.dial_limit || dial_attempts_left == 0 {
            break;
        }
        if pid.as_str() == our_peer_maint || sm.is_connected_to_peer(&pid) {
            continue;
        }
        let is_seed = is_local_seed_peer(&pid, catalog.as_ref(), dial_book.as_ref(), seed_targets);
        // Lexical half-connect among mesh (non-seed) peers to reduce duplicate dials.
        if !is_seed && our_peer_maint >= pid.as_str() {
            continue;
        }
        if peer_dir.in_backoff(&pid, now) {
            continue;
        }
        if plan.force_non_bootstrap && is_seed {
            continue;
        }
        if should_skip_for_bootstrap_quota(
            is_seed,
            node_role,
            plan.connected_bootstrap,
            bootstrap_dial_quota(node_role),
            active_peers,
            adaptive_min_active_peers,
        ) {
            continue;
        }
        if let Some(desc) = plan.desc_by_peer.get(&pid) {
            // Soft-cap applies to everyone including seeds (no cast exemption).
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
        let Some(entry) = dial_book.get(&pid) else {
            continue;
        };
        let mut endpoints = entry.value().to_vec();
        drop(entry);
        endpoints.sort_by_key(|(proto, _)| {
            transport_order
                .iter()
                .position(|o| o == proto)
                .unwrap_or(usize::MAX)
        });
        // Static order is only the prior; what actually worked here wins.
        let endpoints = router_maint.paths().rank(&endpoints, now);
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
                        spawn_path_verification(
                            router_maint.clone(),
                            session_id.clone(),
                            transport_name.clone(),
                            addr,
                        );
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
                        if is_seed {
                            plan.connected_bootstrap = plan.connected_bootstrap.saturating_add(1);
                        }
                        dialed_any = true;
                        active_peers = sm.distinct_peer_count();
                        break;
                    }
                    Err(_) => {
                        router_maint.paths().record_failure(
                            &transport_name,
                            addr,
                            PathFailure::Connect,
                            now,
                        );
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
pub(crate) async fn dial_bootstrap_address(
    transports: &[Arc<dyn Transport>],
    router: &Arc<Router>,
    incoming: &tokio::sync::mpsc::Sender<IncomingPacket>,
    our_peer_id: &str,
    target: &crate::node::options::BootstrapNode,
    handshake_payload: &[u8],
    dedupe: Option<&super::BootstrapDialDedupe>,
    record_dial_ok: Option<(&Arc<Mutex<HashMap<SocketAddr, u64>>>, u64)>,
) -> bool {
    let now = crate::topology::now_ms();
    let mut endpoints: Vec<(String, SocketAddr)> = Vec::new();
    // No protocols listed means "any transport we have", on the seed's address.
    let listed = if target.protocols.is_empty() {
        transports
            .iter()
            .map(|t| (t.name().to_string(), target.addr))
            .collect()
    } else {
        target.endpoints()
    };
    for (proto, addr) in listed {
        let usable = transports
            .iter()
            .any(|t| t.is_listener() && t.name().eq_ignore_ascii_case(&proto));
        if usable {
            endpoints.push((proto, addr));
        }
    }
    if let Some(d) = dedupe {
        if d.active_peers > 0 {
            let set = d.set.lock().unwrap();
            if endpoints
                .iter()
                .any(|(p, _)| set.contains(&(p.clone(), target.addr)))
            {
                drop(set);
                if let Some((m, ts)) = record_dial_ok {
                    m.lock().unwrap().insert(target.addr, ts);
                }
                return true;
            }
        }
    }
    let ranked = router.paths().rank(&endpoints, now);
    let peer_hint = target.peer_id_hint.as_ref().map(|p| p.as_str().to_string());
    let candidates: Vec<RaceCandidate> = ranked
        .into_iter()
        .filter_map(|(proto, addr)| {
            let transport = transports
                .iter()
                .find(|t| t.is_listener() && t.name().eq_ignore_ascii_case(&proto))?
                .clone();
            Some(RaceCandidate {
                transport,
                addr,
                peer_hint: peer_hint.clone(),
            })
        })
        .collect();
    let winner = race_verified_dial(
        candidates,
        router.clone(),
        incoming.clone(),
        handshake_packet(our_peer_id, handshake_payload),
        RaceConfig::default(),
    )
    .await;
    let Some(winner) = winner else {
        crate::net_dial!(
            "[NodeRuntime] Bootstrap {} unreachable over every transport",
            target.addr
        );
        return false;
    };
    crate::info!(
        "[NodeRuntime] Connected to bootstrap {} via {} ({} ms)",
        winner.addr,
        winner.transport,
        winner.rtt_ms
    );
    if let Some(d) = dedupe {
        d.set
            .lock()
            .unwrap()
            .insert((winner.transport, target.addr));
    }
    if let Some((m, ts)) = record_dial_ok {
        m.lock().unwrap().insert(target.addr, ts);
    }
    true
}
