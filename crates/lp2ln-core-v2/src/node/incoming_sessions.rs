use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::node::distribution::{
    peers_to_drop_when_overloaded, BOOTSTRAP_INCOMING_HEADROOM, INCOMING_ROTATION_INTERVAL_MS,
    OVERLOAD_REDIRECT_DESCRIPTOR_LIMIT,
};

/// Сколько regular-дескрипторов слать newcomer'у proactive-сразу после handshake
/// (чтобы не ждать RequestPeers → быстрое переключение на mesh).
pub const BOOTSTRAP_PROACTIVE_PEERS_LIMIT: usize = 20;
/// Максимальный admission jitter на bootstrap при всплеске входящих.
pub const BOOTSTRAP_ADMISSION_JITTER_MAX_MS: u64 = 3_000;
/// Сколько менее загруженных bootstrap-соседей вкладывать в preamble
/// при overload-редиректе, чтобы newcomer шёл сначала к ним.
pub const BOOTSTRAP_PEER_REDIRECT_PREAMBLE: usize = 3;
/// Для regular ограничиваем входящие возле target (а не max), чтобы
/// не раздувать degree из-за лавины входящих дозвонов.
pub const REGULAR_INCOMING_HEADROOM: usize = 2;

fn adaptive_bootstrap_hard_limit(
    tuning: &TopologyTuning,
    policy: &PeerConnectionPolicy,
    known_peers: usize,
) -> usize {
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

/// Собирает до `limit` дескрипторов других bootstrap-нод, у которых
/// `active_connections` меньше `our_ac`, отсортированных по возрастанию
/// нагрузки. Пустой, если все другие bootstrap'ы более загружены.
pub fn less_loaded_bootstrap_descriptors(
    catalog: &PeerCatalog,
    our_peer_id: &str,
    our_active_connections: u16,
    exclude_peer_id: &str,
    recent_bootstrap_hints: &std::collections::HashMap<String, u32>,
    limit: usize,
) -> Vec<crate::topology::NodeDescriptor> {
    let mut candidates: Vec<_> = catalog
        .descriptors()
        .into_iter()
        .filter(|d| d.peer_id != our_peer_id && d.peer_id != exclude_peer_id)
        .filter(|d| d.capabilities.bootstrap_entry)
        .filter(|d| d.dynamic_status.active_connections < our_active_connections)
        .filter(|d| descriptor_ok_for_discovery_redirect(d))
        .collect();
    candidates.sort_by_key(|d| {
        (
            *recent_bootstrap_hints.get(&d.peer_id).unwrap_or(&0),
            d.dynamic_status.active_connections,
        )
    });
    candidates.truncate(limit);
    candidates
}
use crate::node::options::{NodeOptions, NodeRole, TopologyTuning};
use crate::peer_score::PeerConnectionPolicy;
use crate::packet::Packet;
use crate::peer_score::{PeerScoreStore, PeerScoreWeights};
use crate::protocol::control::NetworkControlPayload;
use crate::router::Router;
use crate::sessions::manager::SessionManager;
use crate::sessions::session::IncomingPacket;
use crate::sessions::Session;
use crate::topology::{
    descriptor_ok_for_discovery_redirect, now_ms, select_peers_for_discovery_response, PeerCatalog,
};
use crate::types::{PeerId, SessionId};

pub async fn send_discovery_redirect_and_close(
    router: &Arc<Router>,
    session: Arc<dyn Session>,
    session_id: &SessionId,
    newcomer: &PeerId,
    our_peer_id: &str,
    catalog: &PeerCatalog,
    random_fraction: f32,
) {
    send_discovery_redirect_and_close_with_preamble(
        router,
        session,
        session_id,
        newcomer,
        our_peer_id,
        catalog,
        random_fraction,
        Vec::new(),
    )
    .await;
}

/// Как `send_discovery_redirect_and_close`, но `preamble` ставится в начало
/// PeersResponse. Используется bootstrap'ом при overload для приоритетного
/// перенаправления newcomer'а на менее загруженные bootstrap-соседи.
pub async fn send_discovery_redirect_and_close_with_preamble(
    router: &Arc<Router>,
    session: Arc<dyn Session>,
    session_id: &SessionId,
    newcomer: &PeerId,
    our_peer_id: &str,
    catalog: &PeerCatalog,
    random_fraction: f32,
    preamble: Vec<crate::topology::NodeDescriptor>,
) {
    router.register_session_only(session_id.clone(), session);
    let exclude_ids: std::collections::HashSet<String> = preamble
        .iter()
        .map(|d| d.peer_id.clone())
        .collect();
    let remaining_limit = OVERLOAD_REDIRECT_DESCRIPTOR_LIMIT.saturating_sub(preamble.len());
    let mut descriptors: Vec<crate::topology::NodeDescriptor> = preamble;
    if remaining_limit > 0 {
        let extra = select_peers_for_discovery_response(
            catalog
                .descriptors()
                .into_iter()
                .filter(|d| d.peer_id != newcomer.as_str())
                .filter(|d| !exclude_ids.contains(&d.peer_id))
                .filter(|d| descriptor_ok_for_discovery_redirect(d))
                .collect(),
            Some(newcomer.as_str()),
            remaining_limit,
            random_fraction,
        );
        descriptors.extend(extra);
    }
    if !descriptors.is_empty() {
        let msg = NetworkControlPayload::PeersResponse { descriptors };
        if let Ok(data) = msg.encode() {
            let packet = Packet {
                signature: None,
                data,
                nodes: vec![],
                sender: our_peer_id.to_string(),
                receiver: newcomer.as_str().to_string(),
                max_hops: 2,
                request_id: None,
                chunk_stream_id: None,
                chunk_index: None,
                total_chunks: None,
            };
            let _ = router.send_to_session(session_id.clone(), packet).await;
        }
    }
    let _ = router.teardown_session(session_id).await;
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_incoming_session_handler(
    incoming_sessions_rx: &mut tokio::sync::mpsc::Receiver<Arc<dyn Session>>,
    session_manager: Arc<SessionManager>,
    router_for_incoming: Arc<Router>,
    our_peer_id_for_incoming: String,
    policy_live_incoming: Arc<RwLock<PeerConnectionPolicy>>,
    incoming_catalog: Arc<PeerCatalog>,
    incoming_peer_store: Arc<PeerScoreStore>,
    incoming_weights: PeerScoreWeights,
    incoming_node_role: NodeRole,
    incoming_topology_tuning: TopologyTuning,
    incoming_discovery_random_fraction: f32,
    incoming_packets_tx_for_sessions: tokio::sync::mpsc::Sender<IncomingPacket>,
) -> anyhow::Result<()> {
    let mut last_rotation_ms = 0u64;
    let mut recent_redirect_until: std::collections::HashMap<PeerId, u64> =
        std::collections::HashMap::new();
    let mut recent_bootstrap_hints: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    let mut fairness_window_started_ms = now_ms();
    while let Some(session) = incoming_sessions_rx.recv().await {
            let incoming_policy = NodeOptions::effective_peer_connection_policy_for(
                policy_live_incoming.read().unwrap().clone(),
                incoming_node_role,
            )
            .normalized();
            crate::session!(
                "[NodeRuntime] New session: {} (kind: {:?})",
                session.id(),
                session.kind()
            );

            let session_id = SessionId::from(session.id().to_string());
            if let Some(peer_id) = session.peer_id() {
                let pid = PeerId::from(peer_id.to_string());
                let already_connected = session_manager.is_connected_to_peer(&pid);
                if already_connected {
                    crate::debug!(
                        "[NodeRuntime] Reject duplicate incoming session from {}",
                        pid
                    );
                    send_discovery_redirect_and_close(
                        &router_for_incoming,
                        session.clone(),
                        &session_id,
                        &pid,
                        &our_peer_id_for_incoming,
                        incoming_catalog.as_ref(),
                        incoming_discovery_random_fraction,
                    )
                    .await;
                    if matches!(incoming_node_role, NodeRole::BootstrapJoin) {
                        let now = now_ms();
                        recent_redirect_until.insert(
                            pid.clone(),
                            now.saturating_add(incoming_topology_tuning.adaptive_redirect_memory_ms),
                        );
                    }
                    continue;
                }

                let connected_now = session_manager.distinct_peer_count();
                let now = now_ms();
                if now.saturating_sub(fairness_window_started_ms)
                    >= incoming_topology_tuning.adaptive_redirect_memory_ms
                {
                    recent_bootstrap_hints.clear();
                    fairness_window_started_ms = now;
                }
                if let Some(until) = recent_redirect_until.get(&pid).copied() {
                    if now < until {
                        send_discovery_redirect_and_close(
                            &router_for_incoming,
                            session.clone(),
                            &session_id,
                            &pid,
                            &our_peer_id_for_incoming,
                            incoming_catalog.as_ref(),
                            incoming_discovery_random_fraction,
                        )
                        .await;
                        continue;
                    }
                }
                let known_peers = incoming_catalog.known_peer_ids().len().max(1);
                let hard_limit = if matches!(incoming_node_role, NodeRole::BootstrapJoin) {
                    adaptive_bootstrap_hard_limit(
                        &incoming_topology_tuning,
                        &incoming_policy,
                        known_peers,
                    )
                } else {
                    incoming_policy
                        .target_active_peers
                        .saturating_add(REGULAR_INCOMING_HEADROOM)
                        .min(incoming_policy.max_active_peers)
                };
                let soft_limit = if matches!(incoming_node_role, NodeRole::BootstrapJoin) {
                    hard_limit.saturating_sub(1).max(incoming_policy.target_active_peers)
                } else {
                    incoming_policy.max_active_peers
                };
                if connected_now >= hard_limit {
                    crate::debug!(
                        "[NodeRuntime] Redirect incoming session from {}: hard peer limit reached ({})",
                        pid,
                        hard_limit
                    );
                    let preamble = if matches!(incoming_node_role, NodeRole::BootstrapJoin) {
                        less_loaded_bootstrap_descriptors(
                            incoming_catalog.as_ref(),
                            &our_peer_id_for_incoming,
                            connected_now.min(u16::MAX as usize) as u16,
                            pid.as_str(),
                            &recent_bootstrap_hints,
                            BOOTSTRAP_PEER_REDIRECT_PREAMBLE,
                        )
                    } else {
                        Vec::new()
                    };
                    send_discovery_redirect_and_close_with_preamble(
                        &router_for_incoming,
                        session.clone(),
                        &session_id,
                        &pid,
                        &our_peer_id_for_incoming,
                        incoming_catalog.as_ref(),
                        incoming_discovery_random_fraction,
                        preamble.clone(),
                    )
                    .await;
                    for d in preamble {
                        *recent_bootstrap_hints.entry(d.peer_id).or_insert(0) += 1;
                    }
                    if matches!(incoming_node_role, NodeRole::BootstrapJoin) {
                        recent_redirect_until.insert(
                            pid.clone(),
                            now.saturating_add(incoming_topology_tuning.adaptive_redirect_memory_ms),
                        );
                    }
                    continue;
                }

                if connected_now >= soft_limit {
                    if matches!(incoming_node_role, NodeRole::BootstrapJoin) {
                        crate::debug!(
                            "[NodeRuntime] Redirect incoming session from {}: bootstrap soft limit reached ({})",
                            pid,
                            incoming_policy.max_active_peers
                        );
                        let preamble = less_loaded_bootstrap_descriptors(
                            incoming_catalog.as_ref(),
                            &our_peer_id_for_incoming,
                            connected_now.min(u16::MAX as usize) as u16,
                            pid.as_str(),
                            &recent_bootstrap_hints,
                            BOOTSTRAP_PEER_REDIRECT_PREAMBLE,
                        );
                        send_discovery_redirect_and_close_with_preamble(
                            &router_for_incoming,
                            session.clone(),
                            &session_id,
                            &pid,
                            &our_peer_id_for_incoming,
                            incoming_catalog.as_ref(),
                            incoming_discovery_random_fraction,
                            preamble.clone(),
                        )
                        .await;
                        for d in preamble {
                            *recent_bootstrap_hints.entry(d.peer_id).or_insert(0) += 1;
                        }
                        recent_redirect_until.insert(
                            pid.clone(),
                            now.saturating_add(incoming_topology_tuning.adaptive_redirect_memory_ms),
                        );
                        continue;
                    }
                    if now.saturating_sub(last_rotation_ms) < INCOMING_ROTATION_INTERVAL_MS {
                        crate::debug!(
                            "[NodeRuntime] Redirect incoming session from {}: rotation cooldown",
                            pid
                        );
                        send_discovery_redirect_and_close(
                            &router_for_incoming,
                            session.clone(),
                            &session_id,
                            &pid,
                            &our_peer_id_for_incoming,
                            incoming_catalog.as_ref(),
                            incoming_discovery_random_fraction,
                        )
                        .await;
                        continue;
                    }
                    let connected = session_manager.get_all_peers();
                    let mut to_drop = peers_to_drop_when_overloaded(
                        connected,
                        1,
                        incoming_catalog.as_ref(),
                        incoming_peer_store.as_ref(),
                        &incoming_weights,
                        incoming_node_role,
                    );
                    if let Some(victim) = to_drop.pop() {
                        incoming_catalog.observe_failure(&victim);
                        let _ = session_manager.close_all_sessions_for_peer(&victim).await;
                        last_rotation_ms = now;
                        crate::debug!(
                            "[NodeRuntime] Rotated peer {} to admit newcomer {}",
                            victim,
                            pid
                        );
                    } else {
                        crate::debug!(
                            "[NodeRuntime] Redirect incoming session from {}: no rotation candidate",
                            pid
                        );
                        send_discovery_redirect_and_close(
                            &router_for_incoming,
                            session.clone(),
                            &session_id,
                            &pid,
                            &our_peer_id_for_incoming,
                            incoming_catalog.as_ref(),
                            incoming_discovery_random_fraction,
                        )
                        .await;
                        continue;
                    }
                }
                session_manager.register(pid, session_id.clone(), session.clone());
            } else {
                session_manager.register_session(session_id.clone(), session.clone());
            }

            session
                .clone()
                .spawn_reader(incoming_packets_tx_for_sessions.clone());

            if session.peer_id().is_some() {
                let peer_id_str = session.peer_id().unwrap().to_string();
                let pid = PeerId::from(peer_id_str.as_str());

                // Admission jitter на bootstrap при всплеске входящих: размазывает
                // ack во времени, чтобы 100 newcomer'ов не стартовали синхронно.
                if matches!(incoming_node_role, NodeRole::BootstrapJoin) {
                    let connected_now_after = session_manager.distinct_peer_count();
                    if connected_now_after >= incoming_policy.target_active_peers {
                        let jitter_ms = rand::random::<u64>() % BOOTSTRAP_ADMISSION_JITTER_MAX_MS;
                        if jitter_ms > 0 {
                            tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
                        }
                    }
                }
                let ack_session_id = session_id.clone();
                let ack = Packet {
                    signature: None,
                    data: b"hs_ack".to_vec(),
                    nodes: vec![],
                    sender: our_peer_id_for_incoming.clone(),
                    receiver: peer_id_str.clone(),
                    max_hops: 1,
                    request_id: None,
                    chunk_stream_id: None,
                    chunk_index: None,
                    total_chunks: None,
                };
                if let Err(e) = router_for_incoming.send_to_session(ack_session_id, ack).await {
                    let msg = e.to_string();
                    if msg.contains("not found") {
                        crate::debug!(
                            "[NodeRuntime] handshake ack skipped (session already closed): {}",
                            msg
                        );
                    } else {
                        crate::error!(
                            "[NodeRuntime] Failed to send handshake ack to incoming session: {}",
                            e
                        );
                    }
                }

                // Proactive PeersResponse: bootstrap сразу отдаёт newcomer'у
                // top-N достижимых regular-дескрипторов. Это выключает hub-фазу
                // быстрее: peer начинает формировать mesh до следующего RequestPeers.
                if matches!(incoming_node_role, NodeRole::BootstrapJoin) {
                    let descriptors = select_peers_for_discovery_response(
                        incoming_catalog
                            .descriptors()
                            .into_iter()
                            .filter(|d| d.peer_id != peer_id_str)
                            .filter(|d| !d.capabilities.bootstrap_entry)
                            .filter(|d| descriptor_ok_for_discovery_redirect(d))
                            .collect(),
                        Some(&peer_id_str),
                        BOOTSTRAP_PROACTIVE_PEERS_LIMIT,
                        incoming_discovery_random_fraction.max(0.4),
                    );
                    if !descriptors.is_empty() {
                        let msg = NetworkControlPayload::PeersResponse { descriptors };
                        if let Ok(data) = msg.encode() {
                            let packet = Packet {
                                signature: None,
                                data,
                                nodes: vec![],
                                sender: our_peer_id_for_incoming.clone(),
                                receiver: peer_id_str.clone(),
                                max_hops: 2,
                                request_id: None,
                                chunk_stream_id: None,
                                chunk_index: None,
                                total_chunks: None,
                            };
                            let _ = router_for_incoming
                                .send_to_peer(pid, packet, None)
                                .await;
                        }
                    }
                }
            }
    }
    Err(anyhow::anyhow!(
        "incoming sessions channel closed; incoming loop stopped"
    ))
}
