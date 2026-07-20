use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::node::distribution::OVERLOAD_REDIRECT_DESCRIPTOR_LIMIT;

/// Сколько дескрипторов слать newcomer'у proactive сразу после handshake
/// (чтобы не ждать RequestPeers → быстрое переключение на mesh).
pub const BOOTSTRAP_PROACTIVE_PEERS_LIMIT: usize = 20;
/// Максимальный admission jitter при всплеске входящих.
pub const BOOTSTRAP_ADMISSION_JITTER_MAX_MS: u64 = 3_000;
/// Сколько менее загруженных соседей вкладывать в preamble при overload-редиректе.
pub const BOOTSTRAP_PEER_REDIRECT_PREAMBLE: usize = 3;
/// Для всех ролей ограничиваем входящие возле target (а не max), чтобы
/// не раздувать degree из-за лавины входящих дозвонов.
pub const REGULAR_INCOMING_HEADROOM: usize = 2;
/// Per-subnet inbound accepts/redirects per second before temporary refuse.
pub const INBOUND_SUBNET_RATE_PER_SEC: u32 = 32;

/// Least-loaded accepting peers for redirect preamble (role-agnostic).
pub fn less_loaded_bootstrap_descriptors(
    catalog: &PeerCatalog,
    our_peer_id: &str,
    our_active_connections: u16,
    exclude_peer_id: &str,
    recent_bootstrap_hints: &std::collections::HashMap<String, u32>,
    limit: usize,
) -> Vec<crate::topology::NodeDescriptor> {
    crate::node::seed_book::less_loaded_peer_descriptors(
        catalog,
        our_peer_id,
        our_active_connections,
        exclude_peer_id,
        recent_bootstrap_hints,
        limit,
    )
}
use crate::node::options::{NodeOptions, NodeRole, TopologyTuning};
use crate::packet::Packet;
use crate::peer_score::PeerConnectionPolicy;
use crate::peer_score::{PeerScoreStore, PeerScoreWeights};
use crate::protocol::control::NetworkControlPayload;
use crate::router::Router;
use crate::sessions::Session;
use crate::sessions::manager::SessionManager;
use crate::sessions::session::IncomingPacket;
use crate::topology::{
    AdmissionDecision, CapacityBudget, PeerCandidate, PeerCatalog, SmartMeshPlanner,
    TopologyPlanner, TopologySnapshot, descriptor_ok_for_discovery_redirect, now_ms,
    select_peers_for_discovery_response,
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
    let exclude_ids: std::collections::HashSet<String> =
        preamble.iter().map(|d| d.peer_id.clone()).collect();
    let remaining_limit = OVERLOAD_REDIRECT_DESCRIPTOR_LIMIT.saturating_sub(preamble.len());
    let mut descriptors: Vec<crate::topology::NodeDescriptor> = preamble;
    if remaining_limit > 0 {
        let extra = select_peers_for_discovery_response(
            catalog
                .descriptors()
                .into_iter()
                .filter(|d| d.peer_id != newcomer.as_str())
                .filter(|d| !exclude_ids.contains(&d.peer_id))
                .filter(descriptor_ok_for_discovery_redirect)
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
                protocol_id: None,
            };
            let _ = router.send_to_session(session_id.clone(), packet).await;
        }
    }
    let _ = router.teardown_session(session_id).await;
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_incoming_session_handler(
    cancel: tokio_util::sync::CancellationToken,
    incoming_sessions_rx: &mut tokio::sync::mpsc::Receiver<Arc<dyn Session>>,
    session_manager: Arc<SessionManager>,
    router_for_incoming: Arc<Router>,
    our_peer_id_for_incoming: String,
    policy_live_incoming: Arc<RwLock<PeerConnectionPolicy>>,
    incoming_catalog: Arc<PeerCatalog>,
    _incoming_peer_store: Arc<PeerScoreStore>,
    _incoming_weights: PeerScoreWeights,
    incoming_node_role: NodeRole,
    incoming_topology_tuning: TopologyTuning,
    incoming_discovery_random_fraction: f32,
    incoming_packets_tx_for_sessions: tokio::sync::mpsc::Sender<IncomingPacket>,
) -> anyhow::Result<()> {
    let mut recent_redirect_until: std::collections::HashMap<PeerId, u64> =
        std::collections::HashMap::new();
    let mut recent_bootstrap_hints: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    let mut fairness_window_started_ms = now_ms();
    let mut inbound_subnet_rates: std::collections::HashMap<
        (std::net::IpAddr, u8),
        crate::node::seed_book::InboundRateSlot,
    > = std::collections::HashMap::new();
    let mut global_accept_window_start_ms = now_ms();
    let mut global_accepts_in_window: u32 = 0;
    const GLOBAL_ACCEPTS_PER_SEC: u32 = 64;
    loop {
        let session = tokio::select! {
            _ = cancel.cancelled() => {
                // The sender has live clones in transports/bootstrap/topology,
                // so dropping one clone never closes the channel. Close the
                // receiver explicitly and drain buffered sessions so accepted
                // but unprocessed connections do not leak past shutdown.
                incoming_sessions_rx.close();
                while let Ok(buffered) = incoming_sessions_rx.try_recv() {
                    let _ = buffered.close().await;
                }
                return Ok(());
            }
            maybe = incoming_sessions_rx.recv() => match maybe {
                Some(session) => session,
                None => break,
            },
        };
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
                let now = now_ms();
                recent_redirect_until.insert(
                    pid.clone(),
                    now.saturating_add(incoming_topology_tuning.adaptive_redirect_memory_ms),
                );
                continue;
            }

            // Subnet + global accept budgets (DoS / flood softening).
            let now = now_ms();
            if let Some(remote) = session.remote_addr() {
                let key = crate::node::seed_book::inbound_subnet_key(remote);
                let slot = inbound_subnet_rates.entry(key).or_insert_with(|| {
                    crate::node::seed_book::InboundRateSlot {
                        window_start_ms: now,
                        count: 0,
                    }
                });
                if !slot.allow(now, INBOUND_SUBNET_RATE_PER_SEC) {
                    crate::debug!(
                        "[NodeRuntime] Reject inbound from {} (subnet rate limit)",
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
                    recent_redirect_until.insert(
                        pid.clone(),
                        now.saturating_add(incoming_topology_tuning.adaptive_redirect_memory_ms),
                    );
                    continue;
                }
            }
            if now.saturating_sub(global_accept_window_start_ms) >= 1_000 {
                global_accept_window_start_ms = now;
                global_accepts_in_window = 0;
            }

            let connected_now = session_manager.distinct_peer_count();
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
            // ponytail: minimal snapshot — evaluate_incoming only needs connected count, policy,
            // role, tuning, known_peer_count; other fields are zero-defaults
            let admission_snapshot = TopologySnapshot {
                our_peer_id: crate::types::PeerId::from(our_peer_id_for_incoming.as_str()),
                node_role: incoming_node_role,
                policy: incoming_policy.clone(),
                weights: crate::peer_score::PeerScoreWeights::default(),
                topology_tuning: incoming_topology_tuning.clone(),
                connected_peers: router_for_incoming.connected_peers(),
                connected_bootstrap_count: 0,
                known_peer_count: known_peers,
                peer_total_scores: std::collections::HashMap::new(),
                bootstrap_peer_ids: std::collections::HashSet::new(),
                descriptor_active_conns: std::collections::HashMap::new(),
                catalog_descriptors: Vec::new(),
                capacity: CapacityBudget::default(),
                dial_book: std::collections::HashMap::new(),
                dial_cooldowns: std::collections::HashMap::new(),
                peer_age_ms: std::collections::HashMap::new(),
                bootstrap_targets_count: 0,
                last_bootstrap_reseed_ms: 0,
                now_ms: now,
            };
            if let AdmissionDecision::Redirect { .. } = SmartMeshPlanner.evaluate_incoming(
                &admission_snapshot,
                &PeerCandidate {
                    peer_id: pid.clone(),
                    is_bootstrap_entry: false,
                },
            ) {
                let preamble = less_loaded_bootstrap_descriptors(
                    incoming_catalog.as_ref(),
                    &our_peer_id_for_incoming,
                    connected_now.min(u16::MAX as usize) as u16,
                    pid.as_str(),
                    &recent_bootstrap_hints,
                    BOOTSTRAP_PEER_REDIRECT_PREAMBLE,
                );
                crate::debug!(
                    "[NodeRuntime] Redirect incoming session from {}: planner limit",
                    pid
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
            if global_accepts_in_window >= GLOBAL_ACCEPTS_PER_SEC {
                crate::debug!(
                    "[NodeRuntime] Redirect incoming session from {}: global accept budget",
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
            global_accepts_in_window = global_accepts_in_window.saturating_add(1);
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

            // Admission jitter при всплеске входящих: размазывает
            // ack во времени, чтобы newcomers не стартовали синхронно.
            {
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
                protocol_id: None,
            };
            if let Err(e) = router_for_incoming
                .send_to_session(ack_session_id, ack)
                .await
            {
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

            // Proactive PeersResponse: сразу отдаём newcomer'у top-N достижимых
            // дескрипторов, чтобы mesh формировался до следующего RequestPeers.
            {
                let descriptors = select_peers_for_discovery_response(
                    incoming_catalog
                        .descriptors()
                        .into_iter()
                        .filter(|d| d.peer_id != peer_id_str)
                        .filter(descriptor_ok_for_discovery_redirect)
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
                            protocol_id: None,
                        };
                        let _ = router_for_incoming.send_to_peer(pid, packet, None).await;
                    }
                }
            }
        }
    }
    Err(anyhow::anyhow!(
        "incoming sessions channel closed; incoming loop stopped"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::crypto::NodeKeypair;
    use crate::packet_processor::PacketProcessor;
    use crate::peer_score::{PeerConnectionPolicy, PeerScoreStore, PeerScoreWeights};
    use crate::topology::{NodeCapabilities, NodeDescriptor, NodeDynamicStatus, sign_descriptor};

    #[derive(Debug)]
    struct RecordingSession {
        id: String,
        peer_id: Option<String>,
        sent: Mutex<Vec<Packet>>,
        closed: AtomicBool,
    }

    impl RecordingSession {
        fn new(id: &str, peer_id: Option<&str>) -> Arc<Self> {
            Arc::new(Self {
                id: id.to_string(),
                peer_id: peer_id.map(str::to_string),
                sent: Mutex::new(Vec::new()),
                closed: AtomicBool::new(false),
            })
        }

        fn was_closed(&self) -> bool {
            self.closed.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl Session for RecordingSession {
        fn id(&self) -> &str {
            &self.id
        }

        fn peer_id(&self) -> Option<&str> {
            self.peer_id.as_deref()
        }

        fn kind(&self) -> crate::sessions::LinkKind {
            crate::sessions::LinkKind::DirectTcp
        }

        async fn send(&self, packet: Packet) -> Result<u64> {
            let bytes = packet.wire_size_estimate();
            self.sent.lock().expect("sent lock").push(packet);
            Ok(bytes)
        }

        async fn send_wire(&self, encoded: Vec<u8>) -> Result<u64> {
            use crate::transport::tcp::codec::decode_packet;
            let packet = decode_packet(encoded)?;
            let bytes = packet.wire_size_estimate();
            self.sent.lock().expect("sent lock").push(packet);
            Ok(bytes)
        }

        async fn close(&self) -> Result<()> {
            self.closed.store(true, Ordering::Relaxed);
            Ok(())
        }

        fn spawn_reader(
            self: Arc<Self>,
            _incoming_packets_tx: tokio::sync::mpsc::Sender<IncomingPacket>,
        ) {
        }
    }

    struct NoopProcessor;

    #[async_trait]
    impl PacketProcessor for NoopProcessor {
        async fn process(
            &self,
            _incoming_packet: IncomingPacket,
            _router: Arc<Router>,
        ) -> crate::packet_processor::ProcessAction {
            crate::packet_processor::ProcessAction::Delivered
        }
    }

    fn signed_bootstrap_descriptor(active_connections: u16) -> NodeDescriptor {
        let keypair = NodeKeypair::generate();
        let mut desc = NodeDescriptor::new_unsigned(
            keypair.peer_id(),
            NodeCapabilities {
                bootstrap_entry: true,
                base_session_limit: 16,
                ..NodeCapabilities::default()
            },
            NodeDynamicStatus {
                active_connections,
                ..NodeDynamicStatus::default()
            },
            vec!["tcp:127.0.0.1:10000".to_string()],
            60,
            1,
        );
        sign_descriptor(&mut desc, keypair.signing_key()).expect("sign descriptor");
        desc
    }

    #[test]
    fn overload_redirect_preamble_prefers_less_loaded_bootstrap_peers_and_tracks_hint_fairness() {
        let catalog = PeerCatalog::new();
        let high_hint = signed_bootstrap_descriptor(1);
        let low_load = signed_bootstrap_descriptor(2);
        let higher_load = signed_bootstrap_descriptor(4);
        catalog
            .upsert_descriptor(high_hint.clone())
            .expect("upsert high_hint");
        catalog
            .upsert_descriptor(low_load.clone())
            .expect("upsert low_load");
        catalog
            .upsert_descriptor(higher_load.clone())
            .expect("upsert higher_load");
        let recent_hints = std::collections::HashMap::from([(high_hint.peer_id.clone(), 10_u32)]);

        let selected = less_loaded_bootstrap_descriptors(
            &catalog,
            "our-peer",
            8,
            "newcomer",
            &recent_hints,
            2,
        );

        let selected_ids: Vec<_> = selected.iter().map(|d| d.peer_id.as_str()).collect();
        assert_eq!(
            selected_ids,
            vec![low_load.peer_id.as_str(), higher_load.peer_id.as_str()]
        );
    }

    #[tokio::test]
    async fn incoming_regular_admission_redirects_new_peer_at_hard_limit() {
        let local_key = NodeKeypair::generate();
        let local_peer_id = local_key.peer_id().to_string();
        let peer_1 = NodeKeypair::generate().peer_id().to_string();
        let peer_2 = NodeKeypair::generate().peer_id().to_string();
        let peer_3 = NodeKeypair::generate().peer_id().to_string();
        let score_store = Arc::new(PeerScoreStore::new());
        let weights = PeerScoreWeights::default();
        let session_manager = Arc::new(SessionManager::new(score_store.clone(), weights.clone()));
        let (router, _router_rx) = Router::new(
            session_manager.clone(),
            Arc::new(NoopProcessor),
            Some(Arc::new(local_key.signing_key().clone())),
            local_peer_id.clone(),
            None,
        );
        let router = Arc::new(router);
        let catalog = Arc::new(PeerCatalog::new());
        let policy = Arc::new(RwLock::new(PeerConnectionPolicy {
            min_active_peers: 1,
            target_active_peers: 1,
            max_active_peers: 2,
        }));
        let (incoming_tx, mut incoming_rx) = tokio::sync::mpsc::channel(4);
        let (packet_tx, _packet_rx) = tokio::sync::mpsc::channel(4);

        let handler = tokio::spawn({
            let session_manager = session_manager.clone();
            let router = router.clone();
            let policy = policy.clone();
            let catalog = catalog.clone();
            let score_store = score_store.clone();
            async move {
                run_incoming_session_handler(
                    tokio_util::sync::CancellationToken::new(),
                    &mut incoming_rx,
                    session_manager,
                    router,
                    local_peer_id,
                    policy,
                    catalog,
                    score_store,
                    weights,
                    NodeRole::Regular,
                    TopologyTuning::default(),
                    0.0,
                    packet_tx,
                )
                .await
            }
        });

        let s1 = RecordingSession::new("sess-1", Some(&peer_1));
        let s2 = RecordingSession::new("sess-2", Some(&peer_2));
        let s3 = RecordingSession::new("sess-3", Some(&peer_3));
        incoming_tx
            .send(s1.clone() as Arc<dyn Session>)
            .await
            .expect("send s1");
        incoming_tx
            .send(s2.clone() as Arc<dyn Session>)
            .await
            .expect("send s2");
        incoming_tx
            .send(s3.clone() as Arc<dyn Session>)
            .await
            .expect("send s3");
        drop(incoming_tx);

        let result = handler.await.expect("handler join");
        assert!(result.is_err());
        assert_eq!(session_manager.distinct_peer_count(), 2);
        assert!(session_manager.is_connected_to_peer(&PeerId::from(peer_1.as_str())));
        assert!(session_manager.is_connected_to_peer(&PeerId::from(peer_2.as_str())));
        assert!(!session_manager.is_connected_to_peer(&PeerId::from(peer_3.as_str())));
        assert!(!s1.was_closed());
        assert!(!s2.was_closed());
        assert!(s3.was_closed());
    }
}
