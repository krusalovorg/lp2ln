use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;

use lp2ln_core_v2::{
    PeerId, SessionId,
    node::{
        NodeRole,
        direct_upgrade::{DirectUpgradeEvent, DirectUpgradeRouterSink},
        distribution::should_skip_for_bootstrap_quota,
        nat_traversal::{NatSessionStage, NatTraversalState},
    },
    packet::Packet,
    packet_processor::{PacketProcessor, ProcessAction},
    peer_score::{PeerConnectionPolicy, PeerScoreStore, PeerScoreWeights},
    protocol::control::{NatCandidate, NatCandidateKind, NetworkControlPayload},
    router::{Router, RouterRunOutcome},
    sessions::{IncomingPacket, LinkKind, Session, manager::SessionManager},
    topology::{NodeCapabilities, NodeDescriptor, NodeDynamicStatus},
};

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

    fn sent_len(&self) -> usize {
        self.sent.lock().expect("sent lock").len()
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

    fn kind(&self) -> LinkKind {
        LinkKind::DirectTcp
    }

    async fn send(&self, packet: Packet) -> Result<u64> {
        let bytes = packet.wire_size_estimate();
        self.sent.lock().expect("sent lock").push(packet);
        Ok(bytes)
    }

    async fn send_wire(&self, encoded: Vec<u8>) -> Result<u64> {
        use lp2ln_core_v2::transport::tcp::codec::decode_packet;
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
    ) -> ProcessAction {
        ProcessAction::Delivered
    }
}

struct CountingProcessor {
    count: Arc<AtomicUsize>,
}

#[async_trait]
impl PacketProcessor for CountingProcessor {
    async fn process(
        &self,
        _incoming_packet: IncomingPacket,
        _router: Arc<Router>,
    ) -> ProcessAction {
        self.count.fetch_add(1, Ordering::Relaxed);
        ProcessAction::Delivered
    }
}

fn test_router_with_sink(sink: Option<DirectUpgradeRouterSink>) -> (Router, Arc<SessionManager>) {
    let store = Arc::new(PeerScoreStore::new());
    let manager = Arc::new(SessionManager::new(store, PeerScoreWeights::default()));
    let (router, _rx) = Router::new(
        manager.clone(),
        Arc::new(NoopProcessor),
        None,
        "router-self",
        sink,
    );
    (router, manager)
}

fn test_router() -> (Router, Arc<SessionManager>) {
    test_router_with_sink(None)
}

fn packet(data: Vec<u8>) -> Packet {
    Packet {
        signature: None,
        data,
        nodes: Vec::new(),
        sender: "sender".to_string(),
        receiver: String::new(),
        max_hops: 8,
        request_id: None,
        chunk_stream_id: None,
        chunk_index: None,
        total_chunks: None,
        protocol_id: None,
    }
}

#[test]
fn nat_state_answer_schedules_single_punch_job_and_result_metrics() {
    let state = NatTraversalState::new();
    let local = vec![NatCandidate {
        protocol: "udp".to_string(),
        addr: "10.0.0.2:8081".to_string(),
        kind: NatCandidateKind::Host,
        priority: 100,
    }];
    let remote = vec![NatCandidate {
        protocol: "udp".to_string(),
        addr: "203.0.113.10:4081".to_string(),
        kind: NatCandidateKind::Srflx,
        priority: 300,
    }];

    let offer = state.create_offer("nat-a".to_string(), "peer-b".to_string(), local);
    assert_eq!(state.metrics(), (1, 0, 0));
    assert_eq!(
        state.session("nat-a").expect("created").stage,
        NatSessionStage::OfferCreated
    );

    let answer = lp2ln_core_v2::protocol::control::NatAnswerPayload {
        session_id: offer.session_id,
        candidates: remote,
    };
    assert_eq!(state.handle_answer("peer-b", &answer), Some(250));

    let scheduled = state.session("nat-a").expect("scheduled");
    assert_eq!(scheduled.peer_id, "peer-b");
    assert_eq!(scheduled.stage, NatSessionStage::PunchScheduled);
    assert_eq!(scheduled.start_after_ms, Some(250));

    let jobs = state.take_punch_jobs();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].stage, NatSessionStage::Punching);
    assert!(state.take_punch_jobs().is_empty());

    state.mark_result("nat-a", false, None, Some("timeout".to_string()));
    let failed = state.session("nat-a").expect("failed");
    assert_eq!(failed.stage, NatSessionStage::Failed);
    assert_eq!(failed.failure_reason.as_deref(), Some("timeout"));
    assert_eq!(state.metrics(), (1, 0, 1));
}

#[test]
fn nat_state_ignores_answer_for_unknown_session() {
    let state = NatTraversalState::new();
    let answer = lp2ln_core_v2::protocol::control::NatAnswerPayload {
        session_id: "missing".to_string(),
        candidates: Vec::new(),
    };

    assert_eq!(state.handle_answer("peer-b", &answer), None);
    assert_eq!(state.sessions_len(), 0);
    assert_eq!(state.metrics(), (0, 0, 0));
}

#[tokio::test]
async fn router_prefers_direct_session_over_fallback_neighbors() {
    let (router, _manager) = test_router();
    let target = RecordingSession::new("sess-target", Some("peer-target"));
    let n1 = RecordingSession::new("sess-n1", Some("neighbor-1"));
    let n2 = RecordingSession::new("sess-n2", Some("neighbor-2"));
    router.register_session(
        PeerId::from("peer-target"),
        SessionId::from("sess-target"),
        target.clone(),
    );
    router.register_session(
        PeerId::from("neighbor-1"),
        SessionId::from("sess-n1"),
        n1.clone(),
    );
    router.register_session(
        PeerId::from("neighbor-2"),
        SessionId::from("sess-n2"),
        n2.clone(),
    );

    let request_id = router
        .send_to_peer(
            PeerId::from("peer-target"),
            packet(b"payload".to_vec()),
            None,
        )
        .await
        .expect("direct send");

    assert!(request_id > 0);
    assert_eq!(target.sent_len(), 1);
    assert_eq!(n1.sent_len(), 0);
    assert_eq!(n2.sent_len(), 0);
}

#[tokio::test]
async fn router_fallback_fans_out_to_neighbors_but_skips_excluded_and_path_peers() {
    let (router, _manager) = test_router();
    let mut sessions = Vec::new();
    for i in 0..5 {
        let peer = format!("neighbor-{i}");
        let sess = RecordingSession::new(&format!("sess-{i}"), Some(&peer));
        router.register_session(
            PeerId::from(peer.as_str()),
            SessionId::from(sess.id()),
            sess.clone(),
        );
        sessions.push((peer, sess));
    }

    let mut routed = packet(b"payload".to_vec());
    routed.nodes.push("neighbor-2".to_string());
    router
        .send_to_peer(
            PeerId::from("missing-target"),
            routed,
            Some(PeerId::from("neighbor-1")),
        )
        .await
        .expect("fallback send");

    let total_sent: usize = sessions.iter().map(|(_, s)| s.sent_len()).sum();
    assert_eq!(total_sent, 1, "fallback sends to one eligible neighbor");
    assert_eq!(sessions[1].1.sent_len(), 0, "exclude_from peer was flooded");
    assert_eq!(sessions[2].1.sent_len(), 0, "path peer was flooded");
}

#[tokio::test]
async fn router_fallback_sends_to_first_eligible_neighbor() {
    let (router, _manager) = test_router();
    let mut sessions = Vec::new();
    for i in 0..6 {
        let peer = format!("neighbor-{i}");
        let sess = RecordingSession::new(&format!("sess-{i}"), Some(&peer));
        router.register_session(
            PeerId::from(peer.as_str()),
            SessionId::from(sess.id()),
            sess.clone(),
        );
        sessions.push(sess);
    }

    router
        .send_to_peer(
            PeerId::from("missing-target"),
            packet(b"payload".to_vec()),
            None,
        )
        .await
        .expect("fallback send");

    let total_sent: usize = sessions.iter().map(|s| s.sent_len()).sum();
    assert_eq!(total_sent, 1, "one wire frame per fallback send");
}

#[tokio::test]
async fn router_does_not_flood_control_packets_without_direct_session() {
    let (router, _manager) = test_router();
    let n1 = RecordingSession::new("sess-n1", Some("neighbor-1"));
    let n2 = RecordingSession::new("sess-n2", Some("neighbor-2"));
    router.register_session(
        PeerId::from("neighbor-1"),
        SessionId::from("sess-n1"),
        n1.clone(),
    );
    router.register_session(
        PeerId::from("neighbor-2"),
        SessionId::from("sess-n2"),
        n2.clone(),
    );
    let data = NetworkControlPayload::RequestPeers { limit: 8 }
        .encode()
        .expect("control encode");

    let err = router
        .send_to_peer(PeerId::from("missing-target"), packet(data), None)
        .await
        .expect_err("control packets require direct session");

    assert!(
        err.to_string()
            .contains("No direct session for control packet")
    );
    assert_eq!(n1.sent_len(), 0);
    assert_eq!(n2.sent_len(), 0);
}

#[tokio::test]
async fn router_fallback_emits_direct_upgrade_event() {
    let (tx, mut rx) = mpsc::channel(16);
    let sink = Some(DirectUpgradeRouterSink { enabled: true, tx });
    let (router, _mgr) = test_router_with_sink(sink);
    let n1 = RecordingSession::new("sess-n1", Some("neighbor-1"));
    let n2 = RecordingSession::new("sess-n2", Some("neighbor-2"));
    router.register_session(
        PeerId::from("neighbor-1"),
        SessionId::from("sess-n1"),
        n1.clone(),
    );
    router.register_session(
        PeerId::from("neighbor-2"),
        SessionId::from("sess-n2"),
        n2.clone(),
    );

    router
        .send_to_peer(PeerId::from("missing-target"), packet(b"x".to_vec()), None)
        .await
        .expect("fallback send");

    let ev = rx.recv().await.expect("upgrade event");
    match ev {
        DirectUpgradeEvent::FallbackTraffic { peer_id, bytes } => {
            assert_eq!(peer_id.as_str(), "missing-target");
            assert!(bytes > 0);
        }
    }
}

#[tokio::test]
async fn router_fallback_continues_when_direct_upgrade_queue_full() {
    let (tx, mut rx) = mpsc::channel(1);
    let sink = Some(DirectUpgradeRouterSink { enabled: true, tx });
    let (router, _mgr) = test_router_with_sink(sink);
    let mut sessions = Vec::new();
    for i in 0..3 {
        let peer = format!("neighbor-{i}");
        let sess = RecordingSession::new(&format!("sess-{i}"), Some(&peer));
        router.register_session(
            PeerId::from(peer.as_str()),
            SessionId::from(sess.id()),
            sess.clone(),
        );
        sessions.push(sess);
    }

    router
        .send_to_peer(PeerId::from("missing-target"), packet(b"a".to_vec()), None)
        .await
        .expect("first fallback send");
    router
        .send_to_peer(PeerId::from("missing-target"), packet(b"b".to_vec()), None)
        .await
        .expect("second fallback when upgrade queue saturated");

    assert!(
        router.direct_upgrade_queue_drops() >= 1,
        "second event should overflow capacity-1 queue"
    );
    let _ = rx.recv().await;
    let total_sent: usize = sessions.iter().map(|s| s.sent_len()).sum();
    assert!(total_sent >= 2);
}

fn descriptor(peer_id: &str, bootstrap_entry: bool, active_connections: u16) -> NodeDescriptor {
    NodeDescriptor::new_unsigned(
        peer_id,
        NodeCapabilities {
            bootstrap_entry,
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
    )
}

#[tokio::test]
async fn router_drains_buffered_packets_on_cancel() {
    // Regression for the shutdown packet-loss bug: when the router is
    // cancelled it must drain whatever is already buffered in the ingress
    // queue instead of dropping it.
    let store = Arc::new(PeerScoreStore::new());
    let manager = Arc::new(SessionManager::new(store, PeerScoreWeights::default()));
    let count = Arc::new(AtomicUsize::new(0));
    let (router, mut rx) = Router::new(
        manager.clone(),
        Arc::new(CountingProcessor {
            count: count.clone(),
        }),
        None,
        "router-self",
        None,
    );
    let router = Arc::new(router);

    const N: usize = 1000;
    let sender = router.incoming_sender();
    for i in 0..N {
        sender
            .send(IncomingPacket {
                session_id: format!("sess-{i}"),
                from_node: Some("peer".to_string()),
                packet: packet(vec![1, 2, 3]),
            })
            .await
            .expect("buffer packet");
    }

    // Request shutdown before run starts: the cancel branch must drain.
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();

    let outcome = router.clone().run(&mut rx, cancel).await;
    assert_eq!(outcome, RouterRunOutcome::Cancelled);

    // Let the per-packet processing tasks spawned during the drain finish.
    router
        .shutdown_packet_tasks(std::time::Duration::from_secs(3))
        .await;

    assert_eq!(
        count.load(Ordering::Relaxed),
        N,
        "router dropped buffered packets on shutdown"
    );
}

#[test]
fn distribution_bootstrap_quota_skips_extra_bootstrap_after_regular_has_mesh_peers() {
    let regular_policy = PeerConnectionPolicy {
        min_active_peers: 2,
        target_active_peers: 4,
        max_active_peers: 8,
    };

    assert!(should_skip_for_bootstrap_quota(
        true,
        NodeRole::Regular,
        1,
        2,
        2,
        regular_policy.min_active_peers,
    ));
    assert!(!should_skip_for_bootstrap_quota(
        true,
        NodeRole::BootstrapJoin,
        100,
        1,
        100,
        regular_policy.min_active_peers,
    ));
}
