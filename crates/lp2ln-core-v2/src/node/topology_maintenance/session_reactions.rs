use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use dashmap::DashMap;

use crate::event_core::prelude::{CoreEvent, CoreEventHandler, EventContext, SessionEvent};
use crate::sessions::LinkKind;
use crate::sessions::manager::SessionManager;
use crate::topology::now_ms;
use crate::types::PeerId;

/// Peers queued for redial after session-close reactions (consumed by topology loop).
#[derive(Default)]
pub struct SessionRedialQueue {
    pending: DashMap<PeerId, u64>,
}

impl SessionRedialQueue {
    pub fn new() -> Self {
        Self {
            pending: DashMap::new(),
        }
    }

    pub fn schedule(&self, peer_id: PeerId, not_before_ms: u64) {
        self.pending
            .entry(peer_id)
            .and_modify(|ts| *ts = (*ts).min(not_before_ms))
            .or_insert(not_before_ms);
    }

    pub fn drain_ready(&self, now: u64) -> Vec<PeerId> {
        let mut ready = Vec::new();
        self.pending.retain(|peer_id, not_before| {
            if *not_before <= now {
                ready.push(peer_id.clone());
                false
            } else {
                true
            }
        });
        ready
    }
}

pub struct TopologySessionReactionHandler {
    session_manager: Arc<SessionManager>,
    queue: Arc<SessionRedialQueue>,
    redial_cooldown_ms: u64,
}

impl TopologySessionReactionHandler {
    pub fn new(
        session_manager: Arc<SessionManager>,
        queue: Arc<SessionRedialQueue>,
        redial_cooldown_ms: u64,
    ) -> Self {
        Self {
            session_manager,
            queue,
            redial_cooldown_ms,
        }
    }
}

#[async_trait]
impl CoreEventHandler for TopologySessionReactionHandler {
    async fn handle_event(&self, event: CoreEvent, _ctx: EventContext) -> Result<()> {
        let CoreEvent::Session(SessionEvent::Closed {
            peer_id: Some(peer_id),
            ..
        }) = event
        else {
            return Ok(());
        };

        if self.session_manager.is_connected_to_peer(&peer_id) {
            return Ok(());
        }
        if self
            .session_manager
            .peer_has_link_kind(&peer_id, LinkKind::DirectTcp)
        {
            return Ok(());
        }

        let now = now_ms();
        self.queue
            .schedule(peer_id, now.saturating_add(self.redial_cooldown_ms));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use anyhow::Result;
    use async_trait::async_trait;

    use super::*;
    use crate::event_core::prelude::{CoreBus, CoreEventKind};
    use crate::peer_score::{PeerScoreStore, PeerScoreWeights};
    use crate::sessions::{IncomingPacket, Session};
    use crate::types::{PeerId, SessionId};

    #[derive(Debug)]
    struct TestSession {
        id: String,
        peer_id: Option<String>,
        kind: LinkKind,
        closed: AtomicBool,
        sent: Mutex<Vec<crate::packet::Packet>>,
    }

    impl TestSession {
        fn new(id: &str, peer_id: Option<&str>, kind: LinkKind) -> Arc<Self> {
            Arc::new(Self {
                id: id.to_string(),
                peer_id: peer_id.map(str::to_string),
                kind,
                closed: AtomicBool::new(false),
                sent: Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait]
    impl Session for TestSession {
        fn id(&self) -> &str {
            &self.id
        }

        fn peer_id(&self) -> Option<&str> {
            self.peer_id.as_deref()
        }

        fn kind(&self) -> LinkKind {
            self.kind
        }

        async fn send(&self, packet: crate::packet::Packet) -> Result<u64> {
            let bytes = packet.wire_size_estimate() as u64;
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

    fn manager_with_bus() -> (Arc<SessionManager>, CoreBus) {
        let bus = CoreBus::new(16);
        let manager = Arc::new(
            SessionManager::new(Arc::new(PeerScoreStore::new()), PeerScoreWeights::default())
                .with_event_bus(bus.clone()),
        );
        (manager, bus)
    }

    #[test]
    fn session_redial_queue_drains_ready_peers() {
        let queue = SessionRedialQueue::new();
        queue.schedule(PeerId::from("peer-a"), 100);
        queue.schedule(PeerId::from("peer-b"), 500);

        assert!(queue.drain_ready(99).is_empty());
        let ready = queue.drain_ready(100);
        assert_eq!(ready, vec![PeerId::from("peer-a")]);
        assert!(queue.drain_ready(499).is_empty());
        assert_eq!(queue.drain_ready(500), vec![PeerId::from("peer-b")]);
    }

    #[test]
    fn session_redial_queue_schedule_keeps_earliest_deadline() {
        let queue = SessionRedialQueue::new();
        queue.schedule(PeerId::from("peer-a"), 500);
        queue.schedule(PeerId::from("peer-a"), 200);

        assert_eq!(queue.drain_ready(200), vec![PeerId::from("peer-a")]);
    }

    #[tokio::test]
    async fn topology_handler_schedules_redial_on_relay_close() {
        let queue = Arc::new(SessionRedialQueue::new());
        let manager = Arc::new(SessionManager::new(
            Arc::new(PeerScoreStore::new()),
            PeerScoreWeights::default(),
        ));
        let handler = TopologySessionReactionHandler::new(manager.clone(), queue.clone(), 1_000);

        manager.register(
            PeerId::from("peer-relay"),
            SessionId::from("sess-relay"),
            TestSession::new("sess-relay", Some("peer-relay"), LinkKind::Relay),
        );
        manager
            .close_session(&SessionId::from("sess-relay"))
            .await
            .expect("close relay session");

        let bus = CoreBus::new(8);
        bus.register_event_handler(CoreEventKind::Session, Arc::new(handler));
        let before = now_ms();
        bus.emit(CoreEvent::Session(SessionEvent::Closed {
            session_id: SessionId::from("sess-relay"),
            peer_id: Some(PeerId::from("peer-relay")),
            reason: None,
        }))
        .await
        .expect("emit session closed");

        assert!(queue.drain_ready(before).is_empty());
        assert_eq!(
            queue.drain_ready(before.saturating_add(1_000)),
            vec![PeerId::from("peer-relay")]
        );
    }

    #[tokio::test]
    async fn topology_handler_skips_when_direct_tcp_exists() {
        let queue = Arc::new(SessionRedialQueue::new());
        let manager = Arc::new(SessionManager::new(
            Arc::new(PeerScoreStore::new()),
            PeerScoreWeights::default(),
        ));
        let handler = TopologySessionReactionHandler::new(manager.clone(), queue.clone(), 1_000);

        manager.register(
            PeerId::from("peer-a"),
            SessionId::from("sess-tcp"),
            TestSession::new("sess-tcp", Some("peer-a"), LinkKind::DirectTcp),
        );

        let bus = CoreBus::new(8);
        bus.register_event_handler(CoreEventKind::Session, Arc::new(handler));
        bus.emit(CoreEvent::Session(SessionEvent::Closed {
            session_id: SessionId::from("sess-other"),
            peer_id: Some(PeerId::from("peer-a")),
            reason: None,
        }))
        .await
        .expect("emit closed");

        assert!(queue.drain_ready(u64::MAX).is_empty());
    }

    #[tokio::test]
    async fn topology_handler_skips_when_still_connected() {
        let queue = Arc::new(SessionRedialQueue::new());
        let manager = Arc::new(SessionManager::new(
            Arc::new(PeerScoreStore::new()),
            PeerScoreWeights::default(),
        ));
        let handler = TopologySessionReactionHandler::new(manager.clone(), queue.clone(), 1_000);

        manager.register(
            PeerId::from("peer-a"),
            SessionId::from("sess-relay"),
            TestSession::new("sess-relay", Some("peer-a"), LinkKind::Relay),
        );
        manager.register(
            PeerId::from("peer-a"),
            SessionId::from("sess-tcp"),
            TestSession::new("sess-tcp", Some("peer-a"), LinkKind::DirectTcp),
        );

        let bus = CoreBus::new(8);
        bus.register_event_handler(CoreEventKind::Session, Arc::new(handler));
        bus.emit(CoreEvent::Session(SessionEvent::Closed {
            session_id: SessionId::from("sess-relay"),
            peer_id: Some(PeerId::from("peer-a")),
            reason: None,
        }))
        .await
        .expect("emit closed");

        assert!(queue.drain_ready(u64::MAX).is_empty());
    }

    #[tokio::test]
    async fn session_manager_close_emits_closed_event_on_bus() {
        let (manager, bus) = manager_with_bus();
        let mut observer = bus.subscribe_events();
        manager.register(
            PeerId::from("peer-a"),
            SessionId::from("sess-1"),
            TestSession::new("sess-1", Some("peer-a"), LinkKind::Relay),
        );
        manager
            .close_session(&SessionId::from("sess-1"))
            .await
            .expect("close");

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        let mut saw_closed = false;
        while tokio::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let Ok(Ok(event)) = tokio::time::timeout(remaining, observer.recv()).await else {
                break;
            };
            if matches!(
                event,
                CoreEvent::Session(SessionEvent::Closed {
                    session_id,
                    peer_id: Some(peer),
                    ..
                }) if session_id.as_str() == "sess-1" && peer.as_str() == "peer-a"
            ) {
                saw_closed = true;
                break;
            }
        }
        assert!(saw_closed, "expected SessionEvent::Closed on bus");
    }
}
