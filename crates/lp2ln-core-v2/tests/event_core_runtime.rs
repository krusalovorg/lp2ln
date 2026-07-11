use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use lp2ln_core_v2::event_core::prelude::{
    CoreBus, CoreEvent, CoreEventKind, LifecycleEvent, ServiceDescriptor, ServiceKind,
    ServiceStatus, SessionEvent, TransportEvent,
};
use lp2ln_core_v2::node::{NodeBuilder, NodeLifecycleState, NodeOptions, NodeRuntime, RuntimeMode};
use lp2ln_core_v2::sessions::{LinkKind, Session};
use lp2ln_core_v2::transport::tcp::TcpTransport;
use lp2ln_core_v2::types::{PeerId, SessionId};
use std::sync::atomic::{AtomicBool, Ordering};

fn test_options() -> NodeOptions {
    let mut options = NodeOptions::empty();
    options.enable_topology_maintenance = false;
    options.with_listen("tcp", "127.0.0.1:0".parse().expect("addr"))
}

fn build_node(mut options: NodeOptions) -> NodeRuntime {
    if !options.listens.contains_key("tcp") {
        options = options.with_listen("tcp", "127.0.0.1:0".parse().expect("addr"));
    }
    NodeBuilder::new()
        .add_transport(Arc::new(TcpTransport::new()) as Arc<dyn lp2ln_core_v2::transport::Transport>)
        .build(options)
        .expect("build")
}

#[derive(Debug)]
struct RelayTestSession {
    id: String,
    peer_id: String,
    closed: AtomicBool,
}

impl RelayTestSession {
    fn new(id: &str, peer_id: &str) -> Arc<Self> {
        Arc::new(Self {
            id: id.to_string(),
            peer_id: peer_id.to_string(),
            closed: AtomicBool::new(false),
        })
    }
}

#[async_trait]
impl Session for RelayTestSession {
    fn id(&self) -> &str {
        &self.id
    }

    fn peer_id(&self) -> Option<&str> {
        Some(&self.peer_id)
    }

    fn kind(&self) -> LinkKind {
        LinkKind::Relay
    }

    async fn send(&self, packet: lp2ln_core_v2::packet::Packet) -> Result<u64> {
        Ok(packet.wire_size_estimate() as u64)
    }

    async fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn spawn_reader(
        self: Arc<Self>,
        _incoming_packets_tx: tokio::sync::mpsc::Sender<lp2ln_core_v2::sessions::IncomingPacket>,
    ) {
    }
}

async fn collect_events_until(
    observer: &mut tokio::sync::broadcast::Receiver<CoreEvent>,
    timeout: Duration,
    mut done: impl FnMut(&CoreEvent) -> bool,
) -> Vec<CoreEvent> {
    let mut collected = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Ok(Ok(event)) = tokio::time::timeout(remaining, observer.recv()).await else {
            break;
        };
        let finished = done(&event);
        collected.push(event);
        if finished {
            break;
        }
    }
    collected
}

#[tokio::test]
async fn node_runtime_owns_core_bus_and_emits_lifecycle() {
    let mut node = build_node(test_options());
    let bus = node.core_bus();
    let mut observer = bus.subscribe_events();
    node.start().await.expect("start");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut saw_ready = false;
    while let Ok(Ok(event)) =
        tokio::time::timeout(Duration::from_millis(200), observer.recv()).await
    {
        if let CoreEvent::Lifecycle(le) = event {
            if le.status == ServiceStatus::Ready {
                saw_ready = true;
                break;
            }
        }
    }
    assert!(saw_ready, "expected lifecycle Ready event on bus");
    assert_eq!(node.lifecycle_state(), NodeLifecycleState::Running);
    node.stop().await.expect("stop");
    assert_eq!(node.lifecycle_state(), NodeLifecycleState::Stopped);
    assert!(bus.stats().emitted_events >= 2);
}

#[tokio::test]
async fn core_bus_stats_track_observer_lag() {
    let bus = CoreBus::new(4);
    let mut observer = bus.subscribe_events();
    let event = CoreEvent::Lifecycle(LifecycleEvent {
        service: ServiceDescriptor::new("test", ServiceKind::Runtime),
        status: ServiceStatus::Ready,
        generation: 1,
        reason: None,
    });
    for _ in 0..8 {
        let _ = bus.emit(event.clone()).await;
    }
    let _ = observer.recv().await;
    let stats = bus.stats();
    assert!(stats.emitted_events >= 8);
    assert!(stats.broadcast_observer_deliveries >= 1);
}

#[tokio::test]
async fn startup_registers_health_bridge_handlers() {
    let mut node = build_node(test_options());
    let bus = node.core_bus();
    assert_eq!(bus.event_handler_count(CoreEventKind::Lifecycle), 0);
    assert_eq!(bus.event_handler_count(CoreEventKind::Transport), 0);

    node.start().await.expect("start");

    assert!(
        bus.event_handler_count(CoreEventKind::Lifecycle) >= 1,
        "expected lifecycle health bridge handler"
    );
    assert!(
        bus.event_handler_count(CoreEventKind::Transport) >= 1,
        "expected transport health bridge handler"
    );
    assert_eq!(
        bus.event_handler_count(CoreEventKind::Session),
        0,
        "session handler should stay disabled by default"
    );

    node.stop().await.expect("stop");
}

#[tokio::test]
async fn startup_registers_session_handler_when_topology_react_enabled() {
    let mut options = test_options();
    options.topology_react_to_session_events = true;
    let mut node = build_node(options);
    let bus = node.core_bus();

    node.start().await.expect("start");

    assert_eq!(
        bus.event_handler_count(CoreEventKind::Session),
        1,
        "topology session reaction handler should register on startup"
    );

    node.stop().await.expect("stop");
}

#[tokio::test]
async fn runtime_emits_transport_events_on_start() {
    let mut node = build_node(test_options());
    let bus = node.core_bus();
    let mut observer = bus.subscribe_events();

    node.start().await.expect("start");
    let events = collect_events_until(&mut observer, Duration::from_millis(500), |event| {
        matches!(event, CoreEvent::Transport(TransportEvent::Ready(_)))
    })
    .await;

    let kinds: HashSet<_> = events
        .iter()
        .filter_map(|event| match event {
            CoreEvent::Transport(te) => Some(std::mem::discriminant(te)),
            _ => None,
        })
        .collect();
    assert!(
        kinds.len() >= 2,
        "expected multiple transport lifecycle events, got: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, CoreEvent::Transport(TransportEvent::Ready(_)))),
        "expected transport Ready event"
    );

    node.stop().await.expect("stop");
}

#[tokio::test]
async fn session_close_emits_closed_event_through_runtime_bus() {
    let mut node = build_node(test_options());
    let bus = node.core_bus();
    let mut observer = bus.subscribe_events();
    node.start().await.expect("start");

    let router = node.router().expect("router after start");
    router.register_session(
        PeerId::from("peer-a"),
        SessionId::from("sess-relay"),
        RelayTestSession::new("sess-relay", "peer-a"),
    );
    router
        .teardown_session(&SessionId::from("sess-relay"))
        .await
        .expect("close session");

    let events = collect_events_until(&mut observer, Duration::from_secs(1), |event| {
        matches!(
            event,
            CoreEvent::Session(SessionEvent::Closed {
                session_id,
                ..
            }) if session_id.as_str() == "sess-relay"
        )
    })
    .await;

    assert!(
        events.iter().any(|event| matches!(
            event,
            CoreEvent::Session(SessionEvent::Closed {
                session_id,
                peer_id: Some(peer),
                ..
            }) if session_id.as_str() == "sess-relay" && peer.as_str() == "peer-a"
        )),
        "expected SessionEvent::Closed on runtime bus, got: {events:?}"
    );
    assert_eq!(node.active_peer_count(), 0);

    node.stop().await.expect("stop");
}

#[tokio::test]
async fn health_bridge_reflects_lifecycle_and_transport_degraded() {
    let mut node = build_node(test_options());
    let bus = node.core_bus();
    node.start().await.expect("start");
    assert!(!node.is_degraded());

    bus.emit(CoreEvent::Lifecycle(LifecycleEvent {
        service: ServiceDescriptor::new("topology", ServiceKind::Topology),
        status: ServiceStatus::Degraded,
        generation: 1,
        reason: Some("test degradation".to_string()),
    }))
    .await
    .expect("emit lifecycle degraded");
    assert!(node.is_degraded());
    assert_eq!(node.health_snapshot().mode, RuntimeMode::Degraded);
    assert!(
        node.health_snapshot()
            .last_error
            .as_deref()
            .is_some_and(|msg| msg.contains("topology") && msg.contains("test degradation"))
    );

    bus.emit(CoreEvent::Lifecycle(LifecycleEvent {
        service: ServiceDescriptor::new("runtime", ServiceKind::Runtime),
        status: ServiceStatus::Ready,
        generation: 1,
        reason: None,
    }))
    .await
    .expect("emit lifecycle ready");
    assert!(!node.is_degraded());

    bus.emit(CoreEvent::Transport(TransportEvent::Degraded {
        service: ServiceDescriptor::new("tcp", ServiceKind::Transport),
        protocol: lp2ln_core_v2::event_core::prelude::TransportProtocol::Tcp,
        reason: "listener restart loop".to_string(),
        loss_rate: 0.0,
    }))
    .await
    .expect("emit transport degraded");
    assert!(node.is_degraded());

    bus.emit(CoreEvent::Transport(TransportEvent::Ready(
        lp2ln_core_v2::event_core::prelude::TransportReadiness {
            service: ServiceDescriptor::new("tcp", ServiceKind::Transport),
            protocol: lp2ln_core_v2::event_core::prelude::TransportProtocol::Tcp,
            listen_addr: None,
            public_addr: None,
            capabilities: vec![],
        },
    )))
    .await
    .expect("emit transport ready");
    assert!(!node.is_degraded());

    node.stop().await.expect("stop");
}

#[tokio::test]
async fn session_close_through_runtime_registers_topology_redial_when_enabled() {
    let mut options = test_options();
    options.topology_react_to_session_events = true;
    options.topology_tuning.prune_redial_cooldown_ms = 50;
    let mut node = build_node(options);
    node.start().await.expect("start");

    let bus = node.core_bus();
    let deliveries_before = bus.stats().event_handler_deliveries;
    assert_eq!(bus.event_handler_count(CoreEventKind::Session), 1);

    let router = node.router().expect("router after start");
    router.register_session(
        PeerId::from("peer-redial"),
        SessionId::from("sess-redial"),
        RelayTestSession::new("sess-redial", "peer-redial"),
    );
    router
        .teardown_session(&SessionId::from("sess-redial"))
        .await
        .expect("close session");
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(
        bus.stats().event_handler_deliveries > deliveries_before,
        "topology session handler should process SessionEvent::Closed"
    );
    assert_eq!(node.active_peer_count(), 0);

    node.stop().await.expect("stop");
}
