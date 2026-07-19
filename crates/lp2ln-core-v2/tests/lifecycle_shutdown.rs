use std::sync::Arc;
use std::time::{Duration, Instant};

use lp2ln_core_v2::node::{
    NodeBuilder, NodeLifecycleError, NodeLifecycleState, NodeOptions, NodeRuntime,
};
use lp2ln_core_v2::transport::quic::{QuicTransport, QuicTransportOptions};
use lp2ln_core_v2::transport::tcp::TcpTransport;

fn test_options() -> NodeOptions {
    NodeOptions::new().with_listen("tcp", "127.0.0.1:0".parse().expect("valid addr"))
}

fn build_test_node() -> NodeRuntime {
    NodeBuilder::new()
        .add_transport(Arc::new(TcpTransport::new()) as Arc<dyn lp2ln_core_v2::transport::Transport>)
        .build(test_options())
        .expect("build node")
}

async fn start_test_node() -> NodeRuntime {
    let mut node = build_test_node();
    node.start().await.expect("start node");
    node
}

#[tokio::test]
async fn stop_terminates_quic_listener() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let options = QuicTransportOptions::default();
    let mut opts =
        NodeOptions::empty().with_listen("quic", "127.0.0.1:0".parse().expect("valid addr"));
    opts.quic = options;
    opts.enable_topology_maintenance = false;

    let mut node = NodeBuilder::new()
        .add_transport(Arc::new(QuicTransport::new_listener(
            Some("127.0.0.1:0".parse().expect("valid addr")),
            opts.quic.clone(),
        )) as Arc<dyn lp2ln_core_v2::transport::Transport>)
        .build(opts)
        .expect("build node");

    node.start().await.expect("start node");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let stop_started = Instant::now();
    node.stop().await.expect("stop node");
    assert!(
        stop_started.elapsed() < Duration::from_secs(5),
        "QUIC stop took too long: {:?}",
        stop_started.elapsed()
    );
    assert_eq!(node.lifecycle_state(), NodeLifecycleState::Stopped);
}

#[tokio::test]
async fn stop_terminates_all_runtime_services() {
    let node = start_test_node().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let stop_started = Instant::now();
    node.stop().await.expect("stop node");
    assert!(
        stop_started.elapsed() < Duration::from_secs(5),
        "stop took too long: {:?}",
        stop_started.elapsed()
    );
    assert_eq!(node.lifecycle_state(), NodeLifecycleState::Stopped);
    assert_eq!(node.lifecycle_active_tasks(), 0);
}

#[tokio::test]
async fn stop_during_topology_tick_does_not_hang() {
    let node = start_test_node().await;
    // Maintenance initial jitter is at most MAINTENANCE_START_JITTER_MS + 1.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let stop_started = Instant::now();
    node.stop().await.expect("stop during topology tick");
    assert!(
        stop_started.elapsed() < Duration::from_secs(5),
        "stop hung during topology maintenance: {:?}",
        stop_started.elapsed()
    );
}

#[tokio::test]
async fn stop_interrupts_service_backoff() {
    let node = start_test_node().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    node.test_close_router_ingress();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let stop_started = Instant::now();
    node.stop().await.expect("stop during router backoff");
    assert!(
        stop_started.elapsed() < Duration::from_millis(400),
        "stop waited for full backoff interval: {:?}",
        stop_started.elapsed()
    );
}

#[tokio::test]
async fn stop_is_idempotent() {
    let node = start_test_node().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    node.stop().await.expect("first stop");
    let second_started = Instant::now();
    node.stop().await.expect("second stop must be idempotent");
    assert!(
        second_started.elapsed() < Duration::from_secs(1),
        "second stop hung: {:?}",
        second_started.elapsed()
    );
    assert_eq!(node.lifecycle_state(), NodeLifecycleState::Stopped);
}

#[tokio::test]
async fn start_after_stop_is_rejected() {
    let mut node = start_test_node().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    node.stop().await.expect("stop node");

    let err = node.start().await.expect_err("restart must be rejected");
    let lifecycle_err = err
        .downcast_ref::<NodeLifecycleError>()
        .expect("typed lifecycle error");
    assert_eq!(*lifecycle_err, NodeLifecycleError::RestartNotSupported);
    assert_eq!(node.lifecycle_state(), NodeLifecycleState::Stopped);
}
