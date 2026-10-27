// Link survival — a seed reachable over two paths, one of them blackholed the
// way carrier filtering does it: TCP connects, nothing ever comes back.
// The node must end up on the working path and remember the dead one.

use std::sync::Arc;
use std::time::Duration;

use lp2ln_core_v2::db::P2PDatabase;
use lp2ln_core_v2::event_core::prelude::{CoreEvent, TransportEvent};
use lp2ln_core_v2::node::options::BootstrapNode;
use lp2ln_core_v2::node::{NodeBuilder, NodeOptions};
use lp2ln_core_v2::transport::Transport;
use lp2ln_core_v2::transport::tcp::TcpTransport;

fn temp_db() -> Arc<P2PDatabase> {
    let dir = std::env::temp_dir().join(format!("link_survival_{}", uuid::Uuid::new_v4()));
    Arc::new(P2PDatabase::new(dir.to_str().unwrap()).expect("temp db"))
}

fn opts() -> NodeOptions {
    let mut opts = NodeOptions::empty().with_listen("tcp", "127.0.0.1:0".parse().unwrap());
    opts.enable_topology_maintenance = false;
    opts
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_survives_blackholed_path_and_learns_it() {
    // Accepts connections, reads, never answers.
    let blackhole = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let blackhole_port = blackhole.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = blackhole.accept().await {
            held.push(stream);
        }
    });

    let mut node_a = NodeBuilder::new()
        .db(temp_db())
        .add_transport(Arc::new(TcpTransport::new()) as Arc<dyn Transport>)
        .build(opts())
        .expect("build A");
    let mut bus_rx = node_a.core_bus().subscribe_events();
    node_a.start().await.expect("start A");
    let addr_a = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(CoreEvent::Transport(TransportEvent::Ready(r))) = bus_rx.recv().await {
                if let Some(addr) = r.listen_addr {
                    return addr;
                }
            }
        }
    })
    .await
    .expect("A ready");

    // Blackholed endpoint listed first, so the static order picks it.
    let mut opts_b = opts();
    opts_b.bootstrap_nodes = vec![BootstrapNode::new(
        addr_a,
        [
            format!("tcp:{blackhole_port}"),
            format!("tcp:{}", addr_a.port()),
        ],
        None,
    )];
    let mut node_b = NodeBuilder::new()
        .db(temp_db())
        .add_transport(Arc::new(TcpTransport::new()) as Arc<dyn Transport>)
        .build(opts_b)
        .expect("build B");
    node_b.start().await.expect("start B");

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while node_b.active_peer_count() == 0 {
        assert!(std::time::Instant::now() < deadline, "B never reached A");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The blackholed attempt finishes in the background and is penalised.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let paths = node_b.link_paths();
        let good = paths.iter().find(|p| p.addr.port() == addr_a.port());
        let bad = paths.iter().find(|p| p.addr.port() == blackhole_port);
        if let (Some(good), Some(bad)) = (good, bad) {
            if bad.consecutive_failures > 0 {
                assert!(good.rtt_ms.is_some());
                assert!(good.reliability > bad.reliability);
                assert!(bad.backoff_remaining_ms > 0);
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "blackholed path was never penalised: {paths:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    node_a.stop().await.expect("stop A");
    node_b.stop().await.expect("stop B");
}
