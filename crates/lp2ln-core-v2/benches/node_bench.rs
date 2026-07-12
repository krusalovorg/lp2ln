/// End-to-end throughput through full NodeRuntime pipeline:
/// Router ingress → PacketProcessor (semaphore, 256 permits) → broadcast delivery.
///
/// Unlike transport_bench (raw sessions), this exercises every layer:
/// SessionManager, DefaultPacketProcessor, Router dispatch, CoreBus events.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use lp2ln_core_v2::logger::LoggerOptions;
use lp2ln_core_v2::node::{NodeBuilder, NodeOptions, NodeRuntime};
use lp2ln_core_v2::packet::Packet;
use lp2ln_core_v2::router::Router;
use lp2ln_core_v2::sessions::Session;
use lp2ln_core_v2::sessions::session::{IncomingPacket, LinkKind};
use lp2ln_core_v2::transport::obfuscation::Obfuscator;
use lp2ln_core_v2::transport::quic::{QuicTransport, QuicTransportOptions};
use lp2ln_core_v2::transport::tcp::TcpTransport;
use lp2ln_core_v2::transport::udp::{UdpSession, UdpTransport};
use lp2ln_core_v2::transport::Transport;
use lp2ln_core_v2::types::SessionId;
use tokio::net::UdpSocket;
use tokio::sync::broadcast::error::RecvError;

// Smaller batch than transport_bench — full pipeline is ~10× slower.
const BATCH: usize = 200;

fn make_packet(size: usize, sender: &str, receiver: &str) -> Packet {
    Packet {
        signature: None,
        data: vec![0u8; size],
        nodes: vec![],
        sender: sender.into(),
        receiver: receiver.into(),
        max_hops: 4,
        request_id: None,
        chunk_stream_id: None,
        chunk_index: None,
        total_chunks: None,
    }
}

/// Grab a free OS-assigned port, release it, return the number.
/// Tiny race window — acceptable for benchmark setup only.
async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    tokio::time::sleep(Duration::from_millis(5)).await;
    p
}

fn node_opts(listen: Option<(&str, SocketAddr)>) -> NodeOptions {
    let mut opts = NodeOptions::empty().allow_unsigned_packets(true);
    opts.enable_topology_maintenance = false;
    // Suppress all log output during benchmark runs.
    opts = opts.with_logger_options(LoggerOptions {
        log_dir: None,
        file_enabled: false,
        show_debug: false,
        show_info: false,
        show_warning: false,
        show_error: false,
    });
    if let Some((proto, addr)) = listen {
        opts = opts.with_listen(proto, addr);
    }
    opts
}

// ── per-protocol setup ────────────────────────────────────────────────────────

// Returns: (node_a, node_b, router_b, session_id, peer_a_id, peer_b_id)
// peer_b_id must be the packet sender — DefaultPacketProcessor enforces sender == session.peer_id.
async fn setup_tcp() -> (NodeRuntime, NodeRuntime, Arc<Router>, SessionId, String, String) {
    let port = free_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let mut node_a = NodeBuilder::new()
        .add_transport(Arc::new(TcpTransport::new()) as Arc<dyn Transport>)
        .build(node_opts(Some(("tcp", addr))))
        .unwrap();
    node_a.start().await.unwrap();

    let mut node_b = NodeBuilder::new()
        .add_transport(Arc::new(TcpTransport::new_dial()) as Arc<dyn Transport>)
        .build(node_opts(None))
        .unwrap();
    node_b.start().await.unwrap();

    let session_id = node_b.connect("tcp", addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    let router_b = node_b.router().unwrap();
    let peer_a = node_a.peer_id().to_string();
    let peer_b = node_b.peer_id().to_string();
    (node_a, node_b, router_b, session_id, peer_a, peer_b)
}

// UDP uses two independent sockets rather than UdpTransport's shared accept-loop
// socket. The shared-socket design would create a race between the accept loop's
// recv_from and the inbound session reader's recv_from on the same fd, causing
// ~50% of bench datagrams to be silently discarded by the accept loop.
async fn setup_udp() -> (NodeRuntime, NodeRuntime, Arc<Router>, SessionId, String, String) {
    let mut node_a = NodeBuilder::new()
        .add_transport(Arc::new(UdpTransport::new_dial()) as Arc<dyn Transport>)
        .build(node_opts(None))
        .unwrap();
    node_a.start().await.unwrap();

    let mut node_b = NodeBuilder::new()
        .add_transport(Arc::new(UdpTransport::new_dial()) as Arc<dyn Transport>)
        .build(node_opts(None))
        .unwrap();
    node_b.start().await.unwrap();

    let obfs = Arc::new(Obfuscator::plain());
    let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr_a = sock_a.local_addr().unwrap();
    let addr_b = sock_b.local_addr().unwrap();

    // sess_a lives on node_a and receives from sock_b's address.
    // sess_b lives on node_b and sends to sock_a's address.
    let sess_a = UdpSession::new_from_socket(sock_a, addr_b, None, LinkKind::DirectUdp, obfs.clone())
        .unwrap();
    let sess_b = UdpSession::new_from_socket(sock_b, addr_a, None, LinkKind::DirectUdp, obfs)
        .unwrap();

    let router_a = node_a.router().unwrap();
    let router_b = node_b.router().unwrap();
    let sid_b = SessionId::from(sess_b.id().to_string());

    router_a.register_session_only(
        SessionId::from(sess_a.id().to_string()),
        sess_a.clone() as Arc<dyn Session>,
    );
    (sess_a as Arc<dyn Session>).spawn_reader(router_a.incoming_sender());

    router_b.register_session_only(sid_b.clone(), sess_b.clone() as Arc<dyn Session>);
    (sess_b as Arc<dyn Session>).spawn_reader(router_b.incoming_sender());

    let peer_a = node_a.peer_id().to_string();
    let peer_b = node_b.peer_id().to_string();
    (node_a, node_b, router_b, sid_b, peer_a, peer_b)
}

async fn setup_quic() -> (NodeRuntime, NodeRuntime, Arc<Router>, SessionId, String, String) {
    let port = free_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let quic_opts = QuicTransportOptions::default();

    let mut node_a = NodeBuilder::new()
        .add_transport(
            Arc::new(QuicTransport::new_listener(Some(addr), quic_opts.clone()))
                as Arc<dyn Transport>,
        )
        .build(node_opts(Some(("quic", addr))))
        .unwrap();
    node_a.start().await.unwrap();

    let mut node_b = NodeBuilder::new()
        .add_transport(Arc::new(QuicTransport::new_dial(quic_opts)) as Arc<dyn Transport>)
        .build(node_opts(None))
        .unwrap();
    node_b.start().await.unwrap();

    let session_id = node_b.connect("quic", addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let router_b = node_b.router().unwrap();
    let peer_a = node_a.peer_id().to_string();
    let peer_b = node_b.peer_id().to_string();
    (node_a, node_b, router_b, session_id, peer_a, peer_b)
}

// ── benchmark ─────────────────────────────────────────────────────────────────

fn node_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("node_throughput");
    group.measurement_time(Duration::from_secs(15));

    for &size in &[100_usize, 8_192] {
        let label = if size < 1_024 {
            format!("{size}B")
        } else {
            format!("{}KB", size / 1_024)
        };
        group.throughput(Throughput::Bytes(BATCH as u64 * size as u64));

        // ── TCP ──────────────────────────────────────────────────────────────
        let (node_a_tcp, _node_b_tcp, router_b_tcp, sid_tcp, peer_a_tcp, peer_b_tcp) =
            rt.block_on(setup_tcp());
        let sub_tcp = Arc::new(tokio::sync::Mutex::new(
            node_a_tcp.router().unwrap().subscribe(),
        ));

        group.bench_function(BenchmarkId::new("tcp", &label), |b| {
            let r = router_b_tcp.clone();
            let sid = sid_tcp.clone();
            let pkt = make_packet(size, &peer_b_tcp, &peer_a_tcp);
            let sub = sub_tcp.clone();
            b.to_async(&rt).iter(|| async {
                for _ in 0..BATCH {
                    r.send_to_session(sid.clone(), pkt.clone()).await.unwrap();
                }
                drain_batch(sub.clone(), BATCH).await;
            });
        });

        // ── UDP ──────────────────────────────────────────────────────────────
        let (node_a_udp, _node_b_udp, router_b_udp, sid_udp, peer_a_udp, peer_b_udp) =
            rt.block_on(setup_udp());
        let sub_udp = Arc::new(tokio::sync::Mutex::new(
            node_a_udp.router().unwrap().subscribe(),
        ));

        group.bench_function(BenchmarkId::new("udp", &label), |b| {
            let r = router_b_udp.clone();
            let sid = sid_udp.clone();
            let pkt = make_packet(size, &peer_b_udp, &peer_a_udp);
            let sub = sub_udp.clone();
            b.to_async(&rt).iter(|| async {
                for _ in 0..BATCH {
                    r.send_to_session(sid.clone(), pkt.clone()).await.unwrap();
                }
                drain_batch(sub.clone(), BATCH).await;
            });
        });

        // ── QUIC ─────────────────────────────────────────────────────────────
        let (node_a_quic, _node_b_quic, router_b_quic, sid_quic, peer_a_quic, peer_b_quic) =
            rt.block_on(setup_quic());
        let sub_quic = Arc::new(tokio::sync::Mutex::new(
            node_a_quic.router().unwrap().subscribe(),
        ));

        group.bench_function(BenchmarkId::new("quic", &label), |b| {
            let r = router_b_quic.clone();
            let sid = sid_quic.clone();
            let pkt = make_packet(size, &peer_b_quic, &peer_a_quic);
            let sub = sub_quic.clone();
            b.to_async(&rt).iter(|| async {
                for _ in 0..BATCH {
                    r.send_to_session(sid.clone(), pkt.clone()).await.unwrap();
                }
                drain_batch(sub.clone(), BATCH).await;
            });
        });
    }

    group.finish();
}

/// Wait until `count` packets arrive on the broadcast receiver.
/// Lagged errors mean the pipeline processed packets faster than we polled —
/// count them as received since they went through the full stack.
async fn drain_batch(
    sub: Arc<tokio::sync::Mutex<tokio::sync::broadcast::Receiver<IncomingPacket>>>,
    count: usize,
) {
    let mut rx = sub.lock().await;
    let mut received = 0;
    while received < count {
        match rx.recv().await {
            Ok(_) => received += 1,
            Err(RecvError::Lagged(n)) => received += n as usize,
            Err(RecvError::Closed) => break,
        }
    }
}

criterion_group!(benches, node_throughput);
criterion_main!(benches);
