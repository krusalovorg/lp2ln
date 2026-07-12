use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use lp2ln_core_v2::packet::Packet;
use lp2ln_core_v2::sessions::session::LinkKind;
use lp2ln_core_v2::sessions::{IncomingPacket, Session};
use lp2ln_core_v2::transport::obfuscation::Obfuscator;
use lp2ln_core_v2::transport::quic::{QuicTransport, QuicTransportOptions};
use lp2ln_core_v2::transport::tcp::TcpSession;
use lp2ln_core_v2::transport::udp::UdpSession;
use lp2ln_core_v2::transport::{Transport, TransportContext};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

// Packets sent per criterion iteration — large enough to amortise async overhead.
const BATCH: usize = 1_000;

fn make_packet(size: usize) -> Packet {
    Packet {
        signature: None,
        data: vec![0u8; size],
        nodes: vec![],
        sender: "bench-a".into(),
        receiver: "bench-b".into(),
        max_hops: 4,
        request_id: None,
        chunk_stream_id: None,
        chunk_index: None,
        total_chunks: None,
    }
}

// ── session pair helpers ──────────────────────────────────────────────────────

/// Raw TCP pair: bypasses the transport handshake so we measure pure wire throughput.
async fn pair_tcp() -> (Arc<dyn Session>, Arc<dyn Session>) {
    let obfs = Arc::new(Obfuscator::plain());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<Arc<dyn Session>>();
    let obfs2 = obfs.clone();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let s = TcpSession::new_from_stream(stream, None, LinkKind::DirectTcp, obfs2).unwrap()
            as Arc<dyn Session>;
        let _ = tx.send(s);
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let client = TcpSession::new_from_stream(stream, None, LinkKind::DirectTcp, obfs).unwrap()
        as Arc<dyn Session>;
    let server = rx.await.unwrap();
    (client, server)
}

/// Two independent UDP sockets pointing at each other — no shared-socket races.
async fn pair_udp() -> (Arc<dyn Session>, Arc<dyn Session>) {
    let obfs = Arc::new(Obfuscator::plain());
    let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr_a = a.local_addr().unwrap();
    let addr_b = b.local_addr().unwrap();

    let sess_a = UdpSession::new_from_socket(a, addr_b, None, LinkKind::DirectUdp, obfs.clone())
        .unwrap() as Arc<dyn Session>;
    let sess_b = UdpSession::new_from_socket(b, addr_a, None, LinkKind::DirectUdp, obfs).unwrap()
        as Arc<dyn Session>;
    (sess_a, sess_b)
}

/// QUIC pair — mirrors the quic_transport_smoke test.
async fn pair_quic() -> (Arc<dyn Session>, Arc<dyn Session>) {
    let opts = QuicTransportOptions::default();
    let listener = Arc::new(QuicTransport::new_listener(
        Some("127.0.0.1:0".parse().unwrap()),
        opts.clone(),
    ));
    let dialer = Arc::new(QuicTransport::new_dial(opts));

    let (incoming_tx, mut incoming_rx) = mpsc::channel(8);
    let bound = listener
        .start(TransportContext {
            incoming_sessions_tx: incoming_tx,
            incoming_packets_tx: mpsc::channel(8).0,
            listen_addr: None,
            event_tx: None,
            keypair: None,
            catalog: None,
        })
        .await
        .unwrap()
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let outbound = dialer.dial(bound).await.unwrap();
    // First send opens the QUIC stream so the listener creates the inbound session.
    outbound.send(make_packet(1)).await.unwrap();
    let inbound = tokio::time::timeout(Duration::from_secs(5), incoming_rx.recv())
        .await
        .unwrap()
        .unwrap();
    (outbound, inbound)
}

// ── bench helpers ─────────────────────────────────────────────────────────────

/// Spawns a background task that drains a session's reader so send channels never fill.
fn drain(session: Arc<dyn Session>) {
    let (tx, mut rx) = mpsc::channel::<IncomingPacket>(8_192);
    session.clone().spawn_reader(tx);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
}

/// Sets up an echo pair: server echoes every packet back, returns (client, pong_rx).
async fn setup_echo(
    client: Arc<dyn Session>,
    server: Arc<dyn Session>,
) -> (
    Arc<dyn Session>,
    Arc<tokio::sync::Mutex<mpsc::Receiver<IncomingPacket>>>,
) {
    let (echo_tx, mut echo_rx) = mpsc::channel::<IncomingPacket>(256);
    server.clone().spawn_reader(echo_tx);
    let server2 = server.clone();
    tokio::spawn(async move {
        while let Some(p) = echo_rx.recv().await {
            let _ = server2.send(p.packet).await;
        }
    });
    let (pong_tx, pong_rx) = mpsc::channel::<IncomingPacket>(256);
    client.clone().spawn_reader(pong_tx);
    (client, Arc::new(tokio::sync::Mutex::new(pong_rx)))
}

// ── benchmarks ────────────────────────────────────────────────────────────────

fn throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("throughput");
    group.measurement_time(Duration::from_secs(10));

    // 100 B → max packet rate; 8 KB → data throughput (fits in a UDP datagram after encoding).
    for &size in &[100_usize, 8_192] {
        let label = if size < 1_024 {
            format!("{size}B")
        } else {
            format!("{}KB", size / 1_024)
        };
        group.throughput(Throughput::Bytes(BATCH as u64 * size as u64));

        let tcp_sender = rt.block_on(async {
            let (client, server) = pair_tcp().await;
            drain(server);
            client
        });
        group.bench_function(BenchmarkId::new("tcp", &label), |b| {
            let s = tcp_sender.clone();
            let p = make_packet(size);
            b.to_async(&rt).iter(|| async {
                for _ in 0..BATCH {
                    s.send(p.clone()).await.unwrap();
                }
            });
        });

        let udp_sender = rt.block_on(async {
            let (a, b) = pair_udp().await;
            drain(b);
            a
        });
        group.bench_function(BenchmarkId::new("udp", &label), |b| {
            let s = udp_sender.clone();
            let p = make_packet(size);
            b.to_async(&rt).iter(|| async {
                for _ in 0..BATCH {
                    s.send(p.clone()).await.unwrap();
                }
            });
        });

        let quic_sender = rt.block_on(async {
            let (out, inn) = pair_quic().await;
            drain(inn);
            out
        });
        group.bench_function(BenchmarkId::new("quic", &label), |b| {
            let s = quic_sender.clone();
            let p = make_packet(size);
            b.to_async(&rt).iter(|| async {
                for _ in 0..BATCH {
                    s.send(p.clone()).await.unwrap();
                }
            });
        });
    }

    group.finish();
}

fn latency(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("latency");
    group.measurement_time(Duration::from_secs(10));
    // ping-pong iterations are cheap in wall time but each has async overhead.
    group.sample_size(500);

    let ping = make_packet(64);

    let (tcp_client, tcp_pong) = rt.block_on(async {
        let (c, s) = pair_tcp().await;
        setup_echo(c, s).await
    });
    group.bench_function("tcp", |b| {
        let s = tcp_client.clone();
        let rx = tcp_pong.clone();
        let p = ping.clone();
        b.to_async(&rt).iter(|| async {
            s.send(p.clone()).await.unwrap();
            rx.lock().await.recv().await.unwrap();
        });
    });

    let (udp_client, udp_pong) = rt.block_on(async {
        let (c, s) = pair_udp().await;
        setup_echo(c, s).await
    });
    group.bench_function("udp", |b| {
        let s = udp_client.clone();
        let rx = udp_pong.clone();
        let p = ping.clone();
        b.to_async(&rt).iter(|| async {
            s.send(p.clone()).await.unwrap();
            rx.lock().await.recv().await.unwrap();
        });
    });

    let (quic_client, quic_pong) = rt.block_on(async {
        let (c, s) = pair_quic().await;
        setup_echo(c, s).await
    });
    group.bench_function("quic", |b| {
        let s = quic_client.clone();
        let rx = quic_pong.clone();
        let p = ping.clone();
        b.to_async(&rt).iter(|| async {
            s.send(p.clone()).await.unwrap();
            rx.lock().await.recv().await.unwrap();
        });
    });

    group.finish();
}

criterion_group!(benches, throughput, latency);
criterion_main!(benches);
