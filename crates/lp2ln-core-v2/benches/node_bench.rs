/// End-to-end throughput through full NodeRuntime pipeline:
/// Router ingress → PacketProcessor (semaphore, 256 permits) → broadcast delivery.
///
/// Unlike transport_bench (raw sessions), this exercises every layer:
/// SessionManager, DefaultPacketProcessor, Router dispatch, CoreBus events.
///
/// ## Crypto stack (`send_to_session` path)
///
/// | Layer | Always on | `verify_off` (default bench) | `verify_on` (prod bench) |
/// |-------|-----------|------------------------------|--------------------------|
/// | ChaCha20Poly1305 secure envelope (egress) | yes | yes | yes |
/// | ChaCha20Poly1305 decrypt + replay window (ingress) | yes | yes | yes |
/// | ECDSA sign on egress | yes | yes | yes |
/// | ECDSA verify on ingress | — | skipped (`allow_unsigned_packets`) | yes |
/// | QUIC TLS 1.3 (transport) | quic only | yes | yes |
///
/// Set `LP2LN_BENCH_CPU=1` to print per-core CPU utilization after the main sweep.
/// 1 Gbit/s ceiling ≈ 125 MiB/s — linear scaling toward 80–100 MiB/s on 64–256 KiB
/// blocks indicates per-packet overhead, not wire bandwidth.
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// Target ~1.6 MiB per criterion iteration (same as the original 200 × 8 KiB).
const TARGET_ITER_BYTES: usize = 200 * 8 * 1024;

const PAYLOAD_SIZES: &[usize] = &[100, 8 * 1024, 64 * 1024, 256 * 1024];

#[derive(Clone, Copy)]
enum Protocol {
    Tcp,
    Udp,
    Quic,
}

impl Protocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Quic => "quic",
        }
    }

    /// Plaintext above 8 KiB does not fit in a UDP datagram after secure-envelope + postcard encoding.
    fn supports_payload(self, bytes: usize) -> bool {
        !matches!(self, Self::Udp) || bytes <= 8 * 1024
    }
}

#[derive(Clone, Copy)]
struct SecurityProfile {
    allow_unsigned_packets: bool,
    label: &'static str,
}

const VERIFY_OFF: SecurityProfile = SecurityProfile {
    allow_unsigned_packets: true,
    label: "verify_off",
};

const VERIFY_ON: SecurityProfile = SecurityProfile {
    allow_unsigned_packets: false,
    label: "verify_on",
};

fn batch_for_payload(payload_bytes: usize) -> usize {
    (TARGET_ITER_BYTES / payload_bytes).clamp(1, 200)
}

fn format_size_label(bytes: usize) -> String {
    if bytes < 1_024 {
        format!("{bytes}B")
    } else if bytes < 1_024 * 1_024 {
        format!("{}KB", bytes / 1_024)
    } else {
        format!("{}MB", bytes / (1_024 * 1_024))
    }
}

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

fn node_opts(listen: Option<(&str, SocketAddr)>, security: SecurityProfile) -> NodeOptions {
    let mut opts = NodeOptions::empty().allow_unsigned_packets(security.allow_unsigned_packets);
    opts.enable_topology_maintenance = false;
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

struct BenchSetup {
    _nodes: (NodeRuntime, NodeRuntime),
    router_b: Arc<Router>,
    session_id: SessionId,
    peer_a: String,
    peer_b: String,
    subscriber: Arc<tokio::sync::Mutex<tokio::sync::broadcast::Receiver<IncomingPacket>>>,
}

// peer_b must be the packet sender — DefaultPacketProcessor enforces sender == session.peer_id.
async fn setup(proto: Protocol, security: SecurityProfile) -> BenchSetup {
    let (node_a, node_b, router_b, session_id, peer_a, peer_b) = match proto {
        Protocol::Tcp => setup_tcp(security).await,
        Protocol::Udp => setup_udp(security).await,
        Protocol::Quic => setup_quic(security).await,
    };
    let subscriber = Arc::new(tokio::sync::Mutex::new(node_a.router().unwrap().subscribe()));
    BenchSetup {
        _nodes: (node_a, node_b),
        router_b,
        session_id,
        peer_a,
        peer_b,
        subscriber,
    }
}

async fn setup_tcp(
    security: SecurityProfile,
) -> (NodeRuntime, NodeRuntime, Arc<Router>, SessionId, String, String) {
    let port = free_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let mut node_a = NodeBuilder::new()
        .add_transport(Arc::new(TcpTransport::new()) as Arc<dyn Transport>)
        .build(node_opts(Some(("tcp", addr)), security))
        .unwrap();
    node_a.start().await.unwrap();

    let mut node_b = NodeBuilder::new()
        .add_transport(Arc::new(TcpTransport::new_dial()) as Arc<dyn Transport>)
        .build(node_opts(None, security))
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
async fn setup_udp(
    security: SecurityProfile,
) -> (NodeRuntime, NodeRuntime, Arc<Router>, SessionId, String, String) {
    let mut node_a = NodeBuilder::new()
        .add_transport(Arc::new(UdpTransport::new_dial()) as Arc<dyn Transport>)
        .build(node_opts(None, security))
        .unwrap();
    node_a.start().await.unwrap();

    let mut node_b = NodeBuilder::new()
        .add_transport(Arc::new(UdpTransport::new_dial()) as Arc<dyn Transport>)
        .build(node_opts(None, security))
        .unwrap();
    node_b.start().await.unwrap();

    let obfs = Arc::new(Obfuscator::plain());
    let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr_a = sock_a.local_addr().unwrap();
    let addr_b = sock_b.local_addr().unwrap();

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

async fn setup_quic(
    security: SecurityProfile,
) -> (NodeRuntime, NodeRuntime, Arc<Router>, SessionId, String, String) {
    let port = free_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let quic_opts = QuicTransportOptions::default();

    let mut node_a = NodeBuilder::new()
        .add_transport(
            Arc::new(QuicTransport::new_listener(Some(addr), quic_opts.clone()))
                as Arc<dyn Transport>,
        )
        .build(node_opts(Some(("quic", addr)), security))
        .unwrap();
    node_a.start().await.unwrap();

    let mut node_b = NodeBuilder::new()
        .add_transport(Arc::new(QuicTransport::new_dial(quic_opts)) as Arc<dyn Transport>)
        .build(node_opts(None, security))
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

fn register_protocol_benches(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    rt: &tokio::runtime::Runtime,
    proto: Protocol,
    security: SecurityProfile,
    sizes: &[usize],
) {
    for &size in sizes {
        if !proto.supports_payload(size) {
            continue;
        }
        let batch = batch_for_payload(size);
        let label = format_size_label(size);
        let bench_id = BenchmarkId::new(proto.as_str(), format!("{label}/{}", security.label));
        group.throughput(Throughput::Bytes(batch as u64 * size as u64));

        let setup = rt.block_on(setup(proto, security));
        let _keepalive = setup._nodes;
        let router_b = setup.router_b;
        let session_id = setup.session_id;
        let peer_a = setup.peer_a;
        let peer_b = setup.peer_b;
        let subscriber = setup.subscriber;

        group.bench_function(bench_id, |b| {
            let r = router_b.clone();
            let sid = session_id.clone();
            let pkt = make_packet(size, &peer_b, &peer_a);
            let sub = subscriber.clone();
            b.to_async(rt).iter(|| async {
                for _ in 0..batch {
                    r.send_to_session(sid.clone(), pkt.clone()).await.unwrap();
                }
                drain_batch(sub.clone(), batch).await;
            });
        });
    }
}

fn node_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("node_throughput");
    group.measurement_time(Duration::from_secs(15));

    for proto in [Protocol::Tcp, Protocol::Udp, Protocol::Quic] {
        register_protocol_benches(&mut group, &rt, proto, VERIFY_OFF, PAYLOAD_SIZES);
    }

    group.finish();

    if std::env::var_os("LP2LN_BENCH_CPU").is_some() {
        run_cpu_probe();
    }
}

fn run_cpu_probe() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(cpu_probe());
}

/// Production crypto: full ECDSA verify on ingress. Only mid/large payloads — signing
/// cost is mostly fixed per packet, so small-packet prod numbers are dominated by overhead.
fn node_throughput_prod(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("node_throughput_prod");
    group.measurement_time(Duration::from_secs(12));
    let prod_sizes = &[8 * 1024, 64 * 1024];

    for proto in [Protocol::Tcp, Protocol::Udp, Protocol::Quic] {
        register_protocol_benches(&mut group, &rt, proto, VERIFY_ON, prod_sizes);
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

// ── optional CPU probe ────────────────────────────────────────────────────────

struct CpuSample {
    core_index: usize,
    max_util_pct: f32,
}

async fn cpu_probe() {
    use sysinfo::{CpuRefreshKind, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

    const PROBE_SECS: u64 = 8;
    const PAYLOAD: usize = 8 * 1024;
    let batch = batch_for_payload(PAYLOAD);

    eprintln!("\n[LP2LN_BENCH_CPU] {PROBE_SECS}s QUIC 8KB probe (verify_off, full crypto egress/ingress)...");

    let setup = setup(Protocol::Quic, VERIFY_OFF).await;
    let router_b = setup.router_b;
    let sid = setup.session_id;
    let pkt = make_packet(PAYLOAD, &setup.peer_b, &setup.peer_a);
    let sub = setup.subscriber;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_sampler = stop.clone();
    let sampler = std::thread::spawn(move || {
        let mut system = System::new_with_specifics(
            RefreshKind::nothing()
                .with_cpu(CpuRefreshKind::everything())
                .with_processes(ProcessRefreshKind::everything()),
        );
        let pid = sysinfo::get_current_pid().ok();
        let mut core_peak: Vec<f32> = Vec::new();
        let mut process_peak = 0.0f32;

        while !stop_sampler.load(Ordering::Relaxed) {
            system.refresh_cpu_usage();
            if let Some(pid) = pid {
                system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
                if let Some(proc_) = system.process(pid) {
                    process_peak = process_peak.max(proc_.cpu_usage());
                }
            }
            for (i, cpu) in system.cpus().iter().enumerate() {
                let util = cpu.cpu_usage();
                if i >= core_peak.len() {
                    core_peak.push(util);
                } else {
                    core_peak[i] = core_peak[i].max(util);
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let samples: Vec<CpuSample> = core_peak
            .into_iter()
            .enumerate()
            .map(|(core_index, max_util_pct)| CpuSample {
                core_index,
                max_util_pct,
            })
            .collect();
        (samples, process_peak)
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(PROBE_SECS);
    let mut iterations = 0u64;
    while tokio::time::Instant::now() < deadline {
        for _ in 0..batch {
            router_b
                .send_to_session(sid.clone(), pkt.clone())
                .await
                .unwrap();
        }
        drain_batch(sub.clone(), batch).await;
        iterations += 1;
    }

    stop.store(true, Ordering::Relaxed);
    let (core_samples, process_peak) = sampler.join().expect("cpu sampler thread");

    let hottest = core_samples
        .iter()
        .max_by(|a, b| {
            a.max_util_pct
                .partial_cmp(&b.max_util_pct)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    eprintln!(
        "[LP2LN_BENCH_CPU] iterations={iterations}, process_peak={process_peak:.1}%"
    );
    if let Some(h) = hottest {
        eprintln!(
            "[LP2LN_BENCH_CPU] hottest core: #{} at {:.1}% — {}",
            h.core_index,
            h.max_util_pct,
            if h.max_util_pct >= 95.0 {
                "likely single-thread bottleneck (serialization / queue drain)"
            } else if h.max_util_pct >= 70.0 {
                "moderate single-core pressure; check criterion element/s vs throughput"
            } else {
                "multi-core headroom; throughput may be allocation/copy bound"
            }
        );
    }
    let loaded: Vec<_> = core_samples
        .iter()
        .filter(|s| s.max_util_pct >= 50.0)
        .collect();
    eprintln!(
        "[LP2LN_BENCH_CPU] cores >=50%: {}/{}",
        loaded.len(),
        core_samples.len()
    );
}

criterion_group!(benches, node_throughput, node_throughput_prod);
criterion_main!(benches);
