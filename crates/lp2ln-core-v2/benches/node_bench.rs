/// End-to-end throughput through full NodeRuntime pipeline:
/// Router ingress в†’ PacketProcessor (semaphore, 256 permits) в†’ broadcast delivery.
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
/// | ECDSA verify on ingress | – | skipped (`allow_unsigned_packets`) | yes |
/// | QUIC TLS 1.3 (transport) | quic only | yes | yes |
///
/// Set `LP2LN_BENCH_CPU=1` to print per-core CPU utilization after the main sweep.
/// 1 Gbit/s ceiling ≈ 125 MiB/s – linear scaling toward 80–100 MiB/s on 64–256 KiB
/// blocks indicates per-packet overhead, not wire bandwidth.
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use lp2ln_core_v2::event_core::prelude::{CoreEvent, TransportEvent};
use lp2ln_core_v2::logger::LoggerOptions;
use lp2ln_core_v2::node::{NodeBuilder, NodeOptions, NodeRuntime};
use lp2ln_core_v2::packet::Packet;
use lp2ln_core_v2::router::Router;
use lp2ln_core_v2::sessions::Session;
use lp2ln_core_v2::sessions::session::{IncomingPacket, LinkKind};
use lp2ln_core_v2::transport::Transport;
use lp2ln_core_v2::transport::obfuscation::Obfuscator;
use lp2ln_core_v2::transport::quic::{QuicTransport, QuicTransportOptions};
use lp2ln_core_v2::transport::tcp::TcpTransport;
use lp2ln_core_v2::transport::udp::{UdpSession, UdpTransport};
use lp2ln_core_v2::types::SessionId;
use tokio::net::UdpSocket;
use tokio::sync::broadcast::error::RecvError;

// Allocator instrumentation is confined to this benchmark executable.
#[global_allocator]
static BENCH_ALLOCATOR: ProbeAllocator = ProbeAllocator;
static COUNT_ALLOCATIONS: AtomicBool = AtomicBool::new(false);
static ALLOCATION_CALLS: AtomicU64 = AtomicU64::new(0);
static REQUESTED_BYTES: AtomicU64 = AtomicU64::new(0);

struct ProbeAllocator;

impl ProbeAllocator {
    fn record(ptr: *mut u8, size: usize) -> *mut u8 {
        if COUNT_ALLOCATIONS.load(Ordering::Relaxed) && !ptr.is_null() {
            ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
            REQUESTED_BYTES.fetch_add(size as u64, Ordering::Relaxed);
        }
        ptr
    }
}

// SAFETY: all allocation operations preserve System's pointer and layout
// contracts. The probe only records successful calls.
unsafe impl std::alloc::GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        Self::record(unsafe { std::alloc::System.alloc(layout) }, layout.size())
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        Self::record(
            unsafe { std::alloc::System.alloc_zeroed(layout) },
            layout.size(),
        )
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        Self::record(
            unsafe { std::alloc::System.realloc(ptr, layout, size) },
            size,
        )
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}

/// Target ~1.6 MiB per criterion iteration (same as the original 200 Г— 8 KiB).
const BENCH_PROTOCOL_ID: u16 = 0xffe0;
const BATCH_TIMEOUT: Duration = Duration::from_secs(3);
const UDP_OBSERVATION_WINDOW: Duration = Duration::from_millis(100);

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
        protocol_id: Some(BENCH_PROTOCOL_ID),
    }
}

async fn start_listener(node: &mut NodeRuntime) -> SocketAddr {
    let mut events = node.core_bus().subscribe_events();
    node.start().await.unwrap();
    tokio::time::timeout(BATCH_TIMEOUT, async {
        loop {
            if let CoreEvent::Transport(TransportEvent::Ready(ready)) = events.recv().await.unwrap()
                && let Some(bound) = ready.listen_addr
            {
                return bound;
            }
        }
    })
    .await
    .expect("benchmark listener did not become ready")
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

// в”Ђв”Ђ per-protocol setup в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

struct BenchSetup {
    _nodes: (NodeRuntime, NodeRuntime),
    router_b: Arc<Router>,
    session_id: SessionId,
    peer_a: String,
    peer_b: String,
    subscriber: tokio::sync::Mutex<tokio::sync::broadcast::Receiver<Arc<IncomingPacket>>>,
}

// peer_b must be the packet sender – DefaultPacketProcessor enforces sender == session.peer_id.
async fn setup(proto: Protocol, security: SecurityProfile) -> BenchSetup {
    let (node_a, node_b, router_b, session_id, peer_a, peer_b) = match proto {
        Protocol::Tcp => setup_tcp(security).await,
        Protocol::Udp => setup_udp(security).await,
        Protocol::Quic => setup_quic(security).await,
    };
    let subscriber = tokio::sync::Mutex::new(node_a.router().unwrap().subscribe_authenticated());
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
) -> (
    NodeRuntime,
    NodeRuntime,
    Arc<Router>,
    SessionId,
    String,
    String,
) {
    let addr = "127.0.0.1:0".parse().unwrap();

    let mut node_a = NodeBuilder::new()
        .add_transport(Arc::new(TcpTransport::new()) as Arc<dyn Transport>)
        .build(node_opts(Some(("tcp", addr)), security))
        .unwrap();
    let addr = start_listener(&mut node_a).await;

    let mut node_b = NodeBuilder::new()
        .add_transport(Arc::new(TcpTransport::new_dial()) as Arc<dyn Transport>)
        .build(node_opts(None, security))
        .unwrap();
    node_b.start().await.unwrap();

    let session_id = tokio::time::timeout(BATCH_TIMEOUT, node_b.connect("tcp", addr))
        .await
        .expect("TCP dial timed out")
        .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    let router_b = node_b.router().unwrap();
    let peer_a = node_a.peer_id().to_string();
    let peer_b = node_b.peer_id().to_string();
    (node_a, node_b, router_b, session_id, peer_a, peer_b)
}

// Keep the preconnected sockets here for comparability with the previous
// loopback bench. Listener/demux is covered by udp_transport_smoke.
async fn setup_udp(
    security: SecurityProfile,
) -> (
    NodeRuntime,
    NodeRuntime,
    Arc<Router>,
    SessionId,
    String,
    String,
) {
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

    let sess_a =
        UdpSession::new_from_socket(sock_a, addr_b, None, LinkKind::DirectUdp, obfs.clone())
            .unwrap();
    let sess_b =
        UdpSession::new_from_socket(sock_b, addr_a, None, LinkKind::DirectUdp, obfs).unwrap();

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
) -> (
    NodeRuntime,
    NodeRuntime,
    Arc<Router>,
    SessionId,
    String,
    String,
) {
    let addr = "127.0.0.1:0".parse().unwrap();
    let quic_opts = QuicTransportOptions::default();

    let mut node_a = NodeBuilder::new()
        .add_transport(
            Arc::new(QuicTransport::new_listener(Some(addr), quic_opts.clone()))
                as Arc<dyn Transport>,
        )
        .build(node_opts(Some(("quic", addr)), security))
        .unwrap();
    let addr = start_listener(&mut node_a).await;

    let mut node_b = NodeBuilder::new()
        .add_transport(Arc::new(QuicTransport::new_dial(quic_opts)) as Arc<dyn Transport>)
        .build(node_opts(None, security))
        .unwrap();
    node_b.start().await.unwrap();

    let session_id = tokio::time::timeout(BATCH_TIMEOUT, node_b.connect("quic", addr))
        .await
        .expect("QUIC dial timed out")
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let router_b = node_b.router().unwrap();
    let peer_a = node_a.peer_id().to_string();
    let peer_b = node_b.peer_id().to_string();
    (node_a, node_b, router_b, session_id, peer_a, peer_b)
}

// в”Ђв”Ђ benchmark в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

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
        if matches!(proto, Protocol::Udp) && std::env::var_os("LP2LN_BENCH_UDP").is_none() {
            continue;
        }
        let setup = rt.block_on(setup(proto, security));
        let next_id = AtomicU64::new(1);
        let pkt = make_packet(size, &setup.peer_b, &setup.peer_a);

        if matches!(proto, Protocol::Udp) {
            let sample = rt.block_on(run_batch(&setup, &pkt, &next_id, batch, proto, None));
            sample.print(&format!("udp/{label}/{}", security.label), batch, size);
            eprintln!(
                "[udp ingress] {label}/{} {:?}",
                security.label,
                setup._nodes.0.router().unwrap().ingress_metrics(),
            );
        } else {
            // Fixed throughput is valid only for the reliable scenarios that
            // assert receipt of every unique message.
            group.throughput(Throughput::Bytes(batch as u64 * size as u64));
            group.bench_function(bench_id, |b| {
                b.to_async(rt).iter(|| async {
                    let sample = run_batch(&setup, &pkt, &next_id, batch, proto, None).await;
                    assert_eq!(
                        sample.latencies.len(),
                        batch,
                        "reliable batch lost messages: {:?}, subscriber lag={}",
                        setup._nodes.0.router().unwrap().ingress_metrics(),
                        sample.subscriber_lag
                    );
                });
            });
        }
        let (receiver, sender) = setup._nodes;
        rt.block_on(async {
            receiver.stop().await.unwrap();
            sender.stop().await.unwrap();
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

/// Production crypto: full ECDSA verify on ingress. Only mid/large payloads – signing
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

#[derive(Default)]
struct DeliverySample {
    latencies: Vec<Duration>,
    jitter: Duration,
    elapsed: Duration,
    subscriber_lag: u64,
}

impl DeliverySample {
    fn print(&self, label: &str, sent: usize, payload_size: usize) {
        let delivered = self.latencies.len();
        let mut latencies = self.latencies.clone();
        latencies.sort_unstable();
        let percentile_us = |p: usize| {
            let index = (latencies.len() * p).div_ceil(100).saturating_sub(1);
            latencies.get(index).map(Duration::as_micros)
        };
        let loss = 100.0 * (sent - delivered) as f64 / sent as f64;
        let goodput = (delivered * payload_size) as f64 / self.elapsed.as_secs_f64();
        eprintln!(
            "[delivery] {label} sent={sent} delivered={delivered} loss_pct={loss:.2}              goodput_Bps={goodput:.0} p50_us={:?} p95_us={:?} p99_us={:?}              jitter_us={} subscriber_lag={}",
            percentile_us(50),
            percentile_us(95),
            percentile_us(99),
            self.jitter.as_micros(),
            self.subscriber_lag
        );
    }
}

async fn run_batch(
    setup: &BenchSetup,
    template: &Packet,
    next_id: &AtomicU64,
    count: usize,
    protocol: Protocol,
    interval: Option<Duration>,
) -> DeliverySample {
    let first_id = next_id.fetch_add(count as u64, Ordering::Relaxed);
    let mut sent_at = Vec::with_capacity(count);
    let mut received_at = vec![None; count];
    let mut received = 0;
    let mut subscriber_lag = 0;
    let started = Instant::now();
    let mut rx = setup.subscriber.lock().await;
    let future = async {
        let send = async {
            for offset in 0..count {
                if let Some(interval) = interval {
                    tokio::time::sleep_until(
                        tokio::time::Instant::from_std(started) + interval * offset as u32,
                    )
                    .await;
                }
                let mut packet = template.clone();
                packet.request_id = Some(first_id + offset as u64);
                let sending = Instant::now();
                setup
                    .router_b
                    .send_to_session(setup.session_id.clone(), packet)
                    .await
                    .unwrap();
                sent_at.push(sending);
            }
        };
        let receive = async {
            while received < count {
                let incoming = match rx.recv().await {
                    Ok(incoming) => incoming,
                    Err(RecvError::Lagged(n)) => {
                        subscriber_lag += n;
                        continue;
                    }
                    Err(RecvError::Closed) => break,
                };
                let packet = &incoming.packet;
                if packet.sender != template.sender
                    || packet.receiver != template.receiver
                    || packet.protocol_id != Some(BENCH_PROTOCOL_ID)
                    || packet.data != template.data
                {
                    continue;
                }
                let Some(offset) = packet.request_id.and_then(|id| id.checked_sub(first_id)) else {
                    continue;
                };
                if let Some(slot) = received_at.get_mut(offset as usize) {
                    if slot.is_none() {
                        *slot = Some(Instant::now());
                        received += 1;
                    }
                }
            }
        };
        tokio::join!(send, receive);
    };
    let deadline = if matches!(protocol, Protocol::Udp) {
        UDP_OBSERVATION_WINDOW
    } else {
        BATCH_TIMEOUT
    } + interval.unwrap_or_default() * count as u32;
    let _ = tokio::time::timeout(deadline, future).await;
    assert_eq!(
        sent_at.len(),
        count,
        "sender did not submit the whole batch before the deadline"
    );
    let mut latencies = Vec::with_capacity(received);
    let mut last_latency: Option<Duration> = None;
    let mut jitter_secs = 0.0;
    for (send, receive) in sent_at.into_iter().zip(received_at) {
        let Some(receive) = receive else {
            last_latency = None;
            continue;
        };
        let latency = receive.saturating_duration_since(send);
        if let Some(last) = last_latency {
            let delta = (latency.as_secs_f64() - last.as_secs_f64()).abs();
            jitter_secs += (delta - jitter_secs) / 16.0;
        }
        last_latency = Some(latency);
        latencies.push(latency);
    }
    DeliverySample {
        latencies,
        jitter: Duration::from_secs_f64(jitter_secs),
        elapsed: started.elapsed(),
        subscriber_lag,
    }
}

struct CpuSample {
    core_index: usize,
    max_util_pct: f32,
}

async fn cpu_probe() {
    use sysinfo::{CpuRefreshKind, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

    let probe_secs = std::env::var("LP2LN_BENCH_PROBE_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(8);
    const PAYLOAD: usize = 8 * 1024;
    let batch = batch_for_payload(PAYLOAD);

    eprintln!(
        "\n[LP2LN_BENCH_CPU] {probe_secs}s QUIC 8KB probe (verify_on, full crypto egress/ingress)..."
    );

    let setup = setup(Protocol::Quic, VERIFY_ON).await;
    let pkt = make_packet(PAYLOAD, &setup.peer_b, &setup.peer_a);
    let next_id = AtomicU64::new(1);

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
        let mut rss_peak = 0u64;

        while !stop_sampler.load(Ordering::Relaxed) {
            system.refresh_cpu_usage();
            if let Some(pid) = pid {
                system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
                if let Some(proc_) = system.process(pid) {
                    process_peak = process_peak.max(proc_.cpu_usage());
                    rss_peak = rss_peak.max(proc_.memory());
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
        (samples, process_peak, rss_peak)
    });

    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(probe_secs);
    let measure_allocator = std::env::var_os("LP2LN_BENCH_ALLOCATIONS").is_some();
    ALLOCATION_CALLS.store(0, Ordering::Relaxed);
    REQUESTED_BYTES.store(0, Ordering::Relaxed);
    COUNT_ALLOCATIONS.store(measure_allocator, Ordering::Relaxed);
    let mut iterations = 0u64;
    while tokio::time::Instant::now() < deadline {
        let sample = run_batch(&setup, &pkt, &next_id, batch, Protocol::Quic, None).await;
        assert_eq!(sample.latencies.len(), batch, "CPU probe lost messages");
        iterations += 1;
    }

    COUNT_ALLOCATIONS.store(false, Ordering::Relaxed);
    let seconds = started.elapsed().as_secs_f64();
    let packets = iterations * batch as u64;
    let rate = packets as f64 / seconds;
    eprintln!(
        "[burst] delivered={packets} pps={rate:.1} goodput_mib_per_sec={:.2} alloc_calls={} requested_bytes={}",
        rate * PAYLOAD as f64 / (1024.0 * 1024.0),
        ALLOCATION_CALLS.load(Ordering::Relaxed),
        REQUESTED_BYTES.load(Ordering::Relaxed),
    );
    let receiver = &setup._nodes.0;
    let sample = run_batch(
        &setup,
        &make_packet(100, &setup.peer_b, &setup.peer_a),
        &next_id,
        250,
        Protocol::Quic,
        Some(Duration::from_millis(20)),
    )
    .await;
    sample.print("quic/100B/verify_on/50pps", 250, 100);
    let queues = receiver.router().unwrap().ingress_metrics();
    eprintln!(
        "[ingress] decoded={} authenticated={} authenticated_local={} replay_or_late={} queue_drops={}          queue_age_mean_us={} queue_age_max_us={}",
        queues.decoded_packets,
        queues.authenticated_packets,
        queues.authenticated_local_packets,
        queues.replay_or_late_rejections,
        queues.processor_queue_drops,
        queues.processor_queue_wait_total_micros / queues.processor_queue_samples.max(1),
        queues.processor_queue_wait_max_micros,
    );

    // ADMISSION_PROFILE_BEGIN
    let rx = receiver.router().unwrap().ingress_memory();
    let tx = setup._nodes.1.router().unwrap().egress_contention();
    eprintln!(
        "[admission] ingress_peak_bytes={} ingress_refused={} ingress_contended={} egress_contended={} egress_wait_us={} reliable_transport_refused={} reliable_dispatch_refused={}",
        rx.peak_bytes,
        rx.refused,
        rx.contended,
        tx.contended,
        tx.waited_micros,
        rx.reliable_refused,
        queues.reliable_admission_failures
    );
    // ADMISSION_PROFILE_END
    stop.store(true, Ordering::Relaxed);
    let (core_samples, process_peak, rss_peak) = sampler.join().expect("cpu sampler thread");

    let hottest = core_samples.iter().max_by(|a, b| {
        a.max_util_pct
            .partial_cmp(&b.max_util_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    eprintln!(
        "[LP2LN_BENCH_CPU] iterations={iterations}, process_peak={process_peak:.1}%, rss_peak_bytes={rss_peak}"
    );
    if let Some(h) = hottest {
        eprintln!(
            "[LP2LN_BENCH_CPU] hottest core: #{} at {:.1}% – {}",
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
