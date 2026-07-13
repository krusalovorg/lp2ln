//! Multi-hop routing benchmark — M0.
//!
//! Three separated experiments:
//!   topology_convergence — cost of building the graph (setup only, excluded from delivery timing)
//!   routing_delivery     — single-packet latency on a pre-built graph
//!   routing_load         — batch throughput: all sends before any waiting (true flood)
//!
//! Profile via BENCH_PROFILE env var:
//!   quick (default) — 10/100 nodes, short CI/smoke
//!   full            — 100/1000 nodes, local regression (1000-node convergence excluded)
//!   scale           — includes 1000-node convergence, manual experiment
//!
//! Results written to target/bench-results/network_sim_{profile}_{timestamp}.json

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput};
use lp2ln_core_v2::logger::{LoggerOptions, init};
use lp2ln_core_v2::node::{NodeBuilder, NodeOptions, NodeRuntime};
use lp2ln_core_v2::sessions::session::IncomingPacket;
use lp2ln_core_v2::simulation::network::{
    SimNetwork, graph_diameter_estimate, make_routing_packet_with_id, wait_for_request_id,
};
use lp2ln_core_v2::simulation::topology::{ScenarioConfig, run_baseline_scenario};
use lp2ln_core_v2::transport::Transport;
use lp2ln_core_v2::transport::tcp::TcpTransport;
use lp2ln_core_v2::types::PeerId;
use tokio::sync::broadcast::error::RecvError;

const TICKS_PER_NODE: usize = 150;
const MAX_HOPS: u8 = 32;
const WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const DELIVERY_PAYLOADS: &[usize] = &[100, 8 * 1024];

// ── Profile ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Profile {
    Quick,
    Full,
    Scale,
}

impl Profile {
    fn from_env() -> Self {
        match std::env::var("BENCH_PROFILE").as_deref() {
            Ok("full")  => Self::Full,
            Ok("scale") => Self::Scale,
            _           => Self::Quick,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Full  => "full",
            Self::Scale => "scale",
        }
    }
}

struct BenchSizes {
    /// Sizes measured inside each Criterion iter (setup IS the metric here).
    // ponytail: 1000-node excluded from quick/full — only scale; prevents 2-min CI blowup
    convergence: &'static [usize],
    /// Topology built ONCE before iter; only delivery is timed.
    delivery: &'static [usize],
    /// Same one-time build; each iter sends the whole batch concurrently.
    load: &'static [usize],
    /// Live NodeRuntime chain sizes.
    live: &'static [usize],
    load_batch: usize,
}

fn sizes(p: Profile) -> BenchSizes {
    match p {
        Profile::Quick => BenchSizes {
            convergence: &[10, 100],
            delivery:    &[10, 100],
            load:        &[100],
            live:        &[5, 10],
            load_batch:  10,
        },
        Profile::Full => BenchSizes {
            convergence: &[100],
            delivery:    &[100, 1000],
            load:        &[100, 1000],
            live:        &[10, 20],
            load_batch:  20,
        },
        Profile::Scale => BenchSizes {
            convergence: &[100, 1000],
            delivery:    &[100, 1000],
            load:        &[100, 1000],
            live:        &[10, 20],
            load_batch:  20,
        },
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

static LOGGER: std::sync::Once = std::sync::Once::new();

fn bench_logger() {
    LOGGER.call_once(|| {
        init(&LoggerOptions {
            log_dir:      None,
            file_enabled: false,
            show_debug:   false,
            show_info:    false,
            show_warning: false,
            show_error:   false,
        });
    });
}

fn tokio_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn fmt_size(b: usize) -> String {
    if b < 1024 { format!("{b}B") } else { format!("{}KB", b / 1024) }
}

struct SimEnv {
    network:       SimNetwork,
    source:        u64,
    target:        u64,
    shortest_hops: usize,
}

async fn build_sim_env(n: usize) -> SimEnv {
    let scenario = ScenarioConfig { node_count: n, steps: n * TICKS_PER_NODE };
    let (snapshot, metrics) = run_baseline_scenario(scenario);
    if metrics.largest_component_ratio < 0.9 {
        eprintln!(
            "[bench] warn: component_ratio={:.2} for {n} nodes",
            metrics.largest_component_ratio
        );
    }
    let pair     = SimNetwork::farthest_pair_from_snapshot(&snapshot).expect("farthest pair");
    let diameter = graph_diameter_estimate(&snapshot);
    let network  = SimNetwork::from_topology_snapshot(&snapshot).await.expect("sim network");
    eprintln!(
        "[bench] nodes={n} diameter={diameter} pair={}→{} hops={} avg_degree={:.2}",
        pair.source, pair.target, pair.distance, metrics.average_degree,
    );
    SimEnv { network, source: pair.source, target: pair.target, shortest_hops: pair.distance }
}

fn node_opts(listen: Option<SocketAddr>) -> NodeOptions {
    let mut opts = NodeOptions::empty().allow_unsigned_packets(true);
    opts.enable_topology_maintenance = false;
    opts = opts.with_logger_options(LoggerOptions {
        log_dir:      None,
        file_enabled: false,
        show_debug:   false,
        show_info:    false,
        show_warning: false,
        show_error:   false,
    });
    if let Some(addr) = listen {
        opts = opts.with_listen("tcp", addr);
    }
    opts
}

// ── Live chain ────────────────────────────────────────────────────────────────

struct LiveChain {
    /// All nodes except first (which is Arc'd for sharing across closures).
    nodes:        Vec<NodeRuntime>,
    first:        Arc<NodeRuntime>,
    last_peer_id: String,
    hop_count:    usize,
}

async fn build_live_chain(n: usize) -> LiveChain {
    let base_port: u16 = 22_100 + (n as u16 * 10);
    let mut nodes: Vec<NodeRuntime> = Vec::with_capacity(n);
    let mut addrs: Vec<SocketAddr>  = Vec::with_capacity(n);

    for idx in 0..n {
        let addr: SocketAddr = format!("127.0.0.1:{}", base_port + idx as u16).parse().unwrap();
        addrs.push(addr);
        let mut node = NodeBuilder::new()
            .add_transport(Arc::new(TcpTransport::new()) as Arc<dyn Transport>)
            .build(node_opts(Some(addr)))
            .expect("build node");
        node.start().await.expect("start");
        nodes.push(node);
    }
    for idx in 1..n {
        nodes[idx].connect("tcp", addrs[idx - 1]).await.expect("chain connect");
    }
    if n >= 4 {
        nodes[n - 1].connect("tcp", addrs[n / 2]).await.expect("cross connect");
    }
    tokio::time::sleep(Duration::from_millis(750)).await;

    let last_peer_id = nodes[n - 1].peer_id().to_string();
    let first = Arc::new(nodes.remove(0));
    LiveChain { nodes, first, last_peer_id, hop_count: n.saturating_sub(1) }
}

async fn wait_live_delivery(
    sub: &mut tokio::sync::broadcast::Receiver<Arc<IncomingPacket>>,
    sender: &str,
    receiver: &str,
    request_id: u64,
    timeout: Duration,
) -> Option<usize> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(rem, sub.recv()).await {
            Ok(Ok(inc)) => {
                let p = &inc.packet;
                if p.sender == sender && p.receiver == receiver && p.request_id == Some(request_id) {
                    return Some(p.nodes.len());
                }
            }
            Ok(Err(RecvError::Lagged(_))) => continue,
            _ => break,
        }
    }
    None
}

// ── JSON output ───────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct BenchRun {
    timestamp:  String,
    commit_sha: String,
    profile:    String,
    os:         String,
    scenarios:  Vec<LoadScenario>,
}

#[derive(serde::Serialize)]
struct LoadScenario {
    nodes:         usize,
    batch:         usize,
    payload_bytes: usize,
    sent:          usize,
    delivered:     usize,
    delivery_rate: f64,
    avg_hops:      f64,
    wall_time_ms:  u64,
}

fn git_sha() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn write_results(profile: Profile, scenarios: Vec<LoadScenario>) {
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let run = BenchRun {
        timestamp:  ts.clone(),
        commit_sha: git_sha(),
        profile:    profile.as_str().to_string(),
        os:         format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
        scenarios,
    };
    let dir = std::path::Path::new("target/bench-results");
    std::fs::create_dir_all(dir).ok();
    let path = dir.join(format!("network_sim_{}_{ts}.json", profile.as_str()));
    match serde_json::to_string_pretty(&run) {
        Ok(json) => {
            std::fs::write(&path, json).ok();
            eprintln!("[bench] results → {}", path.display());
        }
        Err(e) => eprintln!("[bench] json write failed: {e}"),
    }
}

// ── Benchmark groups ──────────────────────────────────────────────────────────

/// Measures topology setup cost: simulation + SimNetwork construction.
/// Setup IS the thing being timed here — runs inside each Criterion iter.
fn topology_convergence(c: &mut Criterion, node_sizes: &[usize]) {
    let rt = tokio_rt();
    let mut group = c.benchmark_group("topology_convergence");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    for &n in node_sizes {
        group.bench_function(BenchmarkId::new("nodes", n), |b| {
            b.to_async(&rt).iter(|| async move {
                let scenario = ScenarioConfig { node_count: n, steps: n * TICKS_PER_NODE };
                let (snapshot, _) = run_baseline_scenario(scenario);
                let net = SimNetwork::from_topology_snapshot(&snapshot).await.expect("sim net");
                net.shutdown().await;
            });
        });
    }
    group.finish();
}

/// Single-packet delivery latency. Topology built ONCE — setup not in timing.
fn routing_delivery(c: &mut Criterion, node_sizes: &[usize]) {
    let rt = tokio_rt();
    let mut group = c.benchmark_group("routing_delivery");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(20));

    for &n in node_sizes {
        let env      = rt.block_on(build_sim_env(n));   // one-time setup
        let source   = env.source;
        let target   = env.target;
        let shortest = env.shortest_hops;
        let network  = Arc::new(env.network);
        let sender   = network.peer_id(source).to_string();
        let receiver = network.peer_id(target).to_string();
        let rx = Arc::new(tokio::sync::Mutex::new(network.subscribe(target)));
        let seq = AtomicU64::new(1);

        for &payload in DELIVERY_PAYLOADS {
            group.throughput(Throughput::Bytes(payload as u64));
            let label = format!("{n}nodes/{}", fmt_size(payload));
            group.bench_with_input(
                BenchmarkId::new("farthest_pair", &label),
                &payload,
                |b, &payload| {
                    let network  = network.clone();
                    let rx       = rx.clone();
                    let sender   = sender.clone();
                    let receiver = receiver.clone();
                    b.to_async(&rt).iter(|| {
                        let rid      = seq.fetch_add(1, Ordering::Relaxed);
                        let network  = network.clone();
                        let rx       = rx.clone();
                        let sender   = sender.clone();
                        let receiver = receiver.clone();
                        async move {
                            let pkt = make_routing_packet_with_id(
                                &sender, &receiver, payload, MAX_HOPS, Some(rid),
                            );
                            network.send_from(source, pkt).await.expect("send");
                            let mut guard = rx.lock().await;
                            let hops = wait_for_request_id(
                                &mut guard, rid, &sender, &receiver, WAIT_TIMEOUT,
                            )
                            .await
                            .unwrap_or_else(|| panic!("delivery timeout nodes={n}"));
                            assert!(
                                hops <= shortest + 2,
                                "hops {hops} exceeds shortest {shortest} + 2"
                            );
                        }
                    });
                },
            );
        }

        drop(rx);
        if let Ok(net) = Arc::try_unwrap(network) {
            rt.block_on(net.shutdown());
        }
    }
    group.finish();
}

/// Batch throughput. Each Criterion iter sends the full batch concurrently,
/// then waits for all unique deliveries under one deadline.
fn routing_load(
    c: &mut Criterion,
    node_sizes: &[usize],
    batch: usize,
    results: &mut Vec<LoadScenario>,
) {
    let rt = tokio_rt();
    let mut group = c.benchmark_group("routing_load");
    group.sample_size(10);
    group.throughput(Throughput::Elements(batch as u64));
    group.measurement_time(Duration::from_secs(30));

    for &n in node_sizes {
        let env      = rt.block_on(build_sim_env(n));   // one-time setup
        let source   = env.source;
        let target   = env.target;
        let shortest = env.shortest_hops;
        let network  = Arc::new(env.network);
        let sender   = network.peer_id(source).to_string();
        let receiver = network.peer_id(target).to_string();
        // monotonically increasing base so request_ids never collide across iters
        let base_id  = AtomicU64::new(1);

        group.bench_with_input(
            BenchmarkId::new("batch_farthest", format!("{n}nodes/8KB")),
            &n,
            |b, _| {
                let network  = network.clone();
                let sender   = sender.clone();
                let receiver = receiver.clone();
                b.to_async(&rt).iter(|| {
                    let network  = network.clone();
                    let sender   = sender.clone();
                    let receiver = receiver.clone();
                    let base     = base_id.fetch_add(batch as u64, Ordering::Relaxed);
                    async move {
                        let m = network
                            .batch_flood_and_wait(
                                source, target, &sender, &receiver,
                                batch, 8 * 1024, MAX_HOPS, WAIT_TIMEOUT, base,
                            )
                            .await;
                        eprintln!(
                            "[load] nodes={n} delivered={}/{} rate={:.1}% avg_edge_hops={:.1} shortest_edges={shortest}",
                            m.delivered, m.sent,
                            m.delivery_rate() * 100.0,
                            m.avg_hops(),
                        );
                        assert!(
                            m.delivery_rate() >= 0.90,
                            "delivery rate {:.1}% < 90%",
                            m.delivery_rate() * 100.0
                        );
                        m.wall_time
                    }
                });
            },
        );

        // One-shot measurement for JSON (outside Criterion, unique request_id range)
        let snap_base = base_id.fetch_add(batch as u64, Ordering::Relaxed);
        let m = rt.block_on(network.batch_flood_and_wait(
            source, target, &sender, &receiver,
            batch, 8 * 1024, MAX_HOPS, WAIT_TIMEOUT, snap_base,
        ));
        results.push(LoadScenario {
            nodes:         n,
            batch,
            payload_bytes: 8 * 1024,
            sent:          m.sent,
            delivered:     m.delivered,
            delivery_rate: m.delivery_rate(),
            avg_hops:      m.avg_hops(),
            wall_time_ms:  m.wall_time.as_millis() as u64,
        });

        if let Ok(net) = Arc::try_unwrap(network) {
            rt.block_on(net.shutdown());
        }
    }
    group.finish();
}

/// Live NodeRuntime chain. Explicit stop() on every node after group finishes (Slice 04).
fn live_chain(c: &mut Criterion, node_sizes: &[usize]) {
    let rt = tokio_rt();
    let mut group = c.benchmark_group("live_chain");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(25));

    for &n in node_sizes {
        let chain    = rt.block_on(build_live_chain(n));
        let sender   = chain.first.peer_id().to_string();
        let receiver = chain.last_peer_id.clone();
        let route    = PeerId::from(receiver.as_str());
        let hop_limit = chain.hop_count + 2;

        let sub = {
            let last = chain.nodes.last().expect("last node");
            Arc::new(tokio::sync::Mutex::new(
                last.router().expect("router").subscribe(),
            ))
        };

        group.bench_with_input(
            BenchmarkId::new("chain_end_to_end", format!("{n}nodes")),
            &n,
            |b, _| {
                let first    = chain.first.clone();
                let sub      = sub.clone();
                let sender   = sender.clone();
                let receiver = receiver.clone();
                let route    = route.clone();
                b.to_async(&rt).iter(|| {
                    let first    = first.clone();
                    let sub      = sub.clone();
                    let sender   = sender.clone();
                    let receiver = receiver.clone();
                    let route    = route.clone();
                    async move {
                        let rid = first
                            .send_with_options(
                                route,
                                vec![0xCD; 256],
                                Some(receiver.clone()),
                                Some(MAX_HOPS),
                                None,
                            )
                            .await
                            .expect("live send");
                        let mut guard = sub.lock().await;
                        let hops = wait_live_delivery(&mut guard, &sender, &receiver, rid, WAIT_TIMEOUT)
                            .await
                            .expect("live delivery timeout");
                        assert!(hops <= hop_limit, "hops {hops} > limit {hop_limit}");
                    }
                });
            },
        );

        // Slice 04: explicit teardown — no background task leaks after bench
        drop(sub);
        for node in &chain.nodes {
            rt.block_on(node.stop()).ok();
        }
        rt.block_on(chain.first.stop()).ok();
    }
    group.finish();
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    bench_logger();
    let profile = Profile::from_env();
    let s = sizes(profile);
    let mut load_results: Vec<LoadScenario> = Vec::new();

    let mut c = Criterion::default().configure_from_args();

    topology_convergence(&mut c, s.convergence);
    routing_delivery(&mut c, s.delivery);
    routing_load(&mut c, s.load, s.load_batch, &mut load_results);
    live_chain(&mut c, s.live);

    c.final_summary();

    write_results(profile, load_results);
}
