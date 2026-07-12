//! Multi-node routing benchmark: in-memory SimNetwork (100/1000 nodes) and live
//! NodeRuntime chain validation (10/20 nodes).
//!
//! Measures packet delivery across the farthest pair in a converged topology mesh.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use lp2ln_core_v2::logger::{LoggerOptions, init};
use lp2ln_core_v2::node::{NodeBuilder, NodeOptions, NodeRuntime};
use lp2ln_core_v2::sessions::session::IncomingPacket;
use lp2ln_core_v2::simulation::network::{
    SimNetwork, graph_diameter_estimate, make_routing_packet_with_id, wait_for_request_id,
};
use lp2ln_core_v2::simulation::topology::{
    ScenarioConfig, SimulationMetrics, run_baseline_scenario,
};
use lp2ln_core_v2::transport::Transport;
use lp2ln_core_v2::transport::tcp::TcpTransport;
use lp2ln_core_v2::types::PeerId;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

const TICKS_PER_NODE: usize = 150;
const MAX_HOPS: u8 = 32;
const WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const WAIT_TIMEOUT_LARGE: Duration = Duration::from_secs(120);
const PAYLOAD_SIZES: &[usize] = &[100, 8 * 1024];

fn init_bench_logger() {
    init(&LoggerOptions {
        log_dir: None,
        file_enabled: false,
        show_debug: false,
        show_info: false,
        show_warning: false,
        show_error: false,
    });
}

fn wait_timeout_for(node_count: usize) -> Duration {
    if node_count >= 1000 {
        WAIT_TIMEOUT_LARGE
    } else {
        WAIT_TIMEOUT
    }
}

struct SimBenchEnv {
    _topo_metrics: SimulationMetrics,
    network: SimNetwork,
    source: u64,
    target: u64,
    diameter: usize,
    shortest_hops: usize,
}

async fn build_sim_env(node_count: usize) -> SimBenchEnv {
    let scenario = ScenarioConfig {
        node_count,
        steps: node_count.saturating_mul(TICKS_PER_NODE),
    };
    let (snapshot, topo_metrics) = run_baseline_scenario(scenario);
    if topo_metrics.largest_component_ratio < 0.9 {
        eprintln!(
            "[network_sim_bench] warning: largest_component_ratio={:.2} (< 0.9) for {node_count} nodes",
            topo_metrics.largest_component_ratio
        );
    }
    let pair = SimNetwork::farthest_pair_from_snapshot(&snapshot)
        .expect("farthest pair in converged topology");
    let diameter = graph_diameter_estimate(&snapshot);
    let shortest_hops = pair.distance;
    let network = SimNetwork::from_topology_snapshot(&snapshot)
        .await
        .expect("sim network build");

    eprintln!(
        "[network_sim_bench] nodes={node_count} diameter={diameter} pair={}→{} hops={shortest_hops} avg_degree={:.2}",
        pair.source, pair.target, topo_metrics.average_degree
    );

    SimBenchEnv {
        _topo_metrics: topo_metrics,
        network,
        source: pair.source,
        target: pair.target,
        diameter,
        shortest_hops,
    }
}

fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else {
        format!("{}KB", bytes / 1024)
    }
}

fn node_opts(listen: Option<SocketAddr>) -> NodeOptions {
    let mut opts = NodeOptions::empty().allow_unsigned_packets(true);
    opts.enable_topology_maintenance = false;
    opts = opts.with_logger_options(LoggerOptions {
        log_dir: None,
        file_enabled: false,
        show_debug: false,
        show_info: false,
        show_warning: false,
        show_error: false,
    });
    if let Some(addr) = listen {
        opts = opts.with_listen("tcp", addr);
    }
    opts
}

struct LiveChain {
    _nodes: Vec<NodeRuntime>,
    first: Arc<NodeRuntime>,
    last_peer_id: String,
    hop_count: usize,
}

async fn build_live_chain(node_count: usize) -> LiveChain {
    let base_port: u16 = 22_000 + (node_count as u16 * 10);
    let mut nodes: Vec<NodeRuntime> = Vec::with_capacity(node_count);
    let mut addrs: Vec<SocketAddr> = Vec::with_capacity(node_count);

    for idx in 0..node_count {
        let port = base_port + idx as u16;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        addrs.push(addr);
        let mut node = NodeBuilder::new()
            .add_transport(Arc::new(TcpTransport::new()) as Arc<dyn Transport>)
            .build(node_opts(Some(addr)))
            .expect("build node");
        node.start().await.expect("start node");
        nodes.push(node);
    }

    // Chain: node[i] dials node[i-1].
    for idx in 1..node_count {
        nodes[idx]
            .connect("tcp", addrs[idx - 1])
            .await
            .expect("chain connect");
    }

    // Long cross-link for alternate path validation.
    if node_count >= 4 {
        let mid = node_count / 2;
        nodes[node_count - 1]
            .connect("tcp", addrs[mid])
            .await
            .expect("cross connect");
    }

    tokio::time::sleep(Duration::from_millis(750)).await;

    let last_peer_id = nodes[node_count - 1].peer_id().to_string();
    let first = Arc::new(nodes.remove(0));
    LiveChain {
        _nodes: nodes,
        first,
        last_peer_id,
        hop_count: node_count.saturating_sub(1),
    }
}

async fn wait_live_delivery(
    sub: &mut broadcast::Receiver<Arc<IncomingPacket>>,
    sender: &str,
    receiver: &str,
    request_id: u64,
    timeout: Duration,
) -> Option<usize> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, sub.recv()).await {
            Ok(Ok(incoming)) => {
                let pkt = &incoming.packet;
                if pkt.sender == sender
                    && pkt.receiver == receiver
                    && pkt.request_id == Some(request_id)
                {
                    return Some(pkt.nodes.len());
                }
            }
            Ok(Err(RecvError::Lagged(_))) => continue,
            _ => break,
        }
    }
    None
}

fn network_sim_setup(c: &mut Criterion) {
    init_bench_logger();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let sizes = [10usize, 100, 1000];

    let mut group = c.benchmark_group("network_sim_setup");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));

    for &node_count in &sizes {
        group.bench_with_input(
            BenchmarkId::new("converge_and_build", format!("{node_count}nodes")),
            &node_count,
            |b, &node_count| {
                b.to_async(&rt).iter(|| async move {
                    let env = build_sim_env(node_count).await;
                    env.network.shutdown().await;
                    env.diameter
                });
            },
        );
    }
    group.finish();
}

fn network_sim_single_delivery(c: &mut Criterion) {
    init_bench_logger();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let sizes = [100usize, 1000];

    let mut group = c.benchmark_group("network_sim_single_delivery");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    for &node_count in &sizes {
        let env = rt.block_on(build_sim_env(node_count));
        let network = Arc::new(env.network);
        let sender = network.peer_id(env.source).to_string();
        let receiver = network.peer_id(env.target).to_string();
        let wait_timeout = wait_timeout_for(node_count);
        let rx = Arc::new(tokio::sync::Mutex::new(network.subscribe(env.target)));
        let seq = AtomicU64::new(1);

        for &payload in PAYLOAD_SIZES {
            let label = format!("{node_count}nodes/{}", format_size(payload));
            let source = env.source;
            let shortest = env.shortest_hops;
            group.throughput(Throughput::Bytes(payload as u64));
            group.bench_with_input(
                BenchmarkId::new("farthest_pair", &label),
                &payload,
                |b, &payload| {
                    let network = network.clone();
                    let rx = rx.clone();
                    let sender = sender.clone();
                    let receiver = receiver.clone();
                    b.to_async(&rt).iter(|| {
                        let request_id = seq.fetch_add(1, Ordering::Relaxed);
                        let network = network.clone();
                        let rx = rx.clone();
                        let sender = sender.clone();
                        let receiver = receiver.clone();
                        async move {
                            let packet = make_routing_packet_with_id(
                                &sender,
                                &receiver,
                                payload,
                                MAX_HOPS,
                                Some(request_id),
                            );
                            network.send_from(source, packet).await.expect("send");
                            let mut guard = rx.lock().await;
                            let hops = wait_for_request_id(
                                &mut guard,
                                request_id,
                                &sender,
                                &receiver,
                                wait_timeout,
                            )
                            .await
                            .unwrap_or_else(|| {
                                panic!("single delivery failed (nodes={node_count})");
                            });
                            assert!(
                                hops <= shortest + 2,
                                "hop count {hops} exceeds shortest {shortest} + 2"
                            );
                        }
                    });
                },
            );
            group.throughput(Throughput::Elements(1));
        }
        if let Ok(network) = Arc::try_unwrap(network) {
            rt.block_on(network.shutdown());
        }
    }
    group.finish();
}

fn network_sim_flood(c: &mut Criterion) {
    init_bench_logger();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let sizes = [100usize, 1000];
    const BATCH: usize = 20;

    let mut group = c.benchmark_group("network_sim_flood");
    group.sample_size(10);
    group.throughput(Throughput::Elements(BATCH as u64));
    group.measurement_time(Duration::from_secs(30));

    for &node_count in &sizes {
        let env = rt.block_on(build_sim_env(node_count));
        let network = Arc::new(env.network);
        let sender = network.peer_id(env.source).to_string();
        let receiver = network.peer_id(env.target).to_string();
        let label = format!("{node_count}nodes/8KB");
        let source = env.source;
        let target = env.target;
        let shortest = env.shortest_hops;
        let wait_timeout = wait_timeout_for(node_count);

        group.bench_with_input(
            BenchmarkId::new("farthest_flood", &label),
            &node_count,
            |b, _| {
                let network = network.clone();
                let sender = sender.clone();
                let receiver = receiver.clone();
                b.to_async(&rt).iter(|| {
                    let network = network.clone();
                    let sender = sender.clone();
                    let receiver = receiver.clone();
                    async move {
                    let metrics = network
                        .flood_and_wait_count(
                            source,
                            target,
                            &sender,
                            &receiver,
                            BATCH,
                            8 * 1024,
                            MAX_HOPS,
                            wait_timeout,
                        )
                        .await;
                    eprintln!(
                        "[network_sim_flood] nodes={node_count} delivered={}/{} rate={:.1}% avg_hops={:.1} shortest={shortest}",
                        metrics.delivered,
                        metrics.sent,
                        metrics.delivery_rate() * 100.0,
                        metrics.avg_hops(),
                    );
                    assert!(
                        metrics.delivery_rate() >= 0.90,
                        "flood delivery rate too low: {:.1}%",
                        metrics.delivery_rate() * 100.0
                    );
                    metrics.wall_time
                    }
                });
            },
        );
        if let Ok(network) = Arc::try_unwrap(network) {
            rt.block_on(network.shutdown());
        }
    }
    group.finish();
}

fn network_sim_live(c: &mut Criterion) {
    init_bench_logger();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let sizes = [10usize, 20];

    let mut group = c.benchmark_group("network_sim_live");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(25));

    for &node_count in &sizes {
        let chain = rt.block_on(build_live_chain(node_count));
        let sender = chain.first.peer_id().to_string();
        let receiver = chain.last_peer_id.clone();
        let target = chain._nodes.last().expect("last node");
        let route = PeerId::from(receiver.as_str());
        let sub = Arc::new(tokio::sync::Mutex::new(
            target.router().expect("router").subscribe(),
        ));
        let hop_limit = chain.hop_count + 2;

        group.bench_with_input(
            BenchmarkId::new("chain_end_to_end", format!("{node_count}nodes")),
            &node_count,
            |b, _| {
                let first = chain.first.clone();
                let route = route.clone();
                let sub = sub.clone();
                let sender = sender.clone();
                let receiver = receiver.clone();
                b.to_async(&rt).iter(|| {
                    let first = first.clone();
                    let route = route.clone();
                    let sub = sub.clone();
                    let sender = sender.clone();
                    let receiver = receiver.clone();
                    async move {
                        let request_id = first
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
                        let hops = wait_live_delivery(
                            &mut guard,
                            &sender,
                            &receiver,
                            request_id,
                            WAIT_TIMEOUT,
                        )
                        .await
                        .expect("live delivery");
                        assert!(
                            hops <= hop_limit,
                            "hop count {hops} exceeds chain expectation {hop_limit}"
                        );
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    network_sim_setup,
    network_sim_single_delivery,
    network_sim_flood,
    network_sim_live,
);
criterion_main!(benches);
