use anyhow::Result;
use lp2ln_core_v2::node::{NodeBuilder, NodeOptions};
use lp2ln_core_v2::packet_processor::PING;
use lp2ln_core_v2::sessions::{LinkKind, SessionMetrics};
use lp2ln_core_v2::transport::{tcp::TcpTransport, udp::UdpTransport};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::interval;

const CENTRAL_PORTS: [u16; 3] = [18080, 18081, 18082];
const CLIENT_PORTS: [u16; 3] = [18180, 18181, 18182];
const METRICS_UPDATE_INTERVAL_SECS: u64 = 2;
const BEST_NODES_EVERY_N_UPDATES: u64 = 100;
const METRICS_FILE: &str = "./test_daemon_metrics.json";

#[derive(Debug, Clone, Copy)]
enum NodeRole {
    Central,
    Client,
}

#[derive(Debug, serde::Serialize)]
struct SessionMetricsSnapshot {
    protocol: String,
    uptime_secs: u64,
    last_activity_secs_ago: u64,
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    send_errors: u64,
    receive_errors: u64,
    reconnections: u64,
    is_active: bool,
}

fn metrics_to_snapshot(kind: LinkKind, m: &SessionMetrics) -> SessionMetricsSnapshot {
    SessionMetricsSnapshot {
        protocol: kind.to_string(),
        uptime_secs: m.uptime().as_secs(),
        last_activity_secs_ago: m.time_since_last_activity().as_secs(),
        packets_sent: m.packets_sent,
        packets_received: m.packets_received,
        bytes_sent: m.bytes_sent,
        bytes_received: m.bytes_received,
        send_errors: m.send_errors,
        receive_errors: m.receive_errors,
        reconnections: m.reconnections,
        is_active: m.is_active,
    }
}

#[derive(Debug, serde::Serialize)]
struct NodeMetricsSnapshot {
    peer_id: String,
    role: String,
    timestamp_secs: u64,
    sessions: Vec<SessionMetricsSnapshot>,
}

#[derive(Debug, serde::Serialize)]
struct NetworkMetricsSnapshot {
    timestamp_secs: u64,
    update_count: u64,
    nodes: Vec<NodeMetricsSnapshot>,
}

struct NodeAggregatedMetrics {
    peer_id: String,
    role: NodeRole,
    total_bytes: u64,
    total_packets: u64,
    total_errors: u64,
    sessions_count: usize,
}

fn aggregate_node_metrics(
    peer_id: &str,
    role: NodeRole,
    node: &lp2ln_core_v2::node::runtime::NodeRuntime,
) -> NodeAggregatedMetrics {
    let by_protocol = node.get_metrics_by_protocol();
    let mut total_bytes = 0u64;
    let mut total_packets = 0u64;
    let mut total_errors = 0u64;
    let mut sessions_count = 0usize;
    for (_, metrics_list) in by_protocol {
        for m in &metrics_list {
            sessions_count += 1;
            total_bytes += m.bytes_sent + m.bytes_received;
            total_packets += m.packets_sent + m.packets_received;
            total_errors += m.send_errors + m.receive_errors;
        }
    }
    NodeAggregatedMetrics {
        peer_id: peer_id.to_string(),
        role,
        total_bytes,
        total_packets,
        total_errors,
        sessions_count,
    }
}

/// Рейтинг: больше трафика и меньше ошибок — лучше. Ошибки штрафуются.
fn score_for_ranking(m: &NodeAggregatedMetrics) -> i64 {
    let traffic = m.total_bytes as i64 + (m.total_packets as i64) * 100;
    let penalty = (m.total_errors as i64) * 10_000;
    traffic - penalty
}

fn collect_node_snapshot(
    peer_id: &str,
    role: NodeRole,
    node: &lp2ln_core_v2::node::runtime::NodeRuntime,
) -> NodeMetricsSnapshot {
    let by_protocol = node.get_metrics_by_protocol();
    let sessions: Vec<SessionMetricsSnapshot> = by_protocol
        .into_iter()
        .flat_map(|(kind, metrics_list)| {
            metrics_list
                .iter()
                .map(|m| metrics_to_snapshot(kind, m))
                .collect::<Vec<_>>()
        })
        .collect();
    NodeMetricsSnapshot {
        peer_id: peer_id.to_string(),
        role: match role {
            NodeRole::Central => "central",
            NodeRole::Client => "client",
        }
        .to_string(),
        timestamp_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        sessions,
    }
}

fn save_metrics_to_file(
    nodes: &[(&str, NodeRole, &lp2ln_core_v2::node::runtime::NodeRuntime)],
    path: impl AsRef<Path>,
    update_count: u64,
) -> Result<()> {
    let timestamp_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let node_snapshots: Vec<NodeMetricsSnapshot> = nodes
        .iter()
        .map(|(pid, role, node)| collect_node_snapshot(pid, *role, node))
        .collect();
    let snapshot = NetworkMetricsSnapshot {
        timestamp_secs,
        update_count,
        nodes: node_snapshots,
    };
    let json = serde_json::to_string_pretty(&snapshot)?;
    std::fs::write(path.as_ref(), json)?;
    Ok(())
}

/// Вывод в консоль лучших узлов по метрикам (каждые BEST_NODES_EVERY_N_UPDATES обновлений).
fn print_best_nodes(
    nodes: &[(&str, NodeRole, &lp2ln_core_v2::node::runtime::NodeRuntime)],
    top_n: usize,
) {
    let mut aggregated: Vec<NodeAggregatedMetrics> = nodes
        .iter()
        .map(|(pid, role, node)| aggregate_node_metrics(pid, *role, node))
        .collect();
    aggregated.sort_by(|a, b| score_for_ranking(b).cmp(&score_for_ranking(a)));
    let n = top_n.min(aggregated.len());
    println!("\n========== Лучшие узлы (топ-{} по метрикам) ==========", n);
    for (i, m) in aggregated.into_iter().take(n).enumerate() {
        let role_str = match m.role {
            NodeRole::Central => "центральный",
            NodeRole::Client => "клиент",
        };
        println!(
            "  #{:2}  {}  [{}]  байт={}  пакетов={}  ошибок={}  сессий={}",
            i + 1,
            m.peer_id,
            role_str,
            m.total_bytes,
            m.total_packets,
            m.total_errors,
            m.sessions_count
        );
    }
    println!("======================================================\n");
}

fn build_central_options(port: u16) -> NodeOptions {
    let addr_tcp = format!("0.0.0.0:{}", port).parse().unwrap();
    let addr_udp = format!("0.0.0.0:{}", port + 100).parse().unwrap();
    NodeOptions::empty()
        .with_listen("tcp", addr_tcp)
        .with_listen("udp", addr_udp)
        .with_default_nodes(vec![])
        .allow_unsigned_packets(true)
        .keypair_generate()
}

fn build_client_options(port: u16, central_addrs: Vec<std::net::SocketAddr>) -> NodeOptions {
    let addr_tcp = format!("0.0.0.0:{}", port).parse().unwrap();
    let addr_udp = format!("0.0.0.0:{}", port + 100).parse().unwrap();
    NodeOptions::empty()
        .with_listen("tcp", addr_tcp)
        .with_listen("udp", addr_udp)
        .with_default_nodes(central_addrs)
        .allow_unsigned_packets(true)
        .keypair_generate()
}

fn make_builder() -> NodeBuilder {
    NodeBuilder::new()
        .add_transport(Arc::new(TcpTransport::new()))
        .add_transport(Arc::new(UdpTransport::new()))
}

/// Отправить N тестовых пакетов: клиенты шлют центрам по кругу.
async fn send_test_packets(
    nodes: &[lp2ln_core_v2::node::runtime::NodeRuntime],
    peer_ids: &[String],
    central_count: usize,
    n: u32,
) {
    let client_count = nodes.len() - central_count;
    if central_count == 0 || client_count == 0 {
        lp2ln_core_v2::error!("[TestDaemon] Нет центральных или клиентских узлов");
        return;
    }
    let mut sent = 0u32;
    let mut failed = 0u32;
    for k in 0..n {
        let client_idx = (k as usize) % client_count;
        let central_idx = (k as usize) % central_count;
        let node = &nodes[central_count + client_idx];
        let peer_id = lp2ln_core_v2::PeerId::from(peer_ids[central_idx].clone());
        match node.send(peer_id, PING.to_vec()).await {
            Ok(()) => sent += 1,
            Err(e) => {
                failed += 1;
                if failed <= 3 {
                    lp2ln_core_v2::error!("[TestDaemon] Ошибка отправки: {}", e);
                }
            }
        }
    }
    lp2ln_core_v2::info!(
        "[TestDaemon] Отправлено пакетов: {} (ошибок: {})",
        sent, failed
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    console_subscriber::init();
    lp2ln_core_v2::info!("[TestDaemon] Запуск: 3 центральных узла + {} клиентских", CLIENT_PORTS.len());
    lp2ln_core_v2::info!("[TestDaemon] Введите число N и Enter — отправить N тестовых пакетов. Каждые {} обновлений — рейтинг лучших узлов.", BEST_NODES_EVERY_N_UPDATES);

    let central_addrs: Vec<std::net::SocketAddr> = CENTRAL_PORTS
        .iter()
        .map(|p| format!("127.0.0.1:{}", p).parse().unwrap())
        .collect();

    let mut nodes: Vec<lp2ln_core_v2::node::runtime::NodeRuntime> = Vec::with_capacity(CENTRAL_PORTS.len() + CLIENT_PORTS.len());
    let mut roles: Vec<NodeRole> = Vec::with_capacity(CENTRAL_PORTS.len() + CLIENT_PORTS.len());

    for &port in &CENTRAL_PORTS {
        let opts = build_central_options(port);
        let mut node = make_builder().build(opts)?;
        node.start().await?;
        nodes.push(node);
        roles.push(NodeRole::Central);
    }
    for &port in &CLIENT_PORTS {
        let opts = build_client_options(port, central_addrs.clone());
        let mut node = make_builder().build(opts)?;
        node.start().await?;
        nodes.push(node);
        roles.push(NodeRole::Client);
    }

    let central_count = CENTRAL_PORTS.len();
    let peer_ids: Vec<String> = nodes.iter().map(|n| n.peer_id().to_string()).collect();
    lp2ln_core_v2::info!("[TestDaemon] Центральные узлы: {:?}", &peer_ids[..central_count]);
    lp2ln_core_v2::info!("[TestDaemon] Клиентские узлы: {:?}", &peer_ids[central_count..]);

    tokio::time::sleep(Duration::from_secs(3)).await;

    let update_count = Arc::new(AtomicU64::new(0));
    let metrics_path = std::path::PathBuf::from(METRICS_FILE);
    let mut ticker = interval(Duration::from_secs(METRICS_UPDATE_INTERVAL_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut stdin_lines = BufReader::new(tokio::io::stdin()).lines();

    loop {
        let nodes_ref: Vec<(&str, NodeRole, &lp2ln_core_v2::node::runtime::NodeRuntime)> = nodes
            .iter()
            .zip(roles.iter().copied())
            .map(|(n, r)| (n.peer_id(), r, n))
            .collect();

        tokio::select! {
            _ = ticker.tick() => {
                if let Err(e) = save_metrics_to_file(&nodes_ref, &metrics_path, update_count.load(Ordering::Relaxed)) {
                    lp2ln_core_v2::error!("[TestDaemon] Ошибка сохранения метрик: {}", e);
                }
                let count = update_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count % BEST_NODES_EVERY_N_UPDATES == 0 {
                    print_best_nodes(&nodes_ref, 10);
                }
            }
            line_result = stdin_lines.next_line() => {
                match line_result {
                    Ok(Some(line)) => {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }
                        match line.parse::<u32>() {
                            Ok(n) if n > 0 => {
                                send_test_packets(&nodes, &peer_ids, central_count, n).await;
                            }
                            Ok(_) => {}
                            Err(_) => {
                                println!("[TestDaemon] Введите положительное число (сколько пакетов отправить). Команда 'q' — выход.");
                                if line.eq_ignore_ascii_case("q") {
                                    break;
                                }
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        lp2ln_core_v2::error!("[TestDaemon] Ошибка чтения ввода: {}", e);
                        break;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                lp2ln_core_v2::info!("[TestDaemon] Ctrl+C, останавливаем узлы...");
                break;
            }
        }
    }

    for (i, node) in nodes.iter_mut().enumerate() {
        if let Err(e) = node.stop().await {
            lp2ln_core_v2::error!("[TestDaemon] Ошибка остановки узла {}: {}", i, e);
        }
    }
    lp2ln_core_v2::info!("[TestDaemon] Демон остановлен. Метрики: {}", metrics_path.display());
    Ok(())
}
