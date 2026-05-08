use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use dashmap::DashMap;

use crate::db::P2PDatabase;
use crate::metrics::MetricsAggregator;
use crate::node::addressing::advertised_addr_for_protocol;
use crate::node::distribution::{
    DIAL_HUB_SOFT_CAP_EXTRA, EXPLORATORY_SLOTS, EXPLORATORY_SLOTS_MAX, REGULAR_SELF_HEAL_FLOOR,
    bootstrap_dial_quota, capacity_target_factor, connectivity_selective, descriptor_prefix24,
    dial_endpoint_attempt_budget, dial_reserve_slots, peers_to_drop_when_overloaded,
    rank_dial_candidates, regular_auto_dial_target, should_reseed_bootstrap,
    should_skip_for_bootstrap_quota, stable_bootstrap_reseed_guard,
};
use crate::node::nat_traversal::NatTraversalState;
use crate::node::options::{
    AdaptiveTopologyProfile, BootstrapNode, NodeOptions, NodeRole, TopologyTuning,
};
use crate::packet::Packet;
use crate::peer_score::{
    PeerConnectionPolicy, PeerScore, PeerScoreStore, PeerScoreWeights, total_score,
};
use crate::protocol::control::NetworkControlPayload;
use crate::router::Router;
use crate::sessions::manager::SessionManager;
use crate::sessions::session::IncomingPacket;
use crate::topology::{
    CapacityBudget, NodeCapabilities, NodeDescriptor, NodeDynamicStatus, PeerCatalog,
    descriptor_ok_for_discovery_redirect, now_ms, parse_observed_addr_line,
    select_peers_for_discovery_response, sign_descriptor,
};
use crate::transport::{Transport, TunnelPunchParams};
use crate::types::{PeerId, SessionId};

const MAINTENANCE_INTERVAL_SECS: u64 = 5;
const MAINTENANCE_START_JITTER_MS: u64 = 3_000;
const REGULAR_MAX_HEADROOM: usize = 2;
const REGULAR_DIAL_ATTEMPT_BUDGET_MAX: usize = 8;
const BOOTSTRAP_DIAL_ATTEMPT_BUDGET_MAX: usize = 8;
/// Bootstrap shepherd: интервал между sweep'ами (мс). Не каждый tick,
/// чтобы не мешать newcomer'у устояться.
const SHEPHERD_SWEEP_INTERVAL_MS: u64 = 10_000;
/// Bootstrap закрывает сессию с peer'ом, если у того уже ≥ SHEPHERD_MIN_MESH
/// не-bootstrap соседей — он устоялся в mesh и bootstrap-слот больше не нужен.
const SHEPHERD_MIN_MESH: u16 = 3;
/// Минимальный grace после появления peer'а в каталоге перед shepherd-close.
const SHEPHERD_GRACE_MS: u64 = 15_000;
/// Сколько regular-дескрипторов вкладывать в финальный PeersResponse при shepherd-close.
const SHEPHERD_FINAL_PEERS_LIMIT: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TopologyPhase {
    Bootstrapping,
    Meshing,
    Steady,
}

#[derive(Debug, Clone, Copy)]
struct AdaptiveTickPolicy {
    dial_target: usize,
    dial_target_low: usize,
    dial_target_high: usize,
    exploration_interval_ms: u64,
    bridge_rejoin_cooldown_ms: u64,
    bootstrap_hard_limit: usize,
    exploratory_slots: usize,
}

fn classify_topology_phase(
    known_peers: usize,
    connected_total: usize,
    connected_non_bootstrap: usize,
    target: usize,
) -> TopologyPhase {
    if known_peers <= 24 || connected_non_bootstrap < target.saturating_div(2).max(2) {
        return TopologyPhase::Bootstrapping;
    }
    if connected_total < target || connected_non_bootstrap < target.saturating_sub(1) {
        return TopologyPhase::Meshing;
    }
    TopologyPhase::Steady
}

fn profile_scale(profile: AdaptiveTopologyProfile) -> (f32, f32, f32) {
    match profile {
        AdaptiveTopologyProfile::Conservative => (0.9, 0.85, 1.25),
        AdaptiveTopologyProfile::Balanced => (1.0, 1.0, 1.0),
        AdaptiveTopologyProfile::Aggressive => (1.15, 1.25, 0.8),
    }
}

fn adaptive_tick_policy(
    tuning: &TopologyTuning,
    base_dial_target: usize,
    phase: TopologyPhase,
    known_peers: usize,
) -> AdaptiveTickPolicy {
    let (target_mul, explore_mul, rejoin_mul) = profile_scale(tuning.adaptive_profile.clone());
    let mut dial_target = base_dial_target;
    if tuning.adaptive_topology_enabled {
        dial_target = (((base_dial_target as f32) * target_mul).round() as usize).clamp(
            tuning.adaptive_target_min_floor,
            tuning.adaptive_target_max_ceil,
        );
        // На совсем малых сетях явно держим чуть выше, чтобы не распадаться на островки.
        if known_peers <= 24 {
            dial_target = dial_target.max(4);
        }
    }
    let (mut low, mut high, mut exploratory_slots) = match phase {
        TopologyPhase::Bootstrapping => (
            dial_target.saturating_sub(1).max(2),
            dial_target.saturating_add(2),
            EXPLORATORY_SLOTS_MAX.min(EXPLORATORY_SLOTS.saturating_add(1)),
        ),
        TopologyPhase::Meshing => (
            dial_target.saturating_sub(1).max(2),
            dial_target.saturating_add(1),
            EXPLORATORY_SLOTS_MAX.min(EXPLORATORY_SLOTS),
        ),
        TopologyPhase::Steady => (
            dial_target.saturating_sub(1).max(2),
            dial_target.saturating_add(1),
            EXPLORATORY_SLOTS.saturating_sub(1).max(1),
        ),
    };
    if !tuning.adaptive_topology_enabled {
        low = dial_target.saturating_sub(1).max(2);
        high = dial_target.saturating_add(1);
        exploratory_slots = EXPLORATORY_SLOTS;
    }

    let base_explore = tuning.regular_exploration_interval_ms;
    let exploration_interval_ms = (((base_explore as f32)
        * match phase {
            TopologyPhase::Bootstrapping => 0.6 * explore_mul,
            TopologyPhase::Meshing => 0.9 * explore_mul,
            TopologyPhase::Steady => 1.6 * explore_mul,
        })
    .round() as u64)
        .clamp(
            tuning.adaptive_exploration_interval_min_ms,
            tuning.adaptive_exploration_interval_max_ms,
        );

    let bridge_rejoin_cooldown_ms = (((tuning.regular_bootstrap_rejoin_interval_ms as f32)
        * match phase {
            TopologyPhase::Bootstrapping => 0.7 * rejoin_mul,
            TopologyPhase::Meshing => 1.0 * rejoin_mul,
            TopologyPhase::Steady => 1.8 * rejoin_mul,
        })
    .round() as u64)
        .clamp(
            tuning.adaptive_rejoin_cooldown_min_ms,
            tuning.adaptive_rejoin_cooldown_max_ms,
        );

    let bootstrap_hard_limit = match phase {
        TopologyPhase::Bootstrapping => tuning.adaptive_bootstrap_hard_max.max(6),
        TopologyPhase::Meshing => tuning.adaptive_bootstrap_hard_max.max(5),
        TopologyPhase::Steady => tuning.adaptive_bootstrap_hard_max.max(4),
    };

    AdaptiveTickPolicy {
        dial_target,
        dial_target_low: low,
        dial_target_high: high.max(low),
        exploration_interval_ms,
        bridge_rejoin_cooldown_ms,
        bootstrap_hard_limit,
        exploratory_slots,
    }
}

fn bootstrap_identity(target: &BootstrapNode) -> String {
    if let Some(hint) = target.peer_id_hint.as_ref() {
        hint.as_str().to_string()
    } else {
        target.addr.to_string()
    }
}

fn rank_bootstrap_targets_for_peer(
    local_peer_id: &str,
    targets: &[BootstrapNode],
) -> Vec<BootstrapNode> {
    let mut weighted: Vec<(u64, BootstrapNode)> = targets
        .iter()
        .cloned()
        .map(|t| {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            local_peer_id.hash(&mut hasher);
            bootstrap_identity(&t).hash(&mut hasher);
            // Reverse sort by score (Rendezvous hashing).
            (hasher.finish(), t)
        })
        .collect();
    weighted.sort_by(|a, b| b.0.cmp(&a.0));
    weighted.into_iter().map(|(_, t)| t).collect()
}

pub(crate) async fn dial_bootstrap_address(
    transports: &[Arc<dyn Transport>],
    router: &Arc<Router>,
    incoming_packets_tx: &tokio::sync::mpsc::Sender<IncomingPacket>,
    our_peer_id: &str,
    target: &BootstrapNode,
    handshake_payload: &[u8],
) -> bool {
    for transport in transports {
        if !transport.is_listener() {
            continue;
        }
        if !target.protocols.is_empty()
            && !target
                .protocols
                .iter()
                .any(|p| p.eq_ignore_ascii_case(transport.name()))
        {
            continue;
        }
        match transport.dial(target.addr).await {
            Ok(session) => {
                crate::info!(
                    "[NodeRuntime] Connected to default node {} via {}",
                    target.addr,
                    transport.name()
                );
                let session_id = SessionId::from(session.id().to_string());
                router.register_session_only(session_id.clone(), session.clone());
                session.spawn_reader(incoming_packets_tx.clone());
                let handshake = Packet {
                    signature: None,
                    data: handshake_payload.to_vec(),
                    nodes: vec![],
                    sender: our_peer_id.to_string(),
                    receiver: String::new(),
                    max_hops: 8,
                    request_id: None,
                    chunk_stream_id: None,
                    chunk_index: None,
                    total_chunks: None,
                };
                if let Err(e) = router.send_to_session(session_id, handshake).await {
                    crate::error!(
                        "[NodeRuntime] Failed to send handshake to {}: {}",
                        target.addr,
                        e
                    );
                    return false;
                }
                return true;
            }
            Err(e) => {
                let detail = crate::logger::describe_anyhow_io_error(&e);
                crate::net_dial!(
                    "[NodeRuntime] Dial to {} via {} failed: {}",
                    target.addr,
                    transport.name(),
                    detail
                );
            }
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_topology_maintenance_loop(
    policy_live_maint: Arc<RwLock<PeerConnectionPolicy>>,
    node_role: NodeRole,
    weights: PeerScoreWeights,
    sm: Arc<SessionManager>,
    dial_book: Arc<DashMap<PeerId, Vec<(String, SocketAddr)>>>,
    peer_store: Arc<PeerScoreStore>,
    catalog: Arc<PeerCatalog>,
    db: Option<Arc<P2PDatabase>>,
    listens: DashMap<String, SocketAddr>,
    advertise_addrs: std::collections::HashMap<String, SocketAddr>,
    advertise_fallback_ip: Option<IpAddr>,
    transports_maint: Vec<Arc<dyn Transport>>,
    router_maint: Arc<Router>,
    incoming_maint: tokio::sync::mpsc::Sender<IncomingPacket>,
    our_peer_maint: String,
    descriptor_ver: Arc<AtomicU64>,
    signing_key: k256::ecdsa::SigningKey,
    log_peer_scores: bool,
    topology_tuning: TopologyTuning,
    maintenance_handshake_payload: Vec<u8>,
    bootstrap_targets_maint: Vec<BootstrapNode>,
    nat_state: Arc<NatTraversalState>,
) -> anyhow::Result<()> {
    let initial_jitter = (our_peer_maint
        .bytes()
        .fold(0u64, |acc, b| acc.wrapping_add(b as u64))
        % MAINTENANCE_START_JITTER_MS)
        + 1;
    tokio::time::sleep(Duration::from_millis(initial_jitter)).await;
    let mut interval = tokio::time::interval(Duration::from_secs(MAINTENANCE_INTERVAL_SECS));
    let mut dial_cooldown_until: HashMap<PeerId, u64> = HashMap::new();
    let mut last_bootstrap_reseed_ms = 0u64;
    let mut last_exploration_ms = 0u64;
    let mut last_shepherd_sweep_ms = 0u64;
    let mut bootstrap_deny_until: HashMap<SocketAddr, u64> = HashMap::new();
    let mut peer_admission_ms: HashMap<PeerId, u64> = HashMap::new();
    let descriptor_ttl_secs = 120u64;
    let descriptor_interval = Duration::from_secs(30);
    let mut last_publish = now_ms().saturating_sub(descriptor_interval.as_millis() as u64);
    let mut last_policy_log_ms = 0u64;

    loop {
        interval.tick().await;
        for nat_job in nat_state.take_punch_jobs() {
            let mut success = false;
            let mut selected_addr: Option<String> = None;
            let mut failure_reason: Option<String> = None;
            if let Some(udp_transport) = transports_maint
                .iter()
                .find(|t| t.name().eq_ignore_ascii_case("udp") && t.supports_tunneling())
            {
                let start_after = nat_job.start_after_ms.unwrap_or(0);
                if start_after > 0 {
                    tokio::time::sleep(Duration::from_millis(start_after)).await;
                }
                for candidate in nat_job.remote_candidates.iter() {
                    if !candidate.protocol.eq_ignore_ascii_case("udp") {
                        continue;
                    }
                    let parsed = candidate.addr.parse::<SocketAddr>();
                    let Ok(addr) = parsed else {
                        continue;
                    };
                    let params = TunnelPunchParams {
                        target_ip: addr.ip().to_string(),
                        target_port: addr.port(),
                        timeout_secs: 4,
                    };
                    match udp_transport.punch_tunnel(params).await {
                        Ok(session) => {
                            let session_id = SessionId::from(session.id().to_string());
                            let peer_id = PeerId::from(nat_job.peer_id.as_str());
                            router_maint.register_session(
                                peer_id.clone(),
                                session_id.clone(),
                                session.clone(),
                            );
                            session.spawn_reader(incoming_maint.clone());
                            crate::info!(
                                "[NodeRuntime] NAT tunnel established: peer={} session={} target={}",
                                peer_id,
                                session_id,
                                candidate.addr
                            );
                            success = true;
                            selected_addr = Some(candidate.addr.clone());
                            break;
                        }
                        Err(e) => {
                            failure_reason = Some(e.to_string());
                        }
                    }
                }
            } else {
                failure_reason = Some("UDP transport with tunneling is unavailable".to_string());
            }
            nat_state.mark_result(
                &nat_job.session_id,
                success,
                selected_addr.clone(),
                failure_reason.clone(),
            );
            let result = NetworkControlPayload::NatPunchResult {
                session_id: nat_job.session_id.clone(),
                success,
                selected_addr,
                reason: failure_reason,
            };
            if let Ok(data) = result.encode() {
                let packet = Packet {
                    signature: None,
                    data,
                    nodes: vec![],
                    sender: our_peer_maint.clone(),
                    receiver: nat_job.peer_id.clone(),
                    max_hops: 2,
                    request_id: None,
                    chunk_stream_id: None,
                    chunk_index: None,
                    total_chunks: None,
                };
                let _ = router_maint
                    .send_to_peer(PeerId::from(nat_job.peer_id.as_str()), packet, None)
                    .await;
            }
        }
        let policy = NodeOptions::effective_peer_connection_policy_for(
            policy_live_maint.read().unwrap().clone(),
            node_role,
        )
        .normalized();
        catalog.decay(Duration::from_secs(180));
        catalog.cleanup_expired();
        for (pid, score) in catalog.recalc_scores(&weights) {
            peer_store.insert(pid, score);
        }
        if let Some(ref db) = db {
            let snap = peer_store.snapshot();
            if let Err(e) = db.save_peer_score_snapshot(&snap) {
                crate::warn!("[NodeRuntime] persist peer_scores failed: {}", e);
            }
        }
        if log_peer_scores && crate::logger::is_debug_enabled() {
            let mut rows: Vec<(PeerId, PeerScore)> = peer_store.snapshot();
            rows.sort_by(|a, b| {
                let ta = total_score(&a.1, &weights);
                let tb = total_score(&b.1, &weights);
                tb.partial_cmp(&ta).unwrap_or(std::cmp::Ordering::Equal)
            });
            let summary = rows
                .iter()
                .take(16)
                .map(|(p, s)| {
                    format!(
                        "{}:{:.2}(lat={}ms,ok={:.2})",
                        p.as_str(),
                        total_score(s, &weights),
                        s.latency_ms,
                        s.success_rate
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            if !summary.is_empty() {
                crate::debug!("[NodeRuntime] peer-scores: {}", summary);
            }
        }
        let our_listen_addrs: HashSet<SocketAddr> = listens.iter().map(|r| *r.value()).collect();
        for desc in catalog.descriptors() {
            if desc.peer_id == our_peer_maint {
                continue;
            }
            for addr_s in &desc.observed_addrs {
                let Some((proto, addr)) = parse_observed_addr_line(addr_s) else {
                    continue;
                };
                if addr.ip().is_unspecified() {
                    continue;
                }
                if our_listen_addrs.contains(&addr) {
                    continue;
                }
                if proto != "tcp" && proto != "udp" {
                    continue;
                }
                let mut entry = dial_book
                    .entry(PeerId::from(desc.peer_id.as_str()))
                    .or_default();
                let exists = entry.iter().any(|(t, a)| t == &proto && a == &addr);
                if !exists {
                    entry.push((proto, addr));
                }
            }
        }
        let metrics = MetricsAggregator::aggregate(sm.as_ref(), policy.max_active_peers.max(8));
        let mut n = metrics.node.active_peers as usize;
        let budget = CapacityBudget {
            active_sessions: metrics.node.active_connections as usize,
            max_sessions: policy.max_active_peers.max(8),
            hard_ceiling_connections: policy.max_active_peers.max(16) * 4,
            cpu_load: metrics.node.cpu_load_estimate,
            memory_pressure: metrics.node.memory_pressure_estimate,
            ..CapacityBudget::default()
        };
        let adaptive = budget.recommend_policy(&policy);
        let now = now_ms();
        let known_peers = catalog.known_peer_ids().len().max(1);
        let self_capacity_factor = capacity_target_factor(
            metrics.node.cpu_load_estimate,
            metrics.node.memory_pressure_estimate,
            policy.max_active_peers.min(u16::MAX as usize) as u16,
        );
        let auto_target_regular =
            regular_auto_dial_target(known_peers, &topology_tuning, self_capacity_factor);
        if n > adaptive.max_active_peers {
            let drop_n = n.saturating_sub(adaptive.max_active_peers);
            let connected = router_maint.connected_peers();
            let to_drop = peers_to_drop_when_overloaded(
                connected,
                drop_n,
                catalog.as_ref(),
                peer_store.as_ref(),
                &weights,
                node_role,
            );
            for pid in to_drop {
                catalog.observe_failure(&pid);
                dial_cooldown_until.insert(
                    pid.clone(),
                    now.saturating_add(topology_tuning.prune_redial_cooldown_ms),
                );
                let _ = sm.close_all_sessions_for_peer(&pid).await;
            }
            n = sm.distinct_peer_count();
        }
        let mut desired = adaptive
            .target_active_peers
            .max(adaptive.min_active_peers)
            .min(adaptive.max_active_peers);
        if matches!(node_role, NodeRole::Regular) {
            desired = desired.min(auto_target_regular);
        }
        let reserve_slots = dial_reserve_slots(node_role);
        let dial_target_base = desired
            .saturating_sub(reserve_slots)
            .max(adaptive.min_active_peers);
        let connected_snapshot_for_policy = router_maint.connected_peers();
        let connected_bootstrap_now = connected_snapshot_for_policy
            .iter()
            .filter(|p| catalog.peer_is_bootstrap_entry(p))
            .count();
        let connected_non_bootstrap_now = connected_snapshot_for_policy
            .len()
            .saturating_sub(connected_bootstrap_now);
        let phase = classify_topology_phase(
            known_peers,
            n,
            connected_non_bootstrap_now,
            dial_target_base,
        );
        let adaptive_tick =
            adaptive_tick_policy(&topology_tuning, dial_target_base, phase, known_peers);
        let dial_target = adaptive_tick.dial_target.max(adaptive.min_active_peers);
        let dial_target_low = adaptive_tick.dial_target_low.max(adaptive.min_active_peers);
        let dial_target_high = adaptive_tick.dial_target_high.max(dial_target_low);
        let low_connectivity_reseed = should_reseed_bootstrap(
            n,
            adaptive.min_active_peers,
            connected_bootstrap_now,
            now,
            last_bootstrap_reseed_ms,
        );
        let stable_bootstrap_guard = stable_bootstrap_reseed_guard(
            &topology_tuning,
            node_role,
            n,
            adaptive.min_active_peers,
            known_peers,
            bootstrap_targets_maint.len(),
            connected_bootstrap_now,
        );
        let missing_bootstrap_bridge = matches!(node_role, NodeRole::Regular)
                && connected_bootstrap_now == 0
                // bridge-rejoin нужен только при тонком каталоге/дефиците mesh,
                // а не в steady-state, иначе regular'ы снова прилипают к bootstrap.
                && (n < desired
                    || known_peers < topology_tuning.bootstrap_stable_peer_threshold.saturating_add(2)
                    || !matches!(phase, TopologyPhase::Steady))
                && now.saturating_sub(last_bootstrap_reseed_ms)
                    >= adaptive_tick.bridge_rejoin_cooldown_ms;
        let reseed_for_low = !stable_bootstrap_guard && low_connectivity_reseed;
        let reseed_for_bridge = missing_bootstrap_bridge;
        if !bootstrap_targets_maint.is_empty() && (reseed_for_low || reseed_for_bridge) {
            crate::debug!(
                "[NodeRuntime] bootstrap reseed: active={} min={} boot-connected={} targets={} reason={}",
                n,
                adaptive.min_active_peers,
                connected_bootstrap_now,
                bootstrap_targets_maint.len(),
                if reseed_for_low {
                    "low-connectivity"
                } else {
                    "bridge-rejoin"
                }
            );
            let max_reseed_targets = if reseed_for_low {
                bootstrap_targets_maint.len()
            } else {
                1
            };
            let ranked_targets =
                rank_bootstrap_targets_for_peer(&our_peer_maint, &bootstrap_targets_maint);
            let mut attempted = 0usize;
            let top_k = topology_tuning
                .adaptive_bootstrap_top_k
                .max(1)
                .min(ranked_targets.len());
            for target in ranked_targets.into_iter().take(top_k) {
                if attempted >= max_reseed_targets {
                    break;
                }
                if bootstrap_deny_until
                    .get(&target.addr)
                    .is_some_and(|until| now < *until)
                {
                    continue;
                }
                attempted = attempted.saturating_add(1);
                let ok = dial_bootstrap_address(
                    &transports_maint,
                    &router_maint,
                    &incoming_maint,
                    &our_peer_maint,
                    &target,
                    &maintenance_handshake_payload,
                )
                .await;
                if ok {
                    bootstrap_deny_until.remove(&target.addr);
                } else {
                    bootstrap_deny_until.insert(
                        target.addr,
                        now.saturating_add(adaptive_tick.bridge_rejoin_cooldown_ms),
                    );
                }
            }
            last_bootstrap_reseed_ms = now;
            n = sm.distinct_peer_count();
        }
        let mut max_allowed = adaptive.max_active_peers;
        if matches!(node_role, NodeRole::Regular) {
            max_allowed = max_allowed.min(desired.saturating_add(REGULAR_MAX_HEADROOM));
        }
        if n > max_allowed {
            let drop_n = n.saturating_sub(max_allowed);
            let connected = router_maint.connected_peers();
            let to_drop = peers_to_drop_when_overloaded(
                connected,
                drop_n,
                catalog.as_ref(),
                peer_store.as_ref(),
                &weights,
                node_role,
            );
            for pid in to_drop {
                catalog.observe_failure(&pid);
                dial_cooldown_until.insert(
                    pid.clone(),
                    now.saturating_add(topology_tuning.prune_redial_cooldown_ms),
                );
                let _ = sm.close_all_sessions_for_peer(&pid).await;
            }
            n = sm.distinct_peer_count();
        }
        if matches!(node_role, NodeRole::Regular) && n > dial_target_high {
            let drop_n = n.saturating_sub(dial_target);
            let connected = router_maint.connected_peers();
            let to_drop = peers_to_drop_when_overloaded(
                connected,
                drop_n,
                catalog.as_ref(),
                peer_store.as_ref(),
                &weights,
                node_role,
            );
            if !to_drop.is_empty() {
                crate::info!(
                    "[NodeRuntime] pruning {} peer(s) to stay near desired={} (current={})",
                    to_drop.len(),
                    desired,
                    n
                );
            }
            for pid in to_drop {
                catalog.observe_failure(&pid);
                dial_cooldown_until.insert(
                    pid.clone(),
                    now.saturating_add(topology_tuning.prune_redial_cooldown_ms),
                );
                let _ = sm.close_all_sessions_for_peer(&pid).await;
            }
            n = sm.distinct_peer_count();
        }
        let selective = connectivity_selective(n, dial_target, adaptive.min_active_peers);
        // Exploration только на нижней границе гистерезиса: иначе при
        // n ∈ [low, high) каждые N секунд узел снова дозванивается и
        // граф «ползёт» вверх по числу рёбер без стабилизации.
        let should_explore = matches!(node_role, NodeRole::Regular)
            && n == dial_target_low
            && now.saturating_sub(last_exploration_ms) >= adaptive_tick.exploration_interval_ms;
        if now.saturating_sub(last_policy_log_ms) >= 15_000 {
            crate::debug!(
                "[NodeRuntime] policy snapshot: phase={:?} known={} active={} non_boot={} target={} range=[{},{}] explore_ms={} rejoin_ms={} boot_hard={} explore_slots={}",
                phase,
                known_peers,
                n,
                connected_non_bootstrap_now,
                dial_target,
                dial_target_low,
                dial_target_high,
                adaptive_tick.exploration_interval_ms,
                adaptive_tick.bridge_rejoin_cooldown_ms,
                adaptive_tick.bootstrap_hard_limit,
                adaptive_tick.exploratory_slots
            );
            last_policy_log_ms = now;
        }
        if n < dial_target_low || should_explore {
            let req = NetworkControlPayload::RequestPeers { limit: 48 };
            if let Ok(data) = req.encode() {
                for p in router_maint.connected_peers() {
                    let packet = Packet {
                        signature: None,
                        data: data.clone(),
                        nodes: vec![],
                        sender: our_peer_maint.clone(),
                        receiver: p.as_str().to_string(),
                        max_hops: 2,
                        request_id: None,
                        chunk_stream_id: None,
                        chunk_index: None,
                        total_chunks: None,
                    };
                    let _ = router_maint.send_to_peer(p, packet, None).await;
                }
            }
            let mut candidates: Vec<PeerId> = dial_book.iter().map(|r| r.key().clone()).collect();
            let desc_by_peer: HashMap<PeerId, NodeDescriptor> = catalog
                .descriptors()
                .into_iter()
                .map(|d| (PeerId::from(d.peer_id.as_str()), d))
                .collect();
            let stale_descriptor_cutoff_ms = now.saturating_sub(90_000);
            candidates.retain(|pid| {
                desc_by_peer
                    .get(pid)
                    .map(|d| d.timestamp_ms >= stale_descriptor_cutoff_ms)
                    .unwrap_or(true)
            });
            let connected_snapshot = router_maint.connected_peers();
            let mut connected_bootstrap = connected_snapshot
                .iter()
                .filter(|p| catalog.peer_is_bootstrap_entry(p))
                .count();
            let connected_non_bootstrap =
                connected_snapshot.len().saturating_sub(connected_bootstrap);
            let target_non_bootstrap = if matches!(node_role, NodeRole::Regular) {
                desired.saturating_sub(topology_tuning.regular_bootstrap_min_keep)
            } else {
                0
            };
            let force_non_bootstrap = matches!(node_role, NodeRole::Regular)
                && connected_bootstrap > 0
                && connected_non_bootstrap < target_non_bootstrap;
            let bootstrap_quota = bootstrap_dial_quota(node_role);
            let connected_prefix24: HashSet<[u8; 3]> = connected_snapshot
                .iter()
                .filter_map(|pid| catalog.descriptor_of(pid))
                .filter_map(|d| descriptor_prefix24(&d))
                .collect();
            rank_dial_candidates(
                &mut candidates,
                peer_store.as_ref(),
                &weights,
                &desc_by_peer,
                &our_peer_maint,
                node_role,
                dial_target,
                connected_bootstrap,
                bootstrap_quota,
                true,
                n,
                adaptive.min_active_peers,
                &connected_prefix24,
                known_peers,
                adaptive_tick.exploratory_slots,
            );
            let dial_limit = if should_explore {
                dial_target_high
            } else if force_non_bootstrap {
                // Allow one temporary extra link to pull regular nodes away from bootstrap hubs.
                dial_target_high
            } else {
                dial_target
            };
            let dial_deficit = dial_limit.saturating_sub(n).max(1);
            let mut dial_attempts_left = if matches!(node_role, NodeRole::Regular) {
                dial_deficit.min(REGULAR_DIAL_ATTEMPT_BUDGET_MAX)
            } else {
                dial_deficit.min(BOOTSTRAP_DIAL_ATTEMPT_BUDGET_MAX)
            };
            let mut dialed_any = false;
            for pid in candidates {
                if n >= dial_limit {
                    break;
                }
                if dial_attempts_left == 0 {
                    break;
                }
                if pid.as_str() == our_peer_maint.as_str() {
                    continue;
                }
                if sm.is_connected_to_peer(&pid) {
                    continue;
                }
                if let Some(until) = dial_cooldown_until.get(&pid).copied() {
                    if now < until {
                        continue;
                    }
                }
                if let Some(desc) = desc_by_peer.get(&pid) {
                    if force_non_bootstrap && desc.capabilities.bootstrap_entry {
                        continue;
                    }
                    if should_skip_for_bootstrap_quota(
                        desc,
                        node_role,
                        connected_bootstrap,
                        bootstrap_quota,
                        n,
                        adaptive.min_active_peers,
                    ) {
                        continue;
                    }
                    if !desc.capabilities.bootstrap_entry {
                        if selective && !desc.dynamic_status.accepts_new_sessions {
                            continue;
                        }
                        let cap = desc.capabilities.base_session_limit.max(1) as usize;
                        if selective
                            && n >= REGULAR_SELF_HEAL_FLOOR
                            && desc.dynamic_status.active_connections as usize >= cap
                        {
                            continue;
                        }
                        let soft_cap = dial_target.saturating_add(DIAL_HUB_SOFT_CAP_EXTRA);
                        if selective
                            && n >= REGULAR_SELF_HEAL_FLOOR
                            && desc.dynamic_status.active_connections as usize > soft_cap
                        {
                            continue;
                        }
                    }
                }
                let Some(entry) = dial_book.get(&pid) else {
                    continue;
                };
                let addr_count = entry.value().len();
                let max_endpoints = dial_endpoint_attempt_budget(
                    n,
                    dial_target,
                    adaptive.min_active_peers,
                    addr_count,
                );
                let mut tried_endpoints: HashSet<(String, SocketAddr)> = HashSet::new();
                let mut endpoint_attempts = 0usize;
                for (transport_name, addr) in entry.value().iter() {
                    if endpoint_attempts >= max_endpoints {
                        break;
                    }
                    if !tried_endpoints.insert((transport_name.clone(), *addr)) {
                        continue;
                    }
                    if let Some(t) = transports_maint
                        .iter()
                        .find(|t| t.name() == transport_name.as_str())
                    {
                        if !t.is_listener() {
                            continue;
                        }
                        endpoint_attempts = endpoint_attempts.saturating_add(1);
                        dial_attempts_left = dial_attempts_left.saturating_sub(1);
                        match t.dial(*addr).await {
                            Ok(session) => {
                                let session_id = SessionId::from(session.id().to_string());
                                router_maint.register_session(
                                    pid.clone(),
                                    session_id.clone(),
                                    session.clone(),
                                );
                                session.spawn_reader(incoming_maint.clone());
                                let handshake = Packet {
                                    signature: None,
                                    data: maintenance_handshake_payload.clone(),
                                    nodes: vec![],
                                    sender: our_peer_maint.clone(),
                                    receiver: String::new(),
                                    max_hops: 8,
                                    request_id: None,
                                    chunk_stream_id: None,
                                    chunk_index: None,
                                    total_chunks: None,
                                };
                                let _ = router_maint.send_to_session(session_id, handshake).await;
                                catalog.observe_success(&pid, 80);
                                if desc_by_peer
                                    .get(&pid)
                                    .is_some_and(|d| d.capabilities.bootstrap_entry)
                                {
                                    connected_bootstrap = connected_bootstrap.saturating_add(1);
                                }
                                dial_cooldown_until.remove(&pid);
                                dialed_any = true;
                                n = sm.distinct_peer_count();
                                break;
                            }
                            Err(_) => {
                                catalog.observe_failure(&pid);
                                dial_cooldown_until.insert(
                                    pid.clone(),
                                    now.saturating_add(topology_tuning.dial_retry_cooldown_ms),
                                );
                            }
                        }
                    }
                }
            }
            if should_explore && dialed_any {
                last_exploration_ms = now;
            }
        }
        if matches!(node_role, NodeRole::Regular) {
            let min_keep = adaptive.min_active_peers;
            let desired_keep = desired;
            let connected = router_maint.connected_peers();
            let non_boot = connected
                .iter()
                .filter(|p| !catalog.peer_is_bootstrap_entry(p))
                .count();
            // Ослабленное условие: как только регуляр набрал min_active_peers
            // non-bootstrap соседей, начинаем отпускать bootstrap'ы, а не ждём
            // полного desired_keep. Это ускоряет миграцию из hub-фазы в mesh.
            if non_boot >= min_keep.max(1) {
                let mut boot_peers: Vec<_> = connected
                    .into_iter()
                    .filter(|p| catalog.peer_is_bootstrap_entry(&p))
                    .collect();
                let connected_bootstrap = boot_peers.len();
                if connected_bootstrap > topology_tuning.regular_bootstrap_min_keep {
                    boot_peers.sort_by(|a, b| {
                        let ta = total_score(&peer_store.get(a), &weights);
                        let tb = total_score(&peer_store.get(b), &weights);
                        ta.partial_cmp(&tb).unwrap_or(std::cmp::Ordering::Equal)
                    });
                    let max_bootstrap_drop = connected_bootstrap
                        .saturating_sub(topology_tuning.regular_bootstrap_min_keep);
                    // Раньше: `n - desired_keep` → ждём пока n доберётся до desired.
                    // Теперь: как только mesh ≥ min_keep, агрессивно отпускаем все
                    // bootstrap сверх regular_bootstrap_min_keep.
                    let drop_n = max_bootstrap_drop;
                    if drop_n > 0 {
                        crate::info!(
                            "[NodeRuntime] shedding {} bootstrap_entry peer(s); {} non-bootstrap neighbor(s) (min_keep={}, desired={}, bootstrap_keep={})",
                            drop_n,
                            non_boot,
                            min_keep,
                            desired_keep,
                            topology_tuning.regular_bootstrap_min_keep
                        );
                    }
                    for pid in boot_peers.into_iter().take(drop_n) {
                        catalog.observe_failure(&pid);
                        // После целевого offload не даём тут же перецепиться
                        // обратно на bootstrap.
                        dial_cooldown_until.insert(
                            pid.clone(),
                            now.saturating_add(
                                topology_tuning
                                    .regular_bootstrap_rejoin_interval_ms
                                    .saturating_mul(2),
                            ),
                        );
                        let _ = sm.close_all_sessions_for_peer(&pid).await;
                    }
                }
            }
        }
        n = sm.distinct_peer_count();
        let now = now_ms();

        // Bootstrap shepherd: закрываем сессии с peer'ами, которые уже
        // устоялись в mesh (>= SHEPHERD_MIN_MESH regular-соседей). Это
        // вытесняет bootstrap из hub-роли в steady state, не оставляя
        // ничего «навсегда» прикреплённым.
        if matches!(node_role, NodeRole::BootstrapJoin)
            && now.saturating_sub(last_shepherd_sweep_ms) >= SHEPHERD_SWEEP_INTERVAL_MS
        {
            let connected = router_maint.connected_peers();
            for pid in connected.iter() {
                peer_admission_ms.entry(pid.clone()).or_insert(now);
            }
            let tracked: Vec<PeerId> = peer_admission_ms.keys().cloned().collect();
            for pid in tracked {
                if !sm.is_connected_to_peer(&pid) {
                    peer_admission_ms.remove(&pid);
                }
            }
            let mut shepherded = 0usize;
            for pid in connected.iter() {
                // Не трогаем сессии к другим bootstrap — они часть
                // межбутстрапной связности.
                if catalog.peer_is_bootstrap_entry(pid) {
                    continue;
                }
                let Some(admitted_at) = peer_admission_ms.get(pid).copied() else {
                    continue;
                };
                if now.saturating_sub(admitted_at) < SHEPHERD_GRACE_MS {
                    continue;
                }
                let Some(desc) = catalog.descriptor_of(pid) else {
                    continue;
                };
                // У newcomer'а в дескрипторе active_connections включает
                // связь с нами; нас интересует, есть ли у него mesh
                // ПОМИМО нас: AC-1 ≥ SHEPHERD_MIN_MESH.
                let peer_mesh_size = desc.dynamic_status.active_connections.saturating_sub(1);
                if peer_mesh_size < SHEPHERD_MIN_MESH {
                    continue;
                }
                // Финальный PeersResponse: дадим ему ещё top-N
                // regular-дескрипторов, чтобы заменить нашу связь.
                let descriptors = select_peers_for_discovery_response(
                    catalog
                        .descriptors()
                        .into_iter()
                        .filter(|d| d.peer_id != pid.as_str())
                        .filter(|d| descriptor_ok_for_discovery_redirect(d))
                        .collect(),
                    Some(pid.as_str()),
                    SHEPHERD_FINAL_PEERS_LIMIT,
                    0.4,
                );
                if !descriptors.is_empty() {
                    let msg = NetworkControlPayload::PeersResponse { descriptors };
                    if let Ok(data) = msg.encode() {
                        let packet = Packet {
                            signature: None,
                            data,
                            nodes: vec![],
                            sender: our_peer_maint.clone(),
                            receiver: pid.as_str().to_string(),
                            max_hops: 2,
                            request_id: None,
                            chunk_stream_id: None,
                            chunk_index: None,
                            total_chunks: None,
                        };
                        let _ = router_maint.send_to_peer(pid.clone(), packet, None).await;
                    }
                }
                let _ = sm.close_all_sessions_for_peer(pid).await;
                peer_admission_ms.remove(pid);
                shepherded += 1;
            }
            if shepherded > 0 {
                crate::info!(
                    "[NodeRuntime] shepherd sweep: closed {} settled peer(s) to free bootstrap slot",
                    shepherded
                );
                n = sm.distinct_peer_count();
            }
            last_shepherd_sweep_ms = now;
        }

        if now.saturating_sub(last_publish) >= descriptor_interval.as_millis() as u64 {
            let version = descriptor_ver.fetch_add(1, Ordering::Relaxed) + 1;
            let mut srflx_by_proto: HashMap<String, SocketAddr> = HashMap::new();
            for transport in &transports_maint {
                if !transport.supports_tunneling() {
                    continue;
                }
                let proto = transport.name().to_string();
                let Some(listen_addr) = listens.get(&proto).map(|r| *r.value()) else {
                    continue;
                };
                match transport.get_public_address(listen_addr.port()).await {
                    Ok(public) => {
                        if let Ok(ip) = public.ip.parse::<IpAddr>() {
                            srflx_by_proto.insert(proto, SocketAddr::new(ip, public.port));
                        }
                    }
                    Err(e) => {
                        crate::debug!(
                            "[NodeRuntime] STUN unavailable for {}:{}: {}",
                            proto,
                            listen_addr.port(),
                            e
                        );
                    }
                }
            }
            let mut proto_list: Vec<(String, SocketAddr)> = listens
                .iter()
                .map(|r| {
                    let proto = r.key().clone();
                    let advertised = advertised_addr_for_protocol(
                        &proto,
                        *r.value(),
                        &advertise_addrs,
                        advertise_fallback_ip,
                    );
                    (proto, advertised)
                })
                .collect();
            proto_list.sort_by(|a, b| a.0.cmp(&b.0));
            let mut observed_addrs: Vec<String> = proto_list
                .into_iter()
                .map(|(p, a)| format!("{}:{}", p.to_lowercase(), a))
                .collect();
            for (proto, addr) in srflx_by_proto {
                observed_addrs.push(format!("{}:{}", proto.to_lowercase(), addr));
            }
            observed_addrs.sort();
            observed_addrs.dedup();
            let mut caps = NodeCapabilities::default();
            if matches!(node_role, NodeRole::BootstrapJoin) {
                caps.bootstrap_entry = true;
            }
            // Capacity-aware self-limit: при нагрузке > 0.5 линейно сжимаем
            // публикуемую ёмкость (до min 30% от политики). Другие узлы
            // видят меньший `base_session_limit` → меньше дозваниваются к
            // нам → естественное backpressure без явного handshake.
            let base_cap = adaptive
                .max_active_peers
                .max(caps.base_session_limit as usize)
                .min(u16::MAX as usize) as u16;
            let load = metrics
                .node
                .cpu_load_estimate
                .max(metrics.node.memory_pressure_estimate)
                .clamp(0.0, 1.0);
            let pressure_factor = (1.0 - ((load - 0.5).max(0.0) * 2.0)).clamp(0.3, 1.0);
            let effective_cap = (((base_cap as f32) * pressure_factor).round() as u16).max(4);
            caps.base_session_limit = effective_cap;
            let descriptor = NodeDescriptor::new_unsigned(
                our_peer_maint.clone(),
                caps,
                {
                    let mut s = NodeDynamicStatus::from(&metrics.node);
                    s.accepts_new_sessions =
                        n < adaptive.max_active_peers && pressure_factor >= 0.5;
                    s
                },
                observed_addrs,
                descriptor_ttl_secs,
                version,
            );
            let mut descriptor = descriptor;
            if sign_descriptor(&mut descriptor, &signing_key).is_ok() {
                let _ = catalog.upsert_descriptor(descriptor.clone());
                if let Some(db) = db.as_ref() {
                    let _ = db.upsert_peer_descriptor(&descriptor);
                }
                let msg = NetworkControlPayload::AnnounceNodeDescriptor { descriptor };
                if let Ok(data) = msg.encode() {
                    for p in router_maint.connected_peers() {
                        let packet = Packet {
                            signature: None,
                            data: data.clone(),
                            nodes: vec![],
                            sender: our_peer_maint.clone(),
                            receiver: p.as_str().to_string(),
                            max_hops: 2,
                            request_id: None,
                            chunk_stream_id: None,
                            chunk_index: None,
                            total_chunks: None,
                        };
                        let _ = router_maint.send_to_peer(p, packet, None).await;
                    }
                }
            }
            last_publish = now;
        }
    }
}
