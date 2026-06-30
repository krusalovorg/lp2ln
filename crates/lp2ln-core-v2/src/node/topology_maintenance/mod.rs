use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use dashmap::DashMap;
use tokio_util::sync::CancellationToken;

mod bootstrap;
mod descriptor;
mod dialing;
mod packet_helpers;
mod policy;
mod state;

use self::policy::compute_policy_snapshot;
use self::state::MaintenanceState;
use crate::db::P2PDatabase;
use crate::metrics::MetricsAggregator;
use crate::node::distribution::{
    capacity_target_factor, dial_reserve_slots, peers_to_drop_when_overloaded,
    regular_auto_dial_target,
};
use crate::node::nat_traversal::NatTraversalState;
use crate::node::options::{BootstrapNode, NodeOptions, NodeRole, TopologyTuning};
use crate::peer_score::{
    PeerConnectionPolicy, PeerScore, PeerScoreStore, PeerScoreWeights, total_score,
};
use crate::protocol::control::NetworkControlPayload;
use crate::router::Router;
use crate::sessions::manager::SessionManager;
use crate::sessions::session::IncomingPacket;
use crate::topology::{CapacityBudget, PeerCatalog, now_ms, parse_observed_addr_line};
use crate::transport::{Transport, TunnelPunchParams};
use crate::types::{PeerId, SessionId};
use bootstrap::{handle_bootstrap_reseed, run_bootstrap_shepherd};
use descriptor::publish_descriptor_if_due;
use dialing::{build_dial_plan, execute_dial_plan};
use packet_helpers::{control_packet, handshake_packet, observe_failure_and_close};

#[derive(Clone)]
pub(crate) struct BootstrapDialDedupe {
    pub active_peers: usize,
    pub set: Arc<Mutex<HashSet<(String, SocketAddr)>>>,
}

fn effective_bootstrap_connected_count(
    connected: &[PeerId],
    catalog: &PeerCatalog,
    bootstrap_targets: &[BootstrapNode],
    dial_book: &DashMap<PeerId, Vec<(String, SocketAddr)>>,
    bootstrap_dial_ok_ms: &HashMap<SocketAddr, u64>,
    now: u64,
) -> usize {
    let mut seen: HashSet<PeerId> = HashSet::new();
    for p in connected {
        if catalog.peer_is_bootstrap_entry(p) {
            seen.insert(p.clone());
            continue;
        }
        if let Some(desc) = catalog.descriptor_of(p) {
            if bootstrap_targets
                .iter()
                .any(|t| descriptor_announces_bootstrap_target(&desc, t))
            {
                seen.insert(p.clone());
                continue;
            }
        }
        if let Some(entry) = dial_book.get(p) {
            let hinted = bootstrap_targets
                .iter()
                .any(|t| t.peer_id_hint.as_ref() == Some(p));
            let addr_match = bootstrap_targets.iter().any(|t| {
                entry.value().iter().any(|(proto, addr)| {
                    *addr == t.addr
                        && (t.protocols.is_empty()
                            || t.protocols.iter().any(|tp| tp.eq_ignore_ascii_case(proto)))
                })
            });
            if hinted || addr_match {
                seen.insert(p.clone());
            }
        }
    }
    if !seen.is_empty() {
        return seen.len();
    }
    let any_recent_dial = bootstrap_targets.iter().any(|t| {
        bootstrap_dial_ok_ms
            .get(&t.addr)
            .copied()
            .map(|ts| now.saturating_sub(ts) < BOOTSTRAP_DIAL_OK_TTL_MS)
            .unwrap_or(false)
    });
    if any_recent_dial { 1 } else { 0 }
}

fn descriptor_announces_bootstrap_target(
    desc: &crate::topology::NodeDescriptor,
    t: &BootstrapNode,
) -> bool {
    desc.observed_addrs.iter().any(|line| {
        parse_observed_addr_line(line).is_some_and(|(proto, addr)| {
            addr == t.addr
                && (t.protocols.is_empty()
                    || t.protocols.iter().any(|tp| tp.eq_ignore_ascii_case(&proto)))
        })
    })
}

const MAINTENANCE_INTERVAL_SECS: u64 = 5;
const MAINTENANCE_START_JITTER_MS: u64 = 3_000;
const REGULAR_MAX_HEADROOM: usize = 2;
pub(super) const REGULAR_DIAL_ATTEMPT_BUDGET_MAX: usize = 8;
pub(super) const BOOTSTRAP_DIAL_ATTEMPT_BUDGET_MAX: usize = 8;
pub(super) const SHEPHERD_SWEEP_INTERVAL_MS: u64 = 10_000;
pub(super) const SHEPHERD_MIN_MESH: u16 = 3;
pub(super) const SHEPHERD_GRACE_MS: u64 = 15_000;
pub(super) const SHEPHERD_FINAL_PEERS_LIMIT: usize = 24;
pub(super) const SHEPHERD_SKIP_IF_CONNECTED_AT_MOST: usize = 6;

pub(super) const BOOTSTRAP_DIAL_OK_TTL_MS: u64 = 120_000;

pub(crate) async fn dial_bootstrap_address(
    transports: &[Arc<dyn Transport>],
    router: &Arc<Router>,
    incoming_packets_tx: &tokio::sync::mpsc::Sender<IncomingPacket>,
    our_peer_id: &str,
    target: &BootstrapNode,
    handshake_payload: &[u8],
    dedupe: Option<&BootstrapDialDedupe>,
    record_dial_ok: Option<(&Arc<Mutex<HashMap<SocketAddr, u64>>>, u64)>,
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
        let transport_name = transport.name().to_string();
        let key = (transport_name.clone(), target.addr);
        if let Some(d) = dedupe {
            if d.active_peers > 0 && d.set.lock().unwrap().contains(&key) {
                if let Some((m, ts)) = record_dial_ok {
                    m.lock().unwrap().insert(target.addr, ts);
                }
                return true;
            }
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
                let handshake = handshake_packet(our_peer_id, handshake_payload);
                if let Err(e) = router.send_to_session(session_id, handshake).await {
                    crate::error!(
                        "[NodeRuntime] Failed to send handshake to {}: {}",
                        target.addr,
                        e
                    );
                    return false;
                }
                if let Some(d) = dedupe {
                    d.set.lock().unwrap().insert(key);
                }
                if let Some((m, ts)) = record_dial_ok {
                    m.lock().unwrap().insert(target.addr, ts);
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

struct TopologyMaintenanceCtx<'a> {
    transports_maint: &'a [Arc<dyn Transport>],
    router_maint: &'a Arc<Router>,
    incoming_maint: &'a tokio::sync::mpsc::Sender<IncomingPacket>,
    our_peer_maint: &'a str,
    nat_state: &'a Arc<NatTraversalState>,
    catalog: &'a Arc<PeerCatalog>,
    peer_store: &'a Arc<PeerScoreStore>,
    db: &'a Option<Arc<P2PDatabase>>,
    weights: &'a PeerScoreWeights,
    log_peer_scores: bool,
    listens: &'a DashMap<String, SocketAddr>,
    dial_book: &'a Arc<DashMap<PeerId, Vec<(String, SocketAddr)>>>,
}

async fn process_nat_jobs(ctx: &TopologyMaintenanceCtx<'_>, cancel: &CancellationToken) {
    for nat_job in ctx.nat_state.take_punch_jobs() {
        if cancel.is_cancelled() {
            return;
        }
        let mut success = false;
        let mut selected_addr: Option<String> = None;
        let mut failure_reason: Option<String> = None;
        if let Some(udp_transport) = ctx
            .transports_maint
            .iter()
            .find(|t| t.name().eq_ignore_ascii_case("udp") && t.supports_tunneling())
        {
            let start_after = nat_job.start_after_ms.unwrap_or(0);
            if start_after > 0 {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_millis(start_after)) => {}
                }
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
                        ctx.router_maint.register_session(
                            peer_id.clone(),
                            session_id.clone(),
                            session.clone(),
                        );
                        session.spawn_reader(ctx.incoming_maint.clone());
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
        ctx.nat_state.mark_result(
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
            let packet = control_packet(ctx.our_peer_maint, nat_job.peer_id.clone(), data, 2);
            let _ = ctx
                .router_maint
                .send_to_peer(PeerId::from(nat_job.peer_id.as_str()), packet, None)
                .await;
        }
    }
}

fn refresh_scores(ctx: &TopologyMaintenanceCtx<'_>) {
    ctx.catalog.decay(Duration::from_secs(180));
    ctx.catalog.cleanup_expired();
    for (pid, score) in ctx.catalog.recalc_scores(ctx.weights) {
        ctx.peer_store.insert(pid, score);
    }
    if let Some(db) = ctx.db {
        let snap = ctx.peer_store.snapshot();
        if let Err(e) = db.save_peer_score_snapshot(&snap) {
            crate::warn!("[NodeRuntime] persist peer_scores failed: {}", e);
        }
    }
    if ctx.log_peer_scores && crate::logger::is_debug_enabled() {
        let mut rows: Vec<(PeerId, PeerScore)> = ctx.peer_store.snapshot();
        rows.sort_by(|a, b| {
            let ta = total_score(&a.1, ctx.weights);
            let tb = total_score(&b.1, ctx.weights);
            tb.partial_cmp(&ta).unwrap_or(std::cmp::Ordering::Equal)
        });
        let summary = rows
            .iter()
            .take(16)
            .map(|(p, s)| {
                format!(
                    "{}:{:.2}(lat={}ms,ok={:.2})",
                    p.as_str(),
                    total_score(s, ctx.weights),
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
}

fn sync_dial_book(ctx: &TopologyMaintenanceCtx<'_>) {
    let our_listen_addrs: HashSet<SocketAddr> = ctx.listens.iter().map(|r| *r.value()).collect();
    for desc in ctx.catalog.descriptors() {
        if desc.peer_id == ctx.our_peer_maint {
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
            let mut entry = ctx
                .dial_book
                .entry(PeerId::from(desc.peer_id.as_str()))
                .or_default();
            let exists = entry.iter().any(|(t, a)| t == &proto && a == &addr);
            if !exists {
                entry.push((proto, addr));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_topology_maintenance_loop(
    cancel: CancellationToken,
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
    bootstrap_dial_dedupe: Arc<Mutex<HashSet<(String, SocketAddr)>>>,
    bootstrap_dial_ok_ms: Arc<Mutex<HashMap<SocketAddr, u64>>>,
) -> anyhow::Result<()> {
    let initial_jitter = (our_peer_maint
        .bytes()
        .fold(0u64, |acc, b| acc.wrapping_add(b as u64))
        % MAINTENANCE_START_JITTER_MS)
        + 1;
    tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        _ = tokio::time::sleep(Duration::from_millis(initial_jitter)) => {}
    }
    let mut interval = tokio::time::interval(Duration::from_secs(MAINTENANCE_INTERVAL_SECS));
    let descriptor_ttl_secs = 120u64;
    let descriptor_interval = Duration::from_secs(30);
    let mut state = MaintenanceState::new(descriptor_interval, now_ms());
    let loop_ctx = TopologyMaintenanceCtx {
        transports_maint: &transports_maint,
        router_maint: &router_maint,
        incoming_maint: &incoming_maint,
        our_peer_maint: &our_peer_maint,
        nat_state: &nat_state,
        catalog: &catalog,
        peer_store: &peer_store,
        db: &db,
        weights: &weights,
        log_peer_scores,
        listens: &listens,
        dial_book: &dial_book,
    };

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {}
        }
        process_nat_jobs(&loop_ctx, &cancel).await;
        if cancel.is_cancelled() {
            return Ok(());
        }
        let policy = NodeOptions::effective_peer_connection_policy_for(
            policy_live_maint.read().unwrap().clone(),
            node_role,
        )
        .normalized();
        refresh_scores(&loop_ctx);
        sync_dial_book(&loop_ctx);
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
                observe_failure_and_close(
                    &catalog,
                    &sm,
                    &mut state.dial_cooldown_until,
                    &pid,
                    now.saturating_add(topology_tuning.prune_redial_cooldown_ms),
                )
                .await;
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
        {
            let mut g = bootstrap_dial_ok_ms.lock().unwrap();
            g.retain(|_, ts| now.saturating_sub(*ts) < BOOTSTRAP_DIAL_OK_TTL_MS);
        }
        let dial_ok_snap = bootstrap_dial_ok_ms.lock().unwrap().clone();
        let connected_bootstrap_now = effective_bootstrap_connected_count(
            &connected_snapshot_for_policy,
            catalog.as_ref(),
            &bootstrap_targets_maint,
            dial_book.as_ref(),
            &dial_ok_snap,
            now,
        );
        let connected_non_bootstrap_now = connected_snapshot_for_policy
            .len()
            .saturating_sub(connected_bootstrap_now);
        let policy_snapshot = compute_policy_snapshot(
            &topology_tuning,
            node_role,
            known_peers,
            n,
            connected_bootstrap_now,
            connected_non_bootstrap_now,
            dial_target_base,
            desired,
            adaptive.min_active_peers,
            bootstrap_targets_maint.len(),
            state.last_bootstrap_reseed_ms,
            now,
        );
        let phase = policy_snapshot.phase;
        let adaptive_tick = policy_snapshot.adaptive_tick;
        let dial_target = policy_snapshot.dial_target;
        let dial_target_low = policy_snapshot.dial_target_low;
        let dial_target_high = policy_snapshot.dial_target_high;
        let reseed_for_low = policy_snapshot.reseed_for_low;
        let reseed_for_bridge = policy_snapshot.reseed_for_bridge;
        if handle_bootstrap_reseed(
            reseed_for_low,
            reseed_for_bridge,
            n,
            adaptive.min_active_peers,
            connected_bootstrap_now,
            &bootstrap_targets_maint,
            &our_peer_maint,
            &topology_tuning,
            &mut state.bootstrap_deny_until,
            now,
            &adaptive_tick,
            &transports_maint,
            &router_maint,
            &incoming_maint,
            &maintenance_handshake_payload,
            &bootstrap_dial_dedupe,
            &bootstrap_dial_ok_ms,
        )
        .await
        {
            state.last_bootstrap_reseed_ms = now;
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
                observe_failure_and_close(
                    &catalog,
                    &sm,
                    &mut state.dial_cooldown_until,
                    &pid,
                    now.saturating_add(topology_tuning.prune_redial_cooldown_ms),
                )
                .await;
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
                observe_failure_and_close(
                    &catalog,
                    &sm,
                    &mut state.dial_cooldown_until,
                    &pid,
                    now.saturating_add(topology_tuning.prune_redial_cooldown_ms),
                )
                .await;
            }
            n = sm.distinct_peer_count();
        }
        // Exploration только на нижней границе гистерезиса: иначе при
        // n ∈ [low, high) каждые N секунд узел снова дозванивается и
        // граф «ползёт» вверх по числу рёбер без стабилизации.
        let should_explore = matches!(node_role, NodeRole::Regular)
            && n == dial_target_low
            && now.saturating_sub(state.last_exploration_ms)
                >= adaptive_tick.exploration_interval_ms;
        if now.saturating_sub(state.last_policy_log_ms) >= 15_000 {
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
            state.last_policy_log_ms = now;
        }
        if n < dial_target_low || should_explore {
            let req = NetworkControlPayload::RequestPeers { limit: 48 };
            if let Ok(data) = req.encode() {
                for p in router_maint.connected_peers() {
                    let packet =
                        control_packet(&our_peer_maint, p.as_str().to_string(), data.clone(), 2);
                    let _ = router_maint.send_to_peer(p, packet, None).await;
                }
            }
            let mut plan = build_dial_plan(
                &dial_book,
                &router_maint,
                &catalog,
                &peer_store,
                &weights,
                &our_peer_maint,
                node_role,
                known_peers,
                n,
                desired,
                dial_target,
                dial_target_high,
                adaptive.min_active_peers,
                adaptive_tick.exploratory_slots,
                &topology_tuning,
                should_explore,
                now,
            );
            let exec = execute_dial_plan(
                &mut plan,
                n,
                node_role,
                adaptive.min_active_peers,
                dial_target,
                &dial_book,
                &catalog,
                &sm,
                &transports_maint,
                &router_maint,
                &incoming_maint,
                &our_peer_maint,
                &maintenance_handshake_payload,
                &mut state.dial_cooldown_until,
                &topology_tuning,
                now,
            )
            .await;
            if should_explore && exec.dialed_any {
                state.last_exploration_ms = now;
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
                    .filter(|p| catalog.peer_is_bootstrap_entry(p))
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
                        // После целевого offload не даём тут же перецепиться
                        // обратно на bootstrap.
                        observe_failure_and_close(
                            &catalog,
                            &sm,
                            &mut state.dial_cooldown_until,
                            &pid,
                            now.saturating_add(
                                topology_tuning
                                    .regular_bootstrap_rejoin_interval_ms
                                    .saturating_mul(2),
                            ),
                        )
                        .await;
                    }
                }
            }
        }
        n = sm.distinct_peer_count();
        let now = now_ms();

        let (shepherd_ran, shepherded) = run_bootstrap_shepherd(
            node_role,
            now,
            state.last_shepherd_sweep_ms,
            &router_maint,
            &sm,
            &catalog,
            &mut state.peer_admission_ms,
            &our_peer_maint,
        )
        .await;
        if shepherd_ran {
            state.last_shepherd_sweep_ms = now;
            if shepherded > 0 {
                n = sm.distinct_peer_count();
            }
        }

        state.last_publish = publish_descriptor_if_due(
            now,
            state.last_publish,
            descriptor_interval,
            descriptor_ttl_secs,
            &descriptor_ver,
            &transports_maint,
            &listens,
            &advertise_addrs,
            advertise_fallback_ip,
            node_role,
            &adaptive,
            &metrics,
            n,
            &our_peer_maint,
            &signing_key,
            &catalog,
            &db,
            &router_maint,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::policy::TopologyPhase;
    use super::*;

    #[test]
    fn policy_snapshot_bootstrapping_phase_on_small_network() {
        let tuning = TopologyTuning::default();
        let snapshot = compute_policy_snapshot(
            &tuning,
            NodeRole::Regular,
            12,
            8,
            1,
            7,
            6,
            6,
            4,
            3,
            0,
            60_000,
        );

        assert_eq!(snapshot.phase, TopologyPhase::Bootstrapping);
        assert!(snapshot.dial_target_low <= snapshot.dial_target);
        assert!(snapshot.dial_target <= snapshot.dial_target_high);
    }

    #[test]
    fn policy_snapshot_bridge_reseed_when_no_bootstrap_and_not_steady() {
        let tuning = TopologyTuning::default();
        let snapshot = compute_policy_snapshot(
            &tuning,
            NodeRole::Regular,
            10,
            2,
            0,
            2,
            4,
            6,
            4,
            3,
            0,
            120_000,
        );

        assert!(snapshot.reseed_for_bridge);
    }

    #[test]
    fn policy_snapshot_no_bridge_reseed_in_steady_mesh() {
        let tuning = TopologyTuning::default();
        let snapshot = compute_policy_snapshot(
            &tuning,
            NodeRole::Regular,
            128,
            10,
            0,
            10,
            6,
            6,
            4,
            3,
            0,
            120_000,
        );

        assert_eq!(snapshot.phase, TopologyPhase::Steady);
        assert!(!snapshot.reseed_for_bridge);
    }
}
