use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dashmap::DashMap;
use tokio_util::sync::CancellationToken;

mod args;
mod bootstrap;
mod descriptor;
mod dialing;
mod packet_helpers;
mod policy;
mod session_reactions;
mod state;
mod tick;

pub(crate) use args::TopologyMaintenanceArgs;
pub(crate) use dialing::dial_bootstrap_address;
use self::state::MaintenanceState;
use self::tick::{TickState, prepare_tick};
use crate::db::P2PDatabase;
use crate::node::nat_traversal::NatTraversalState;
use crate::node::options::{DialPolicy, NodeOptions, NodeRole, TopologyTuning};
use crate::peer_score::{
    PeerConnectionPolicy, PeerScore, PeerScoreStore, PeerScoreWeights, total_score,
};
use crate::protocol::control::NetworkControlPayload;
use crate::router::Router;
use crate::sessions::session::IncomingPacket;
use crate::topology::{
    CapacityBudget, NodeDescriptor, PeerCatalog, PeerDirectory,
    SmartMeshPlanner, TopologyPlanner, TopologyReconciler, TopologySnapshot, now_ms,
    parse_observed_addr_line,
};
use crate::transport::{Transport, TunnelPunchParams};
use crate::types::{PeerId, SessionId};
use bootstrap::{handle_bootstrap_reseed, run_bootstrap_shepherd};
use descriptor::publish_descriptor_if_due;
use dialing::{DialPlan, execute_dial_plan};
use packet_helpers::control_packet;
pub use session_reactions::{
    SessionRedialQueue, TopologySessionReactionHandler, TransportDegradedReactionHandler,
};

#[derive(Clone)]
pub(crate) struct BootstrapDialDedupe {
    pub active_peers: usize,
    pub set: Arc<Mutex<HashSet<(String, SocketAddr)>>>,
}

const MAINTENANCE_INTERVAL_SECS: u64 = 5;
const MAINTENANCE_START_JITTER_MS: u64 = 3_000;
pub(super) const REGULAR_DIAL_ATTEMPT_BUDGET_MAX: usize = 8;
pub(super) const BOOTSTRAP_DIAL_ATTEMPT_BUDGET_MAX: usize = 8;
pub(super) const SHEPHERD_SWEEP_INTERVAL_MS: u64 = 10_000;
pub(super) const SHEPHERD_MIN_MESH: u16 = 3;
pub(super) const SHEPHERD_GRACE_MS: u64 = 15_000;
pub(super) const SHEPHERD_FINAL_PEERS_LIMIT: usize = 24;
pub(super) const SHEPHERD_SKIP_IF_CONNECTED_AT_MOST: usize = 6;

pub(super) const BOOTSTRAP_DIAL_OK_TTL_MS: u64 = 120_000;

#[allow(clippy::too_many_arguments)]
fn build_topology_snapshot(
    ctx: &TopologyMaintenanceCtx<'_>,
    topology_tuning: &TopologyTuning,
    policy: &PeerConnectionPolicy,
    capacity: CapacityBudget,
    node_role: NodeRole,
    connected_peers: Vec<PeerId>,
    connected_bootstrap_count: usize,
    known_peer_count: usize,
    bootstrap_targets_count: usize,
    last_bootstrap_reseed_ms: u64,
    now: u64,
) -> TopologySnapshot {
    let peer_scores = ctx.peer_store.snapshot();
    let peer_total_scores: HashMap<PeerId, f32> = peer_scores
        .into_iter()
        .map(|(pid, score)| (pid, crate::peer_score::total_score(&score, ctx.weights)))
        .collect();

    let descriptors = ctx.catalog.descriptors();
    let bootstrap_peer_ids: HashSet<PeerId> = descriptors
        .iter()
        .filter(|d| d.capabilities.bootstrap_entry)
        .map(|d| PeerId::from(d.peer_id.as_str()))
        .collect();
    let descriptor_active_conns: HashMap<PeerId, u16> = descriptors
        .iter()
        .map(|d| (PeerId::from(d.peer_id.as_str()), d.dynamic_status.active_connections))
        .collect();
    let dial_book: HashMap<PeerId, Vec<(String, SocketAddr)>> =
        ctx.dial_book.iter().map(|r| (r.key().clone(), r.value().clone())).collect();
    let peer_age_ms = ctx.router.peer_connection_ages();

    TopologySnapshot {
        our_peer_id: PeerId::from(ctx.our_peer_id),
        node_role,
        policy: policy.clone(),
        weights: ctx.weights.clone(),
        topology_tuning: topology_tuning.clone(),
        connected_peers,
        connected_bootstrap_count,
        known_peer_count,
        peer_total_scores,
        bootstrap_peer_ids,
        descriptor_active_conns,
        catalog_descriptors: descriptors,
        capacity,
        dial_book,
        dial_cooldowns: ctx.peer_dir.cooldowns(),
        peer_age_ms,
        bootstrap_targets_count,
        last_bootstrap_reseed_ms,
        now_ms: now,
    }
}

struct TopologyMaintenanceCtx<'a> {
    transports: &'a [Arc<dyn Transport>],
    router: &'a Arc<Router>,
    incoming: &'a tokio::sync::mpsc::Sender<IncomingPacket>,
    our_peer_id: &'a str,
    nat_state: &'a Arc<NatTraversalState>,
    catalog: &'a Arc<PeerCatalog>,
    peer_store: &'a Arc<PeerScoreStore>,
    peer_dir: &'a Arc<PeerDirectory>,
    db: &'a Option<Arc<P2PDatabase>>,
    weights: &'a PeerScoreWeights,
    log_peer_scores: bool,
    listens: &'a DashMap<String, SocketAddr>,
    dial_book: &'a Arc<DashMap<PeerId, Vec<(String, SocketAddr)>>>,
    dial_policy: &'a DialPolicy,
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
            .transports
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
                        ctx.router.register_session(
                            peer_id.clone(),
                            session_id.clone(),
                            session.clone(),
                        );
                        session.spawn_reader(ctx.incoming.clone());
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
            let packet = control_packet(ctx.our_peer_id, nat_job.peer_id.clone(), data, 2);
            let _ = ctx
                .router
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
        if desc.peer_id == ctx.our_peer_id {
            continue;
        }
        ctx.peer_dir.upsert_from_descriptor(&desc, &our_listen_addrs);
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
            if proto != "tcp" && proto != "udp" && proto != "quic" {
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

pub(crate) async fn run_topology_maintenance_loop(
    cancel: CancellationToken,
    args: TopologyMaintenanceArgs,
) -> anyhow::Result<()> {
    let TopologyMaintenanceArgs {
        policy_live: policy_live_maint,
        node_role,
        weights,
        sm,
        peer_dir,
        dial_book,
        peer_store,
        catalog,
        db,
        listens,
        advertise_addrs,
        advertise_fallback_ip,
        transports,
        router,
        incoming,
        our_peer_id,
        descriptor_ver,
        signing_key,
        log_peer_scores,
        topology_tuning,
        handshake_payload: maintenance_handshake_payload,
        bootstrap_targets: bootstrap_targets_maint,
        nat_state,
        bootstrap_dial_dedupe,
        bootstrap_dial_ok_ms,
        session_redial_queue,
        react_to_session_events,
        dial_policy,
    } = args;
    let initial_jitter = (our_peer_id
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
    let reconciler = TopologyReconciler::new();
    let planner: std::sync::Arc<dyn TopologyPlanner> = std::sync::Arc::new(SmartMeshPlanner);
    let loop_ctx = TopologyMaintenanceCtx {
        transports: &transports,
        router: &router,
        incoming: &incoming,
        our_peer_id: &our_peer_id,
        nat_state: &nat_state,
        catalog: &catalog,
        peer_store: &peer_store,
        peer_dir: &peer_dir,
        db: &db,
        weights: &weights,
        log_peer_scores,
        listens: &listens,
        dial_book: &dial_book,
        dial_policy: &dial_policy,
    };

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {}
        }
        if react_to_session_events {
            if let Some(queue) = session_redial_queue.as_ref() {
                for peer_id in queue.drain_ready(now_ms()) {
                    peer_dir.clear_backoff(&peer_id);
                }
            }
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

        let TickState {
            metrics,
            budget,
            adaptive,
            known_peers,
            connected_snapshot,
            connected_bootstrap_now,
            connected_non_bootstrap_now,
            phase,
            adaptive_tick,
            dial_target,
            dial_target_low,
            dial_target_high,
            reseed_for_low,
            reseed_for_bridge,
            now,
        } = prepare_tick(
            &loop_ctx,
            &policy,
            node_role,
            &sm,
            &topology_tuning,
            &bootstrap_targets_maint,
            &bootstrap_dial_ok_ms,
            state.last_bootstrap_reseed_ms,
        );

        // Planner decides all keep/drop/dial/discovery from a pure snapshot.
        let topology_snapshot = build_topology_snapshot(
            &loop_ctx,
            &topology_tuning,
            &policy,
            budget.clone(),
            node_role,
            connected_snapshot.clone(),
            connected_bootstrap_now,
            known_peers,
            bootstrap_targets_maint.len(),
            state.last_bootstrap_reseed_ms,
            now,
        );
        peer_dir.cleanup_expired(now);
        let topology_plan = planner.plan(&topology_snapshot);
        if !topology_plan.drop.is_empty() {
            crate::debug!(
                "[NodeRuntime] planner: drop={} dial={} discovery={}",
                topology_plan.drop.len(),
                topology_plan.dial.len(),
                topology_plan.discovery.len(),
            );
        }
        reconciler.execute_drops(&topology_plan.drop, &catalog, &sm, &peer_dir).await;
        let mut n = sm.distinct_peer_count();

        if handle_bootstrap_reseed(
            reseed_for_low,
            reseed_for_bridge,
            n,
            adaptive.min_active_peers,
            connected_bootstrap_now,
            &bootstrap_targets_maint,
            &our_peer_id,
            &topology_tuning,
            &mut state.bootstrap_deny_until,
            now,
            &adaptive_tick,
            &transports,
            &router,
            &incoming,
            &maintenance_handshake_payload,
            &bootstrap_dial_dedupe,
            &bootstrap_dial_ok_ms,
        )
        .await
        {
            state.last_bootstrap_reseed_ms = now;
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
        // Discovery: planner already identified which connected peers to ask for more peers.
        for need in &topology_plan.discovery {
            let req = NetworkControlPayload::RequestPeers { limit: 48 };
            if let Ok(data) = req.encode() {
                for p in &need.request_from {
                    let packet =
                        control_packet(&our_peer_id, p.as_str().to_string(), data.clone(), 2);
                    let _ = router.send_to_peer(p.clone(), packet, None).await;
                }
            }
        }

        // Dial: SmartMesh already selected and ordered candidates; execute_dial_plan handles
        // transport selection, backoff guards, and session registration.
        if !topology_plan.dial.is_empty() {
            let desc_by_peer: HashMap<PeerId, NodeDescriptor> = catalog
                .descriptors()
                .into_iter()
                .map(|d| (PeerId::from(d.peer_id.as_str()), d))
                .collect();
            let dial_limit = if should_explore { dial_target_high } else { dial_target };
            let mut plan = DialPlan {
                candidates: topology_plan.dial.iter().map(|i| i.peer_id.clone()).collect(),
                desc_by_peer,
                connected_bootstrap: connected_bootstrap_now,
                dial_limit,
                force_non_bootstrap: false,
            };
            let exec = execute_dial_plan(
                &mut plan,
                n,
                node_role,
                adaptive.min_active_peers,
                dial_target,
                &dial_book,
                &catalog,
                &sm,
                &transports,
                &router,
                &incoming,
                &our_peer_id,
                &maintenance_handshake_payload,
                &peer_dir,
                &topology_tuning,
                loop_ctx.dial_policy.transport_order.as_slice(),
                now,
            )
            .await;
            if should_explore && exec.dialed_any {
                state.last_exploration_ms = now;
            }
        }
        n = sm.distinct_peer_count();
        let now = now_ms();

        let (shepherd_ran, shepherded) = run_bootstrap_shepherd(
            node_role,
            now,
            state.last_shepherd_sweep_ms,
            &router,
            &sm,
            &catalog,
            &mut state.peer_admission_ms,
            &our_peer_id,
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
            &transports,
            &listens,
            &advertise_addrs,
            advertise_fallback_ip,
            node_role,
            &adaptive,
            &metrics,
            n,
            &our_peer_id,
            &signing_key,
            &catalog,
            &db,
            &router,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::policy::{TopologyPhase, compute_policy_snapshot};
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
