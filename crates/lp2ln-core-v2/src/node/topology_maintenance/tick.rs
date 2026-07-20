use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::metrics::MetricsAggregator;
use crate::metrics::contract::AggregatedMetricsSnapshot;
use crate::node::distribution::{
    capacity_target_factor, dial_reserve_slots, regular_auto_dial_target,
};
use crate::node::options::{BootstrapNode, NodeRole, TopologyTuning};
use crate::peer_score::PeerConnectionPolicy;
use crate::sessions::manager::SessionManager;
use crate::topology::{CapacityBudget, now_ms};
use crate::types::PeerId;

use super::policy::{AdaptiveTickPolicy, PolicySnapshot, TopologyPhase, compute_policy_snapshot};
use super::{BOOTSTRAP_DIAL_OK_TTL_MS, TopologyMaintenanceCtx};

pub(super) struct TickState {
    pub(super) metrics: AggregatedMetricsSnapshot,
    pub(super) budget: CapacityBudget,
    pub(super) adaptive: PeerConnectionPolicy,
    pub(super) known_peers: usize,
    pub(super) connected_snapshot: Vec<PeerId>,
    pub(super) connected_bootstrap_now: usize,
    pub(super) connected_non_bootstrap_now: usize,
    pub(super) phase: TopologyPhase,
    pub(super) adaptive_tick: AdaptiveTickPolicy,
    pub(super) dial_target: usize,
    pub(super) dial_target_low: usize,
    pub(super) dial_target_high: usize,
    pub(super) reseed_for_low: bool,
    pub(super) reseed_for_bridge: bool,
    pub(super) now: u64,
}

pub(super) fn prepare_tick(
    ctx: &TopologyMaintenanceCtx<'_>,
    policy: &PeerConnectionPolicy,
    node_role: NodeRole,
    sm: &Arc<SessionManager>,
    topology_tuning: &TopologyTuning,
    bootstrap_targets: &[BootstrapNode],
    bootstrap_dial_ok_ms: &Arc<Mutex<HashMap<SocketAddr, u64>>>,
    last_bootstrap_reseed_ms: u64,
) -> TickState {
    let metrics = MetricsAggregator::aggregate(sm.as_ref(), policy.max_active_peers.max(8));
    let n = metrics.node.active_peers as usize;
    let budget = CapacityBudget {
        active_sessions: metrics.node.active_connections as usize,
        max_sessions: policy.max_active_peers.max(8),
        hard_ceiling_connections: policy.max_active_peers.max(16) * 4,
        cpu_load: metrics.node.conn_load_estimate,
        memory_pressure: metrics.node.local_capacity_pressure,
        ..CapacityBudget::default()
    };
    let adaptive = budget.recommend_policy(policy);
    let now = now_ms();
    let known_peers = ctx.catalog.known_peer_ids().len().max(1);
    let self_capacity_factor = capacity_target_factor(
        metrics.node.conn_load_estimate,
        metrics.node.local_capacity_pressure,
        policy.max_active_peers.min(u16::MAX as usize) as u16,
    );
    let auto_target_regular =
        regular_auto_dial_target(known_peers, topology_tuning, self_capacity_factor);
    let mut desired = adaptive
        .target_active_peers
        .max(adaptive.min_active_peers)
        .min(adaptive.max_active_peers);
    // All roles use the same auto dial target (BootstrapJoin ≡ Regular).
    desired = desired.min(auto_target_regular);
    let reserve_slots = dial_reserve_slots(node_role);
    let dial_target_base = desired
        .saturating_sub(reserve_slots)
        .max(adaptive.min_active_peers);
    let connected_snapshot = ctx.router.connected_peers();
    {
        let mut g = bootstrap_dial_ok_ms.lock().unwrap();
        g.retain(|_, ts| now.saturating_sub(*ts) < BOOTSTRAP_DIAL_OK_TTL_MS);
    }
    let dial_ok_snap = bootstrap_dial_ok_ms.lock().unwrap().clone();
    let connected_bootstrap_now = crate::node::seed_book::connected_seed_count_with_recent(
        &connected_snapshot,
        ctx.catalog,
        bootstrap_targets,
        ctx.dial_book,
        &dial_ok_snap,
        now,
        BOOTSTRAP_DIAL_OK_TTL_MS,
    );
    let connected_non_bootstrap_now = connected_snapshot
        .len()
        .saturating_sub(connected_bootstrap_now);
    let PolicySnapshot {
        phase,
        adaptive_tick,
        dial_target,
        dial_target_low,
        dial_target_high,
        reseed_for_low,
        reseed_for_bridge,
    } = compute_policy_snapshot(
        topology_tuning,
        node_role,
        known_peers,
        n,
        connected_bootstrap_now,
        connected_non_bootstrap_now,
        dial_target_base,
        desired,
        adaptive.min_active_peers,
        bootstrap_targets.len(),
        last_bootstrap_reseed_ms,
        now,
    );
    TickState {
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
    }
}
