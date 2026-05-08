use crate::node::distribution::{
    EXPLORATORY_SLOTS, EXPLORATORY_SLOTS_MAX, should_reseed_bootstrap,
    stable_bootstrap_reseed_guard,
};
use crate::node::options::{AdaptiveTopologyProfile, NodeRole, TopologyTuning};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TopologyPhase {
    Bootstrapping,
    Meshing,
    Steady,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AdaptiveTickPolicy {
    pub(crate) dial_target: usize,
    pub(crate) dial_target_low: usize,
    pub(crate) dial_target_high: usize,
    pub(crate) exploration_interval_ms: u64,
    pub(crate) bridge_rejoin_cooldown_ms: u64,
    pub(crate) bootstrap_hard_limit: usize,
    pub(crate) exploratory_slots: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct PolicySnapshot {
    pub(crate) phase: TopologyPhase,
    pub(crate) adaptive_tick: AdaptiveTickPolicy,
    pub(crate) dial_target: usize,
    pub(crate) dial_target_low: usize,
    pub(crate) dial_target_high: usize,
    pub(crate) reseed_for_low: bool,
    pub(crate) reseed_for_bridge: bool,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_policy_snapshot(
    topology_tuning: &TopologyTuning,
    node_role: NodeRole,
    known_peers: usize,
    connected_total: usize,
    connected_bootstrap_now: usize,
    connected_non_bootstrap_now: usize,
    dial_target_base: usize,
    desired: usize,
    adaptive_min_active_peers: usize,
    bootstrap_targets_len: usize,
    last_bootstrap_reseed_ms: u64,
    now: u64,
) -> PolicySnapshot {
    let phase = classify_topology_phase(
        known_peers,
        connected_total,
        connected_non_bootstrap_now,
        dial_target_base,
    );
    let adaptive_tick = adaptive_tick_policy(topology_tuning, dial_target_base, phase, known_peers);
    let dial_target = adaptive_tick.dial_target.max(adaptive_min_active_peers);
    let dial_target_low = adaptive_tick.dial_target_low.max(adaptive_min_active_peers);
    let dial_target_high = adaptive_tick.dial_target_high.max(dial_target_low);
    let low_connectivity_reseed = should_reseed_bootstrap(
        connected_total,
        adaptive_min_active_peers,
        connected_bootstrap_now,
        now,
        last_bootstrap_reseed_ms,
    );
    let stable_bootstrap_guard = stable_bootstrap_reseed_guard(
        topology_tuning,
        node_role,
        connected_total,
        adaptive_min_active_peers,
        known_peers,
        bootstrap_targets_len,
        connected_bootstrap_now,
    );
    let missing_bootstrap_bridge = matches!(node_role, NodeRole::Regular)
        && connected_bootstrap_now == 0
        && (connected_total < desired
            || known_peers
                < topology_tuning
                    .bootstrap_stable_peer_threshold
                    .saturating_add(2)
            || !matches!(phase, TopologyPhase::Steady))
        && now.saturating_sub(last_bootstrap_reseed_ms) >= adaptive_tick.bridge_rejoin_cooldown_ms;

    PolicySnapshot {
        phase,
        adaptive_tick,
        dial_target,
        dial_target_low,
        dial_target_high,
        reseed_for_low: !stable_bootstrap_guard && low_connectivity_reseed,
        reseed_for_bridge: missing_bootstrap_bridge,
    }
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
