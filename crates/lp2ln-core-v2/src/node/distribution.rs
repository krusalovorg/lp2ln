use crate::node::options::{NodeRole, TopologyTuning};

pub const REGULAR_BOOTSTRAP_DIAL_QUOTA: usize = 2;
pub const BOOTSTRAP_INCOMING_HEADROOM: usize = 3;
pub const REGULAR_INCOMING_RESERVE_SLOTS: usize = 0;
pub const BOOTSTRAP_INCOMING_RESERVE_SLOTS: usize = 1;
pub const BOOTSTRAP_RESEED_INTERVAL_MS: u64 = 12_000;
pub const REGULAR_SELF_HEAL_FLOOR: usize = 3;
pub const DIAL_HUB_SOFT_CAP_EXTRA: usize = 2;
/// Exploratory-слоты: рандомная ротация для эпидемического покрытия.
pub const EXPLORATORY_SLOTS: usize = 2;
pub const EXPLORATORY_SLOTS_MAX: usize = 4;

const OVERLOAD_REDIRECT_LIMIT: usize = 24;

/// Целевое число активных соседей для `Regular` — log-масштаб без
/// переуплотнения графа в малых/средних кластерах.
/// При `known_peers = N`: `target ≈ ceil(log2(N+1)) + 2`. Даёт
/// N=50 → ~8, N=1k → ~12, N=10k → ~16.
pub fn regular_auto_dial_target(
    known_peers: usize,
    tuning: &TopologyTuning,
    capacity_factor: f32,
) -> usize {
    let log_term = ((known_peers.saturating_add(1)) as f32).log2().ceil() as usize;
    let base_target = log_term.saturating_add(2);
    let factor = capacity_factor.clamp(0.7, 1.25);
    let scaled = ((base_target as f32) * factor).round() as usize;
    let min_t = tuning.regular_auto_target_min;
    let max_t = tuning.regular_auto_target_max.max(min_t);
    if tuning.adaptive_topology_enabled {
        let floor = tuning
            .adaptive_target_min_floor
            .min(tuning.adaptive_target_max_ceil);
        let ceil = tuning.adaptive_target_max_ceil.max(floor);
        scaled.clamp(min_t.max(floor), max_t.min(ceil).max(min_t.max(floor)))
    } else {
        scaled.clamp(min_t, max_t)
    }
}

/// Capacity-фактор для target-scaling: 1.0 при номинальной нагрузке,
/// > 1.0 при большом запасе, < 1.0 при перегреве.
pub fn capacity_target_factor(cpu_load: f32, mem_pressure: f32, base_session_limit: u16) -> f32 {
    let load = cpu_load.max(mem_pressure).clamp(0.0, 1.0);
    let load_factor = 1.5 - load;
    let cap_factor = ((base_session_limit as f32) / 64.0).clamp(0.5, 1.5);
    ((load_factor + cap_factor) / 2.0).clamp(0.5, 1.5)
}

/// «Достаточно» связность, чтобы отдавать предпочтение только «принимающим» пирам и не перегружать хабы.
#[inline]
pub fn connectivity_selective(n: usize, dial_target: usize, min_active_peers: usize) -> bool {
    n >= dial_target && n >= min_active_peers
}

/// Сколько адресов перебирать за один тик на одного кандидата: при дефиците — агрессивнее.
pub fn dial_endpoint_attempt_budget(
    n: usize,
    dial_target: usize,
    min_active_peers: usize,
    addr_count: usize,
) -> usize {
    if addr_count == 0 {
        return 0;
    }
    if n < min_active_peers.max(1) || n + 1 < dial_target {
        return addr_count.min(4);
    }
    if n < dial_target {
        return addr_count.min(3);
    }
    addr_count.min(2)
}

pub fn should_skip_for_bootstrap_quota(
    is_seed: bool,
    node_role: NodeRole,
    connected_bootstrap: usize,
    bootstrap_quota: usize,
    current_peers: usize,
    min_active_peers: usize,
) -> bool {
    matches!(node_role, NodeRole::Regular)
        && is_seed
        && ((connected_bootstrap >= bootstrap_quota && current_peers >= min_active_peers)
            // Keep at most one seed edge once we already have a couple of peers.
            || (connected_bootstrap >= 1 && current_peers >= 2))
}

pub fn bootstrap_dial_quota(_node_role: NodeRole) -> usize {
    // Same quota for every role: seeds are address-book entries, not a cast.
    REGULAR_BOOTSTRAP_DIAL_QUOTA
}

pub fn dial_reserve_slots(_node_role: NodeRole) -> usize {
    REGULAR_INCOMING_RESERVE_SLOTS
}

pub fn should_reseed_bootstrap(
    active_peers: usize,
    min_active_peers: usize,
    connected_bootstrap: usize,
    now_ms: u64,
    last_reseed_ms: u64,
) -> bool {
    let low_connectivity =
        active_peers == 0 || (active_peers < min_active_peers && connected_bootstrap == 0);
    low_connectivity && now_ms.saturating_sub(last_reseed_ms) >= BOOTSTRAP_RESEED_INTERVAL_MS
}

/// Блокирует только «лишние» reseed по низкой связности, когда каталог ещё маленький и bootstrap уже есть.
pub fn stable_bootstrap_reseed_guard(
    tuning: &TopologyTuning,
    node_role: NodeRole,
    n: usize,
    min_active_peers: usize,
    known_peers: usize,
    bootstrap_targets_len: usize,
    connected_bootstrap: usize,
) -> bool {
    if !tuning.avoid_reseed_when_stable_bootstrap {
        return false;
    }
    if n < min_active_peers.max(1) {
        return false;
    }
    let only_seed_known_mode = matches!(node_role, NodeRole::Regular)
        && n > 0
        && bootstrap_targets_len > 0
        && known_peers <= bootstrap_targets_len.saturating_add(1);
    let thin_catalog_stable_bootstrap = matches!(node_role, NodeRole::Regular)
        && connected_bootstrap > 0
        && known_peers < tuning.bootstrap_stable_peer_threshold;
    only_seed_known_mode || thin_catalog_stable_bootstrap
}

pub(crate) const OVERLOAD_REDIRECT_DESCRIPTOR_LIMIT: usize = OVERLOAD_REDIRECT_LIMIT;
