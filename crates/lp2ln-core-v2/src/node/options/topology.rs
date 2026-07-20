use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default, PartialEq, Eq)]
pub enum AdaptiveTopologyProfile {
    Conservative,
    #[default]
    Balanced,
    Aggressive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyTuning {
    #[serde(default = "default_regular_auto_target_min")]
    pub regular_auto_target_min: usize,
    #[serde(default = "default_regular_auto_target_max")]
    pub regular_auto_target_max: usize,
    #[serde(default = "default_regular_bootstrap_min_keep")]
    pub regular_bootstrap_min_keep: usize,
    #[serde(default = "default_regular_bootstrap_rejoin_interval_ms")]
    pub regular_bootstrap_rejoin_interval_ms: u64,
    #[serde(default = "default_regular_exploration_interval_ms")]
    pub regular_exploration_interval_ms: u64,
    #[serde(default = "default_dial_retry_cooldown_ms")]
    pub dial_retry_cooldown_ms: u64,
    #[serde(default = "default_prune_redial_cooldown_ms")]
    pub prune_redial_cooldown_ms: u64,
    #[serde(default = "default_bootstrap_stable_peer_threshold")]
    pub bootstrap_stable_peer_threshold: usize,
    #[serde(default = "default_true")]
    pub avoid_reseed_when_stable_bootstrap: bool,
    #[serde(default)]
    pub adaptive_topology_enabled: bool,
    #[serde(default)]
    pub adaptive_profile: AdaptiveTopologyProfile,
    #[serde(default = "default_adaptive_target_min_floor")]
    pub adaptive_target_min_floor: usize,
    #[serde(default = "default_adaptive_target_max_ceil")]
    pub adaptive_target_max_ceil: usize,
    #[serde(default = "default_adaptive_bootstrap_hard_max")]
    pub adaptive_bootstrap_hard_max: usize,
    #[serde(default = "default_adaptive_bootstrap_top_k")]
    pub adaptive_bootstrap_top_k: usize,
    #[serde(default = "default_adaptive_exploration_interval_min_ms")]
    pub adaptive_exploration_interval_min_ms: u64,
    #[serde(default = "default_adaptive_exploration_interval_max_ms")]
    pub adaptive_exploration_interval_max_ms: u64,
    #[serde(default = "default_adaptive_rejoin_cooldown_min_ms")]
    pub adaptive_rejoin_cooldown_min_ms: u64,
    #[serde(default = "default_adaptive_rejoin_cooldown_max_ms")]
    pub adaptive_rejoin_cooldown_max_ms: u64,
    #[serde(default = "default_adaptive_redirect_memory_ms")]
    pub adaptive_redirect_memory_ms: u64,
    /// Minimum time a peer must be connected (ms) before it can be rotated out.
    #[serde(default = "default_min_peer_residency_ms")]
    pub min_peer_residency_ms: u64,
    /// Fraction of target peers rotated per maintenance tick (replaces hardcoded target/4).
    #[serde(default = "default_rotation_budget_frac")]
    pub rotation_budget_frac: f32,
    /// Minimum score improvement required to justify rotating out a connected peer.
    #[serde(default = "default_replacement_epsilon")]
    pub replacement_epsilon: f32,
}

impl Default for TopologyTuning {
    fn default() -> Self {
        Self {
            regular_auto_target_min: default_regular_auto_target_min(),
            regular_auto_target_max: default_regular_auto_target_max(),
            regular_bootstrap_min_keep: default_regular_bootstrap_min_keep(),
            regular_bootstrap_rejoin_interval_ms: default_regular_bootstrap_rejoin_interval_ms(),
            regular_exploration_interval_ms: default_regular_exploration_interval_ms(),
            dial_retry_cooldown_ms: default_dial_retry_cooldown_ms(),
            prune_redial_cooldown_ms: default_prune_redial_cooldown_ms(),
            bootstrap_stable_peer_threshold: default_bootstrap_stable_peer_threshold(),
            avoid_reseed_when_stable_bootstrap: true,
            adaptive_topology_enabled: false,
            adaptive_profile: AdaptiveTopologyProfile::default(),
            adaptive_target_min_floor: default_adaptive_target_min_floor(),
            adaptive_target_max_ceil: default_adaptive_target_max_ceil(),
            adaptive_bootstrap_hard_max: default_adaptive_bootstrap_hard_max(),
            adaptive_bootstrap_top_k: default_adaptive_bootstrap_top_k(),
            adaptive_exploration_interval_min_ms: default_adaptive_exploration_interval_min_ms(),
            adaptive_exploration_interval_max_ms: default_adaptive_exploration_interval_max_ms(),
            adaptive_rejoin_cooldown_min_ms: default_adaptive_rejoin_cooldown_min_ms(),
            adaptive_rejoin_cooldown_max_ms: default_adaptive_rejoin_cooldown_max_ms(),
            adaptive_redirect_memory_ms: default_adaptive_redirect_memory_ms(),
            min_peer_residency_ms: default_min_peer_residency_ms(),
            rotation_budget_frac: default_rotation_budget_frac(),
            replacement_epsilon: default_replacement_epsilon(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_regular_auto_target_min() -> usize { 4 }
fn default_regular_auto_target_max() -> usize { 12 }
fn default_regular_bootstrap_min_keep() -> usize {
    // В steady state regular peer не держит bootstrap: мост остаётся доступным
    // через `bootstrap_nodes` и `missing_bootstrap_bridge` rejoin при изоляции.
    0
}
fn default_regular_bootstrap_rejoin_interval_ms() -> u64 { 20_000 }
fn default_regular_exploration_interval_ms() -> u64 { 12_000 }
fn default_dial_retry_cooldown_ms() -> u64 { 30_000 }
fn default_prune_redial_cooldown_ms() -> u64 { 45_000 }
fn default_bootstrap_stable_peer_threshold() -> usize { 4 }
fn default_adaptive_target_min_floor() -> usize { 3 }
fn default_adaptive_target_max_ceil() -> usize { 16 }
fn default_adaptive_bootstrap_hard_max() -> usize { 8 }
fn default_adaptive_bootstrap_top_k() -> usize { 2 }
fn default_adaptive_exploration_interval_min_ms() -> u64 { 8_000 }
fn default_adaptive_exploration_interval_max_ms() -> u64 { 120_000 }
fn default_adaptive_rejoin_cooldown_min_ms() -> u64 { 20_000 }
fn default_adaptive_rejoin_cooldown_max_ms() -> u64 { 180_000 }
fn default_adaptive_redirect_memory_ms() -> u64 { 12_000 }
fn default_min_peer_residency_ms() -> u64 { 60_000 }
fn default_rotation_budget_frac() -> f32 { 0.25 }
fn default_replacement_epsilon() -> f32 { 0.05 }
