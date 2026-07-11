use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdaptiveLossConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Fraction of sent packets that must be lost to enter compensate mode (0.0–1.0).
    #[serde(default = "default_loss_threshold")]
    pub loss_threshold: f64,
    /// Measurement window in seconds.
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    // ponytail: redundancy_factor wired into config but not used for in-stream duplicate sends
    // (QUIC stream is reliable; redundancy at the routing level is slice 5's job).
    #[serde(default = "default_redundancy_factor")]
    pub redundancy_factor: u8,
}

impl Default for AdaptiveLossConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            loss_threshold: default_loss_threshold(),
            window_secs: default_window_secs(),
            redundancy_factor: default_redundancy_factor(),
        }
    }
}

fn default_loss_threshold() -> f64 {
    0.05
}
fn default_window_secs() -> u64 {
    10
}
fn default_redundancy_factor() -> u8 {
    2
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptiveSendPolicy {
    Normal,
    Compensate,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_loss_config_defaults() {
        let cfg = AdaptiveLossConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.loss_threshold, 0.05);
        assert_eq!(cfg.window_secs, 10);
        assert_eq!(cfg.redundancy_factor, 2);
    }

    #[test]
    fn adaptive_send_policy_eq() {
        assert_eq!(AdaptiveSendPolicy::Normal, AdaptiveSendPolicy::Normal);
        assert_ne!(AdaptiveSendPolicy::Normal, AdaptiveSendPolicy::Compensate);
    }
}
