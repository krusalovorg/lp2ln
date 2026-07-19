use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use crate::types::PeerId;

pub(crate) struct MaintenanceState {
    pub(crate) bootstrap_deny_until: HashMap<SocketAddr, u64>,
    pub(crate) peer_admission_ms: HashMap<PeerId, u64>,
    pub(crate) last_bootstrap_reseed_ms: u64,
    pub(crate) last_exploration_ms: u64,
    pub(crate) last_shepherd_sweep_ms: u64,
    pub(crate) last_publish: u64,
    pub(crate) last_policy_log_ms: u64,
}

impl MaintenanceState {
    pub(crate) fn new(descriptor_interval: Duration, now: u64) -> Self {
        Self {
            bootstrap_deny_until: HashMap::new(),
            peer_admission_ms: HashMap::new(),
            last_bootstrap_reseed_ms: 0,
            last_exploration_ms: 0,
            last_shepherd_sweep_ms: 0,
            last_publish: now.saturating_sub(descriptor_interval.as_millis() as u64),
            last_policy_log_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_initializes_publish_timestamp_with_interval_offset() {
        let now = 10_000;
        let interval = Duration::from_secs(30);
        let state = MaintenanceState::new(interval, now);
        assert_eq!(
            state.last_publish,
            now.saturating_sub(interval.as_millis() as u64)
        );
        assert_eq!(state.last_bootstrap_reseed_ms, 0);
        assert_eq!(state.last_exploration_ms, 0);
    }
}
