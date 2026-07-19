use serde::{Deserialize, Serialize};

use crate::peer_score::PeerConnectionPolicy;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityBudget {
    pub max_sessions: usize,
    pub max_relay_jobs: usize,
    pub max_storage_jobs: usize,
    pub hard_ceiling_connections: usize,
    pub active_sessions: usize,
    pub relay_jobs: usize,
    pub storage_jobs: usize,
    pub cpu_load: f32,
    pub memory_pressure: f32,
}

impl Default for CapacityBudget {
    fn default() -> Self {
        Self {
            max_sessions: 32,
            max_relay_jobs: 24,
            max_storage_jobs: 24,
            hard_ceiling_connections: 128,
            active_sessions: 0,
            relay_jobs: 0,
            storage_jobs: 0,
            cpu_load: 0.0,
            memory_pressure: 0.0,
        }
    }
}

impl CapacityBudget {
    pub fn overloaded(&self) -> bool {
        self.cpu_load > 0.85
            || self.memory_pressure > 0.85
            || self.active_sessions >= self.max_sessions
            || self.relay_jobs >= self.max_relay_jobs
            || self.storage_jobs >= self.max_storage_jobs
    }

    pub fn recommend_policy(&self, base: &PeerConnectionPolicy) -> PeerConnectionPolicy {
        let base = base.normalized();
        if !self.overloaded() {
            return base;
        }
        let min = (base.min_active_peers / 2).max(2);
        let target = (base.target_active_peers * 2 / 3).max(min);
        let mut max = (base.max_active_peers * 3 / 4).max(target);
        max = max.min(self.hard_ceiling_connections.max(target));
        PeerConnectionPolicy {
            min_active_peers: min,
            target_active_peers: target,
            max_active_peers: max,
        }
        .normalized()
    }
}
