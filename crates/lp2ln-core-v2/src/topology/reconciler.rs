use std::collections::HashMap;
use std::sync::Arc;

use crate::sessions::manager::SessionManager;
use crate::topology::PeerCatalog;
use crate::topology::planner::DropIntent;
use crate::types::PeerId;

/// Owns dial-cooldown state and executes a `TopologyPlan` against live runtime.
///
/// The planner decides *what* to do; the reconciler does it safely:
/// deduplication, backoff tracking, and graceful session teardown.
pub struct TopologyReconciler {
    /// Peers that must not be re-dialed until the stored timestamp (ms since epoch).
    pub dial_cooldowns: HashMap<PeerId, u64>,
}

impl Default for TopologyReconciler {
    fn default() -> Self {
        Self::new()
    }
}

impl TopologyReconciler {
    pub fn new() -> Self {
        Self { dial_cooldowns: HashMap::new() }
    }

    pub fn is_in_cooldown(&self, peer_id: &PeerId, now: u64) -> bool {
        self.dial_cooldowns
            .get(peer_id)
            .is_some_and(|&until| now < until)
    }

    /// Remove entries whose cooldown has already expired.
    pub fn prune_expired(&mut self, now: u64) {
        self.dial_cooldowns.retain(|_, &mut until| until > now);
    }

    /// Execute drop intents: record failure in catalog, close all sessions for
    /// the peer, and set the redial cooldown from the intent.
    pub async fn execute_drops(
        &mut self,
        drops: &[DropIntent],
        catalog: &Arc<PeerCatalog>,
        sm: &Arc<SessionManager>,
    ) -> usize {
        let mut count = 0;
        for intent in drops {
            catalog.observe_failure(&intent.peer_id);
            let _ = sm.close_all_sessions_for_peer(&intent.peer_id).await;
            self.dial_cooldowns
                .insert(intent.peer_id.clone(), intent.cooldown_until_ms);
            count += 1;
        }
        count
    }
}
