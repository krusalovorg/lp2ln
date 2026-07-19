use std::sync::Arc;

use crate::sessions::manager::SessionManager;
use crate::topology::peer_directory::PeerDirectory;
use crate::topology::{PeerCatalog, planner::DropIntent};

/// Executes a `TopologyPlan` against live runtime: graceful session teardown
/// and backoff registration via `PeerDirectory`.
///
/// The planner decides *what* to do; the reconciler does it safely.
/// Backoff / cooldown state lives in `PeerDirectory`, not here.
#[derive(Debug, Default)]
pub struct TopologyReconciler;

impl TopologyReconciler {
    pub fn new() -> Self {
        Self
    }

    /// Execute drop intents: record failure in catalog, close all sessions for
    /// the peer, and register the redial backoff in `peer_dir`.
    pub async fn execute_drops(
        &self,
        drops: &[DropIntent],
        catalog: &Arc<PeerCatalog>,
        sm: &Arc<SessionManager>,
        peer_dir: &Arc<PeerDirectory>,
    ) -> usize {
        let mut count = 0;
        for intent in drops {
            catalog.observe_failure(&intent.peer_id);
            let _ = sm.close_all_sessions_for_peer(&intent.peer_id).await;
            peer_dir.set_backoff(&intent.peer_id, intent.cooldown_until_ms);
            count += 1;
        }
        count
    }
}
