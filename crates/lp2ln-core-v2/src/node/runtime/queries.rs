use std::net::SocketAddr;
use std::sync::Arc;

use crate::node::options::NodeRole;
use crate::node::runtime::NodeRuntime;
use crate::node::runtime::health::{RuntimeHealthSnapshot, RuntimeMode};
use crate::node::runtime::lifecycle::NodeLifecycleState;
use crate::peer_score::{PeerScoreStore, PeerScoreWeights};
use crate::router::Router;
use crate::sessions::{LinkKind, SessionMetrics};
use crate::topology::PeerCatalog;
use crate::types::PeerId;

impl NodeRuntime {
    #[doc(hidden)]
    pub fn lifecycle_state(&self) -> NodeLifecycleState {
        self.lifecycle
            .lock()
            .map(|state| *state)
            .unwrap_or(NodeLifecycleState::Stopped)
    }

    #[doc(hidden)]
    pub fn lifecycle_active_tasks(&self) -> usize {
        self.supervisor
            .lock()
            .ok()
            .and_then(|guard| {
                guard
                    .as_ref()
                    .map(crate::node::supervisor::NodeSupervisor::active_task_count)
            })
            .unwrap_or(0)
    }

    #[doc(hidden)]
    pub fn test_close_router_ingress(&self) {
        if let Some(router) = self.router.as_ref() {
            router.close_incoming();
        }
    }

    pub fn peer_score_store(&self) -> Arc<PeerScoreStore> {
        self.session_manager.peer_score_store()
    }

    pub fn peer_catalog(&self) -> Arc<PeerCatalog> {
        self.peer_catalog.clone()
    }

    pub fn register_known_peer_addr(
        &self,
        peer_id: PeerId,
        transport: impl Into<String>,
        addr: SocketAddr,
    ) {
        let transport = transport.into();
        let mut entry = self.dial_book.entry(peer_id).or_default();
        if !entry.iter().any(|(t, a)| t == &transport && a == &addr) {
            entry.push((transport, addr));
        }
    }

    pub fn router(&self) -> Option<Arc<Router>> {
        self.router.clone()
    }

    pub fn peer_id(&self) -> &str {
        self.keypair.peer_id()
    }

    pub fn get_metrics_for_protocol(&self, kind: LinkKind) -> Vec<SessionMetrics> {
        self.session_manager.get_metrics_for_protocol(kind)
    }

    pub fn get_metrics_by_protocol(&self) -> Vec<(LinkKind, Vec<SessionMetrics>)> {
        self.session_manager.get_metrics_by_protocol()
    }

    pub fn debug_sessions(&self) -> Vec<crate::sessions::manager::SessionDebugEntry> {
        self.session_manager.debug_sessions()
    }

    pub fn health_snapshot(&self) -> RuntimeHealthSnapshot {
        self.health.snapshot()
    }

    pub fn is_degraded(&self) -> bool {
        self.health.snapshot().mode == RuntimeMode::Degraded
    }

    pub fn node_role(&self) -> NodeRole {
        self.options.node_role
    }

    pub fn active_peer_count(&self) -> usize {
        self.session_manager.distinct_peer_count()
    }

    pub fn connected_peers(&self) -> Vec<PeerId> {
        if let Some(router) = self.router.as_ref() {
            return router.connected_peers();
        }
        vec![]
    }

    pub fn nat_metrics(&self) -> (u64, u64, u64) {
        self.nat_state.metrics()
    }

    pub fn peer_score_weights(&self) -> &PeerScoreWeights {
        &self.options.peer_score_weights
    }
}
