use crate::event_core::prelude::ServiceStatus;
use crate::node::options::NodeOptions;
use crate::node::runtime::NodeRuntime;
use crate::node::runtime::events::runtime_lifecycle_event;
use crate::peer_score::PeerConnectionPolicy;

impl NodeRuntime {
    fn read_policy_lock(&self) -> PeerConnectionPolicy {
        match self.peer_connection_policy_live.read() {
            Ok(g) => g.clone(),
            Err(poison) => {
                self.health
                    .record_error("policy_lock", "peer policy lock poisoned on read");
                let bus = self.core_bus.clone();
                let generation = self
                    .lifecycle_generation
                    .load(std::sync::atomic::Ordering::Relaxed);
                tokio::spawn(async move {
                    let _ = bus
                        .emit(runtime_lifecycle_event(
                            ServiceStatus::Degraded,
                            generation,
                            Some("peer policy lock poisoned on read".to_string()),
                        ))
                        .await;
                });
                self.request_degradation_stop();
                poison.into_inner().clone()
            }
        }
    }

    fn write_policy_lock(&self, policy: PeerConnectionPolicy) {
        match self.peer_connection_policy_live.write() {
            Ok(mut g) => *g = policy,
            Err(poison) => {
                self.health
                    .record_error("policy_lock", "peer policy lock poisoned on write");
                let bus = self.core_bus.clone();
                let generation = self
                    .lifecycle_generation
                    .load(std::sync::atomic::Ordering::Relaxed);
                tokio::spawn(async move {
                    let _ = bus
                        .emit(runtime_lifecycle_event(
                            ServiceStatus::Degraded,
                            generation,
                            Some("peer policy lock poisoned on write".to_string()),
                        ))
                        .await;
                });
                self.request_degradation_stop();
                let mut g = poison.into_inner();
                *g = policy;
            }
        }
    }

    pub fn peer_connection_policy(&self) -> PeerConnectionPolicy {
        self.read_policy_lock()
    }

    pub fn effective_peer_connection_policy(&self) -> PeerConnectionPolicy {
        let base = self.read_policy_lock();
        NodeOptions::effective_peer_connection_policy_for(base, self.options.node_role)
    }

    pub fn set_peer_connection_policy(&self, policy: PeerConnectionPolicy) -> PeerConnectionPolicy {
        let n = policy.normalized();
        self.write_policy_lock(n.clone());
        n
    }
}
