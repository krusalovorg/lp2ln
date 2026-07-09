use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::event_core::prelude::{
    CoreEvent, CoreEventHandler, EventContext, LifecycleEvent, ServiceStatus, TransportEvent,
};

use super::health::RuntimeHealthState;

/// Observes lifecycle/transport bus events and mirrors them into runtime health.
pub(crate) struct RuntimeHealthBridge {
    health: Arc<RuntimeHealthState>,
}

impl RuntimeHealthBridge {
    pub fn new(health: Arc<RuntimeHealthState>) -> Self {
        Self { health }
    }
}

#[async_trait]
impl CoreEventHandler for RuntimeHealthBridge {
    async fn handle_event(&self, event: CoreEvent, _ctx: EventContext) -> Result<()> {
        match event {
            CoreEvent::Lifecycle(LifecycleEvent {
                status: ServiceStatus::Degraded,
                reason: Some(reason),
                service,
                ..
            }) => {
                self.health.record_error(&service.name, reason);
            }
            CoreEvent::Lifecycle(LifecycleEvent {
                status: ServiceStatus::Ready,
                ..
            }) => {
                self.health.mark_healthy();
            }
            CoreEvent::Transport(TransportEvent::Degraded {
                reason, service, ..
            }) => {
                self.health.record_error(&service.name, reason);
            }
            CoreEvent::Transport(TransportEvent::Ready(_)) => {
                self.health.mark_healthy();
            }
            _ => {}
        }
        Ok(())
    }
}
