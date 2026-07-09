use crate::event_core::prelude::{
    CoreEvent, LifecycleEvent, ServiceDescriptor, ServiceKind, ServiceStatus,
};

pub const RUNTIME_SERVICE_NAME: &str = "node_runtime";

pub fn runtime_lifecycle_event(
    status: ServiceStatus,
    generation: u64,
    reason: Option<String>,
) -> CoreEvent {
    CoreEvent::Lifecycle(LifecycleEvent {
        service: ServiceDescriptor::new(RUNTIME_SERVICE_NAME, ServiceKind::Runtime),
        status,
        generation,
        reason,
    })
}

pub fn transport_service_name(transport_name: &str) -> String {
    format!("transport:{transport_name}")
}
