use std::sync::atomic::Ordering;

use anyhow::Result;

use crate::event_core::prelude::ServiceStatus;
use crate::node::runtime::NodeRuntime;
use crate::node::runtime::events::runtime_lifecycle_event;
use crate::node::runtime::lifecycle::NodeLifecycleState;
use crate::node::runtime::startup::transports::emit_transport_stopped;

pub(crate) async fn run_shutdown(runtime: &NodeRuntime) -> Result<()> {
    let generation = runtime.lifecycle_generation.load(Ordering::Relaxed);
    {
        let mut lifecycle = runtime
            .lifecycle
            .lock()
            .map_err(|_| anyhow::anyhow!("node lifecycle lock poisoned"))?;
        match *lifecycle {
            NodeLifecycleState::Created | NodeLifecycleState::Stopped => return Ok(()),
            NodeLifecycleState::Stopping => return Ok(()),
            NodeLifecycleState::Running => *lifecycle = NodeLifecycleState::Stopping,
        }
    }

    let _ = runtime
        .core_bus
        .emit(runtime_lifecycle_event(
            ServiceStatus::Stopping,
            generation,
            None,
        ))
        .await;

    let producer_cancel = runtime
        .producer_cancel
        .lock()
        .ok()
        .and_then(|mut guard| guard.take());
    if let Some(token) = producer_cancel {
        token.cancel();
    }
    if let Ok(mut guard) = runtime.incoming_sessions_tx.lock() {
        guard.take();
    }

    for transport in &runtime.transports {
        transport.stop().await?;
        emit_transport_stopped(&runtime.core_bus, transport.name());
    }

    for session_id in runtime.session_manager.all_session_ids() {
        let _ = runtime.session_manager.close_session(&session_id).await;
    }

    if let Some(router) = runtime.router.as_ref() {
        router.close_incoming();
    }

    let supervisor = runtime
        .supervisor
        .lock()
        .ok()
        .and_then(|mut guard| guard.take());
    if let Some(supervisor) = supervisor {
        supervisor.shutdown().await;
    }

    if let Some(router) = runtime.router.as_ref() {
        router
            .shutdown_packet_tasks(std::time::Duration::from_secs(3))
            .await;
    }

    if let Ok(mut lifecycle) = runtime.lifecycle.lock() {
        *lifecycle = NodeLifecycleState::Stopped;
    }

    let _ = runtime
        .core_bus
        .emit(runtime_lifecycle_event(
            ServiceStatus::Stopped,
            generation,
            None,
        ))
        .await;

    Ok(())
}
