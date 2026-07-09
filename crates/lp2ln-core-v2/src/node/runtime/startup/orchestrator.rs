use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::mpsc;

use crate::event_core::prelude::{CoreEventKind, ServiceStatus};
use crate::node::direct_upgrade::DirectUpgradeRouterSink;
use crate::node::runtime::NodeRuntime;
use crate::node::runtime::events::runtime_lifecycle_event;
use crate::node::runtime::health_bridge::RuntimeHealthBridge;
use crate::node::runtime::lifecycle::{NodeLifecycleError, NodeLifecycleState};
use crate::node::runtime::startup::bootstrap::{BootstrapService, TransportListenerService};
use crate::node::runtime::startup::context::{RuntimeService, StartupContext};
use crate::node::runtime::startup::direct_upgrade::DirectUpgradeService;
use crate::node::runtime::startup::flow_trace::FlowTraceRuntimeService;
use crate::node::runtime::startup::incoming::IncomingService;
use crate::node::runtime::startup::router::RouterService;
use crate::node::runtime::startup::topology::TopologyService;
use crate::node::supervisor::NodeSupervisor;
use crate::node::topology_maintenance::TopologySessionReactionHandler;
use crate::router::{ROUTER_INCOMING_QUEUE_CAP, Router};

pub(crate) async fn run_startup(runtime: &mut NodeRuntime) -> Result<()> {
    {
        let mut lifecycle = runtime
            .lifecycle
            .lock()
            .map_err(|_| anyhow::anyhow!("node lifecycle lock poisoned"))?;
        match *lifecycle {
            NodeLifecycleState::Created => {}
            NodeLifecycleState::Running | NodeLifecycleState::Stopping => {
                return Err(NodeLifecycleError::AlreadyStarted.into());
            }
            NodeLifecycleState::Stopped => {
                return Err(NodeLifecycleError::RestartNotSupported.into());
            }
        }
        *lifecycle = NodeLifecycleState::Running;
    }

    if runtime.transports.is_empty() {
        if let Ok(mut lifecycle) = runtime.lifecycle.lock() {
            *lifecycle = NodeLifecycleState::Created;
        }
        crate::error!("[NodeRuntime] No transports registered");
        return Err(anyhow::anyhow!("No transports registered"));
    }

    let generation = runtime
        .lifecycle_generation
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    let _ = runtime
        .core_bus
        .emit(runtime_lifecycle_event(
            ServiceStatus::Starting,
            generation,
            None,
        ))
        .await;

    let mut supervisor = NodeSupervisor::with_shutdown_timeout(Duration::from_secs(
        runtime.options.supervisor_shutdown_timeout_secs,
    ));
    let cancel = supervisor.cancellation();
    let producer_cancel = cancel.child_token();
    if let Ok(mut guard) = runtime.producer_cancel.lock() {
        *guard = Some(producer_cancel.clone());
    }

    let (incoming_sessions_tx, incoming_sessions_rx) = mpsc::channel(ROUTER_INCOMING_QUEUE_CAP);
    let signing_key = Some(Arc::new(runtime.keypair.signing_key().clone()));
    let du_cfg = runtime.options.direct_upgrade.clone();
    let (upgrade_sink, direct_upgrade_rx) = if du_cfg.enabled {
        let (tx, rx) = mpsc::channel(du_cfg.event_queue_cap.max(64));
        (
            Some(DirectUpgradeRouterSink { enabled: true, tx }),
            Some(rx),
        )
    } else {
        (None, None)
    };
    let (router_raw, incoming_packets_rx) = Router::new_with_caps(
        runtime.session_manager.clone(),
        runtime.packet_processor.clone(),
        signing_key,
        runtime.keypair.peer_id(),
        upgrade_sink,
        runtime.options.router_incoming_queue_cap,
        runtime.options.router_broadcast_cap,
    );
    let router = Arc::new(router_raw);
    runtime.router = Some(router.clone());

    if let Some(db) = runtime.db.as_ref() {
        if let Ok(cached) = db.load_peer_descriptors() {
            for desc in cached {
                let _ = runtime.peer_catalog.upsert_descriptor(desc);
            }
        }
        if let Ok(scores) = db.load_peer_score_snapshot() {
            let store = runtime.session_manager.peer_score_store();
            for (pid, s) in scores {
                store.insert(pid, s);
            }
        }
    }

    if let Ok(mut guard) = runtime.incoming_sessions_tx.lock() {
        *guard = Some(incoming_sessions_tx.clone());
    }

    let bridge = Arc::new(RuntimeHealthBridge::new(runtime.health.clone()));
    runtime.event_handler_regs.push(
        runtime
            .core_bus
            .register_event_handler(CoreEventKind::Lifecycle, bridge.clone()),
    );
    runtime.event_handler_regs.push(
        runtime
            .core_bus
            .register_event_handler(CoreEventKind::Transport, bridge),
    );

    if runtime.options.topology_react_to_session_events {
        let handler = Arc::new(TopologySessionReactionHandler::new(
            runtime.session_manager.clone(),
            runtime.session_redial_queue.clone(),
            runtime.options.topology_tuning.prune_redial_cooldown_ms,
        ));
        runtime.event_handler_regs.push(
            runtime
                .core_bus
                .register_event_handler(CoreEventKind::Session, handler),
        );
    }

    let (degradation_stop_tx, _degradation_stop_rx) = mpsc::channel(1);
    if let Ok(mut guard) = runtime.degradation_stop_tx.lock() {
        *guard = Some(degradation_stop_tx);
    }

    let mut startup_ctx = StartupContext {
        supervisor: &mut supervisor,
        cancel: cancel.clone(),
        producer_cancel: producer_cancel.clone(),
        options: &runtime.options,
        db: &runtime.db,
        keypair: &runtime.keypair,
        transports: &runtime.transports,
        packet_processor: runtime.packet_processor.clone(),
        session_manager: runtime.session_manager.clone(),
        peer_catalog: runtime.peer_catalog.clone(),
        nat_state: runtime.nat_state.clone(),
        dial_book: runtime.dial_book.clone(),
        bootstrap_dial_dedupe: runtime.bootstrap_dial_dedupe.clone(),
        bootstrap_dial_ok_ms: runtime.bootstrap_dial_ok_ms.clone(),
        descriptor_version: runtime.descriptor_version.clone(),
        peer_connection_policy_live: runtime.peer_connection_policy_live.clone(),
        health: runtime.health.clone(),
        core_bus: runtime.core_bus.clone(),
        lifecycle_generation: generation,
        router: Some(router),
        incoming_packets_rx: Some(incoming_packets_rx),
        direct_upgrade_rx,
        incoming_sessions_tx: Some(incoming_sessions_tx),
        incoming_sessions_rx: Some(incoming_sessions_rx),
        session_redial_queue: runtime.session_redial_queue.clone(),
        event_handler_regs: &mut runtime.event_handler_regs,
        lifecycle: &runtime.lifecycle,
        bootstrap_targets: None,
    };

    let services: Vec<Box<dyn RuntimeService>> = vec![
        Box::new(RouterService),
        Box::new(DirectUpgradeService),
        Box::new(FlowTraceRuntimeService),
        Box::new(TransportListenerService),
        Box::new(IncomingService),
        Box::new(BootstrapService),
        Box::new(TopologyService),
    ];
    for service in services {
        if service.enabled(&startup_ctx) {
            crate::debug!("[NodeRuntime] spawning service: {}", service.name());
            service.spawn(&mut startup_ctx)?;
        }
    }

    if let Ok(mut guard) = runtime.supervisor.lock() {
        *guard = Some(supervisor);
    }

    let _ = runtime
        .core_bus
        .emit(runtime_lifecycle_event(
            ServiceStatus::Ready,
            generation,
            None,
        ))
        .await;

    Ok(())
}
