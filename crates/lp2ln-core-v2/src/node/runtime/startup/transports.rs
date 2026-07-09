use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::event_core::prelude::{
    CoreBus, CoreEvent, ServiceDescriptor, ServiceKind, TransportCapability, TransportEvent,
    TransportProtocol, TransportReadiness,
};
use crate::node::runtime::events::transport_service_name;
use crate::node::runtime::health::SharedHealth;
use crate::node::supervisor::NodeSupervisor;
use crate::transport::{Transport, TransportContext};

fn transport_protocol(name: &str) -> TransportProtocol {
    match name {
        "tcp" => TransportProtocol::Tcp,
        "udp" => TransportProtocol::Udp,
        "quic" => TransportProtocol::Quic,
        _ => TransportProtocol::Custom(name.to_string()),
    }
}

fn emit_transport(bus: &CoreBus, event: TransportEvent) {
    let bus = bus.clone();
    tokio::spawn(async move {
        let _ = bus.emit(CoreEvent::Transport(event)).await;
    });
}

pub(crate) fn spawn_listener_transports(
    supervisor: &mut NodeSupervisor,
    producer_cancel: tokio_util::sync::CancellationToken,
    transports: &[Arc<dyn Transport>],
    listens: &dashmap::DashMap<String, SocketAddr>,
    ctx: TransportContext,
    health: SharedHealth,
    core_bus: CoreBus,
) {
    for transport in transports {
        if !transport.is_listener() {
            continue;
        }
        let listen_addr = listens.get(transport.name()).map(|r| *r);
        let ctx_clone = TransportContext {
            incoming_sessions_tx: ctx.incoming_sessions_tx.clone(),
            incoming_packets_tx: ctx.incoming_packets_tx.clone(),
            listen_addr,
        };
        let transport_clone = transport.clone();
        let transport_name = transport.name().to_string();
        let health = health.clone();
        let core_bus = core_bus.clone();
        let cancel_transport = producer_cancel.clone();
        let service_name: &'static str = match transport_name.as_str() {
            "tcp" => "transport:tcp",
            "udp" => "transport:udp",
            _ => "transport:other",
        };
        let protocol = transport_protocol(&transport_name);
        let service = ServiceDescriptor::new(
            transport_service_name(&transport_name),
            ServiceKind::Transport,
        );

        supervisor.spawn(service_name, async move {
            let mut backoff = Duration::from_millis(500);
            loop {
                if cancel_transport.is_cancelled() {
                    break;
                }
                emit_transport(
                    &core_bus,
                    TransportEvent::Starting {
                        service: service.clone(),
                        protocol: protocol.clone(),
                        listen_addr,
                    },
                );
                let start_result = tokio::select! {
                    _ = cancel_transport.cancelled() => break,
                    result = transport_clone.start(ctx_clone.clone()) => result,
                };
                match start_result {
                    Ok(bound) => {
                        let started_addr = bound.or(listen_addr);
                        if let Some(addr) = started_addr {
                            crate::info!(
                                "[NodeRuntime] Transport {} started on {}",
                                transport_name,
                                addr
                            );
                        } else {
                            crate::info!("[NodeRuntime] Transport {} started", transport_name);
                        }
                        emit_transport(
                            &core_bus,
                            TransportEvent::Ready(TransportReadiness {
                                service: service.clone(),
                                protocol: protocol.clone(),
                                listen_addr: started_addr,
                                public_addr: None,
                                capabilities: vec![
                                    TransportCapability::Listener,
                                    TransportCapability::Dialer,
                                ],
                            }),
                        );
                        health.mark_healthy();
                        break;
                    }
                    Err(e) => {
                        health.transport_restarts.fetch_add(1, Ordering::Relaxed);
                        let reason = format!("{} failed to start: {}", transport_name, e);
                        health.record_error("transport", reason.clone());
                        emit_transport(
                            &core_bus,
                            TransportEvent::Degraded {
                                service: service.clone(),
                                protocol: protocol.clone(),
                                reason,
                            },
                        );
                        if let Some(addr) = listen_addr {
                            crate::warn!(
                                "[NodeRuntime] restarting transport {} on {} after {:?}",
                                transport_name,
                                addr,
                                backoff
                            );
                        } else {
                            crate::warn!(
                                "[NodeRuntime] restarting transport {} after {:?}",
                                transport_name,
                                backoff
                            );
                        }
                        tokio::select! {
                            _ = cancel_transport.cancelled() => break,
                            _ = tokio::time::sleep(backoff) => {}
                        }
                        backoff = (backoff * 2).min(Duration::from_secs(15));
                    }
                }
            }
        });
    }
}

pub(crate) fn emit_transport_stopped(bus: &CoreBus, transport_name: &str) {
    let protocol = transport_protocol(transport_name);
    let service = ServiceDescriptor::new(
        transport_service_name(transport_name),
        ServiceKind::Transport,
    );
    let bus = bus.clone();
    let name = transport_name.to_string();
    tokio::spawn(async move {
        let _ = bus
            .emit(CoreEvent::Transport(TransportEvent::Stopped {
                service,
                protocol,
            }))
            .await;
        crate::info!("[NodeRuntime] Stopped transport: {}", name);
    });
}
