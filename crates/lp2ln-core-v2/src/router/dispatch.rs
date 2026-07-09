use std::sync::Arc;

use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::packet_processor::{
    ChunkAssembler, ChunkAssemblerResult, PacketProcessor, ProcessAction,
};
use crate::router::Router;
use crate::services::MetricsProvider;
use crate::sessions::manager::SessionManager;
use crate::sessions::session::IncomingPacket;
use crate::types::SessionId;

/// Max idle wait between packets while draining the ingress buffer at shutdown.
pub const ROUTER_DRAIN_IDLE: std::time::Duration = std::time::Duration::from_millis(200);
/// Overall budget for the shutdown drain.
pub const ROUTER_DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(3);

/// Ingress scheduling: metrics, chunk assembly, broadcast fanout, processor spawn.
pub struct PacketIngressDispatcher {
    session_manager: Arc<SessionManager>,
    packet_processor: Arc<dyn PacketProcessor>,
    chunk_assembler: Arc<ChunkAssembler>,
    incoming_broadcast_tx: broadcast::Sender<IncomingPacket>,
    our_peer_id: String,
    packet_tasks: TaskTracker,
    packet_cancel: CancellationToken,
}

impl PacketIngressDispatcher {
    pub fn new(
        session_manager: Arc<SessionManager>,
        packet_processor: Arc<dyn PacketProcessor>,
        chunk_assembler: Arc<ChunkAssembler>,
        incoming_broadcast_tx: broadcast::Sender<IncomingPacket>,
        our_peer_id: impl Into<String>,
        packet_tasks: TaskTracker,
        packet_cancel: CancellationToken,
    ) -> Self {
        Self {
            session_manager,
            packet_processor,
            chunk_assembler,
            incoming_broadcast_tx,
            our_peer_id: our_peer_id.into(),
            packet_tasks,
            packet_cancel,
        }
    }

    pub fn packet_tasks(&self) -> &TaskTracker {
        &self.packet_tasks
    }

    pub fn packet_cancel(&self) -> &CancellationToken {
        &self.packet_cancel
    }

    pub fn broadcast_incoming_after_decrypt(&self, incoming: IncomingPacket) {
        let _ = self.incoming_broadcast_tx.send(incoming);
    }

    pub fn dispatch_incoming(
        &self,
        router: Arc<Router>,
        incoming: IncomingPacket,
        semaphore: &Arc<tokio::sync::Semaphore>,
    ) {
        let session_id = SessionId::from(incoming.session_id.clone());
        let bytes_estimate = incoming.packet.wire_size_estimate();
        MetricsProvider::record_packets_received(
            self.session_manager.as_ref(),
            &session_id,
            bytes_estimate,
        );

        let to_process = if ChunkAssembler::is_chunk_packet(&incoming.packet) {
            match self.chunk_assembler.add(incoming) {
                ChunkAssemblerResult::Merged(ip) | ChunkAssemblerResult::PassThrough(ip) => {
                    Some(ip)
                }
                ChunkAssemblerResult::Collecting => None,
            }
        } else {
            Some(incoming)
        };

        let Some(mut incoming) = to_process else {
            return;
        };

        if incoming.from_node.is_none() && !incoming.packet.sender.is_empty() {
            incoming.from_node = Some(incoming.packet.sender.clone());
        }

        let skip_early_ipc =
            crate::crypto::secure_channel::is_secure_envelope(&incoming.packet.data)
                && (incoming.packet.receiver == self.our_peer_id
                    || incoming.packet.receiver.is_empty());
        if !skip_early_ipc {
            let _ = self.incoming_broadcast_tx.send(incoming.clone());
        }

        let processor = self.packet_processor.clone();
        let semaphore = semaphore.clone();
        let packet_cancel = self.packet_cancel.clone();
        self.packet_tasks.spawn(async move {
            tokio::select! {
                _ = packet_cancel.cancelled() => {}
                _ = async move {
                    let Ok(permit) = semaphore.acquire_owned().await else {
                        return;
                    };
                    let _permit = permit;
                    match processor.process(incoming, router.clone()).await {
                        ProcessAction::CloseSession { session_id, reason } => {
                            crate::warn!(
                                "[Router] closing session {} after processor action: {}",
                                session_id,
                                reason
                            );
                            let _ = router.teardown_session(&session_id).await;
                        }
                        ProcessAction::Delivered | ProcessAction::Dropped { .. } => {}
                    }
                } => {}
            }
        });
    }

    pub async fn drain_incoming(
        &self,
        router: Arc<Router>,
        incoming_rx: &mut mpsc::Receiver<IncomingPacket>,
        semaphore: &Arc<tokio::sync::Semaphore>,
    ) {
        let drain_deadline = tokio::time::Instant::now() + ROUTER_DRAIN_BUDGET;
        loop {
            let remaining = drain_deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let idle = ROUTER_DRAIN_IDLE.min(remaining);
            match tokio::time::timeout(idle, incoming_rx.recv()).await {
                Ok(Some(incoming)) => self.dispatch_incoming(router.clone(), incoming, semaphore),
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }
}
