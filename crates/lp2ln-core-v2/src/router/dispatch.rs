use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::{Notify, broadcast, mpsc};
use tokio_util::sync::CancellationToken;

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

struct ProcessJob {
    incoming: IncomingPacket,
    router: Arc<Router>,
}

struct PacketJobQueue {
    inner: Mutex<VecDeque<ProcessJob>>,
    notify: Notify,
}

impl PacketJobQueue {
    fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
        }
    }

    fn push(&self, job: ProcessJob) {
        self.inner.lock().unwrap().push_back(job);
        self.notify.notify_one();
    }

    async fn pop(&self, cancel: &CancellationToken) -> Option<ProcessJob> {
        loop {
            if cancel.is_cancelled() {
                return None;
            }
            if let Some(job) = self.inner.lock().unwrap().pop_front() {
                return Some(job);
            }
            tokio::select! {
                _ = cancel.cancelled() => return None,
                _ = self.notify.notified() => {}
            }
        }
    }
}

/// Ingress scheduling: metrics, chunk assembly, broadcast fanout, processor workers.
pub struct PacketIngressDispatcher {
    session_manager: Arc<SessionManager>,
    #[allow(dead_code)]
    packet_processor: Arc<dyn PacketProcessor>,
    chunk_assembler: Arc<ChunkAssembler>,
    incoming_broadcast_tx: broadcast::Sender<Arc<IncomingPacket>>,
    our_peer_id: String,
    job_queue: Arc<PacketJobQueue>,
    worker_cancel: CancellationToken,
    worker_handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl PacketIngressDispatcher {
    pub fn new(
        session_manager: Arc<SessionManager>,
        packet_processor: Arc<dyn PacketProcessor>,
        chunk_assembler: Arc<ChunkAssembler>,
        incoming_broadcast_tx: broadcast::Sender<Arc<IncomingPacket>>,
        our_peer_id: impl Into<String>,
        worker_concurrency: usize,
    ) -> Self {
        let our_peer_id = our_peer_id.into();
        let job_queue = Arc::new(PacketJobQueue::new());
        let worker_cancel = CancellationToken::new();
        let mut worker_handles = Vec::new();

        for _ in 0..worker_concurrency.max(1) {
            let queue = job_queue.clone();
            let processor = packet_processor.clone();
            let cancel = worker_cancel.child_token();
            worker_handles.push(tokio::spawn(async move {
                loop {
                    let Some(job) = queue.pop(&cancel).await else {
                        break;
                    };
                    match processor.process(job.incoming, job.router.clone()).await {
                        ProcessAction::CloseSession { session_id, reason } => {
                            crate::warn!(
                                "[Router] closing session {} after processor action: {}",
                                session_id,
                                reason
                            );
                            let _ = job.router.teardown_session(&session_id).await;
                        }
                        ProcessAction::Delivered | ProcessAction::Dropped { .. } => {}
                    }
                }
            }));
        }

        Self {
            session_manager,
            packet_processor,
            chunk_assembler,
            incoming_broadcast_tx,
            our_peer_id,
            job_queue,
            worker_cancel,
            worker_handles: Mutex::new(worker_handles),
        }
    }

    pub async fn shutdown_workers(&self, drain_timeout: std::time::Duration) {
        self.worker_cancel.cancel();
        let mut handles: Vec<_> = self.worker_handles.lock().unwrap().drain(..).collect();
        // A worker stuck inside `process()` (e.g. session send backpressure) must
        // not block node shutdown forever — honor the caller's drain budget.
        let join_all = futures::future::join_all(handles.iter_mut());
        if tokio::time::timeout(drain_timeout, join_all).await.is_err() {
            crate::warn!(
                "[Router] packet workers did not finish within {:?}, aborting",
                drain_timeout
            );
            for handle in &handles {
                handle.abort();
            }
            for handle in handles {
                let _ = handle.await;
            }
        }
    }

    pub fn broadcast_incoming_after_decrypt(&self, incoming: IncomingPacket) {
        let _ = self.incoming_broadcast_tx.send(Arc::new(incoming));
    }

    pub fn dispatch_incoming(&self, router: Arc<Router>, incoming: IncomingPacket) {
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

        // `from_node` is the immediate link neighbor (set by transports). Fallback
        // to logical sender only when the session has no peer binding (e.g. fakes).
        if incoming.from_node.is_none()
            && incoming.packet.nodes.is_empty()
            && !incoming.packet.sender.is_empty()
        {
            incoming.from_node = Some(incoming.packet.sender.clone());
        }

        let skip_early_ipc =
            crate::crypto::secure_channel::is_secure_envelope(&incoming.packet.data)
                && (incoming.packet.receiver == self.our_peer_id
                    || incoming.packet.receiver.is_empty());
        if !skip_early_ipc && self.incoming_broadcast_tx.receiver_count() > 0 {
            let _ = self.incoming_broadcast_tx.send(Arc::new(incoming.clone()));
        }

        self.job_queue.push(ProcessJob { incoming, router });
    }

    pub async fn drain_incoming(
        &self,
        router: Arc<Router>,
        incoming_rx: &mut mpsc::Receiver<IncomingPacket>,
    ) {
        let drain_deadline = tokio::time::Instant::now() + ROUTER_DRAIN_BUDGET;
        loop {
            let remaining = drain_deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let idle = ROUTER_DRAIN_IDLE.min(remaining);
            match tokio::time::timeout(idle, incoming_rx.recv()).await {
                Ok(Some(incoming)) => self.dispatch_incoming(router.clone(), incoming),
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }
}
