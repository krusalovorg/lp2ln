use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;

use super::admission::{AdmittedPacket, IngressPermit, decode_retained_bytes};
use tokio::sync::{Notify, mpsc};

use crate::packet_processor::{
    ChunkAssembler, ChunkAssemblerResult, PacketProcessor, ProcessAction, RelayDedup,
};
use crate::router::Router;
use crate::services::{MetricsProvider, SessionSelector};
use crate::sessions::manager::SessionManager;
use crate::sessions::session::IncomingPacket;
use crate::types::SessionId;

/// Max idle wait between packets while draining the ingress buffer at shutdown.
pub const ROUTER_DRAIN_IDLE: std::time::Duration = std::time::Duration::from_millis(200);
/// Overall budget for the shutdown drain.
pub const ROUTER_DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(3);

const DATA_BYTE_LIMIT: usize = 65 * 1024 * 1024;
const CONTROL_BYTE_LIMIT: usize = 128 * 1024;
const CONTROL_ITEM_LIMIT: usize = 32;
const MAX_PENDING_JOBS: usize = 1024;
const CONTROL_BURST: usize = 8;
const CRYPTO_PER_LINK: u64 = 8;
const RELIABLE_ADMISSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

struct ProcessJob {
    incoming: IncomingPacket,
    _permit: Option<IngressPermit>,
    router: Weak<Router>,
    enqueued: Instant,
    bytes: usize,
}

#[derive(Default)]
struct QueueLane {
    jobs: VecDeque<ProcessJob>,
    bytes: usize,
}

impl QueueLane {
    fn push(
        &mut self,
        job: ProcessJob,
        item_limit: usize,
        byte_limit: usize,
    ) -> Result<(), ProcessJob> {
        if self.jobs.len() >= item_limit || job.bytes > byte_limit.saturating_sub(self.bytes) {
            return Err(job);
        }
        self.bytes += job.bytes;
        #[cfg(feature = "packet-trace")]
        crate::packet_trace::record(
            &job.incoming.packet,
            crate::packet_trace::Stage::ProcessorAdmitted,
        );
        self.jobs.push_back(job);
        Ok(())
    }

    fn pop_ready(
        &mut self,
        authenticating: &HashMap<String, LinkOrder>,
        width: u64,
    ) -> Option<ProcessJob> {
        let pos = self.jobs.iter().position(|job| {
            authenticating
                .get(&job.incoming.session_id)
                .is_none_or(|link| link.issued - link.head < width)
        })?;
        let job = self.jobs.remove(pos)?;
        self.bytes -= job.bytes;
        Some(job)
    }
}

#[derive(Default)]
struct QueueState {
    control: QueueLane,
    data: QueueLane,
    control_burst: usize,
    authenticating: HashMap<String, LinkOrder>,
    closed: bool,
}

struct PacketJobQueue {
    inner: Mutex<QueueState>,
    notify: Notify,
    space: Notify,
    max_data_items: usize,
    crypto_width: u64,
}

#[derive(Default)]
struct LinkOrder {
    head: u64,
    issued: u64,
    // At most CRYPTO_PER_LINK positions can be issued but not retired.
    finished: u8,
    progressed: Arc<Notify>,
}

/// Tickets are issued in input order. Authentication may finish in parallel,
/// but only the head can mutate the replay window. Cancellation retires a
/// ticket without skipping any earlier input.
pub struct PacketProcessingOrder {
    queue: Arc<PacketJobQueue>,
    session: String,
    index: u64,
    progressed: Arc<Notify>,
}

impl PacketProcessingOrder {
    pub(crate) async fn wait_turn(&self) {
        loop {
            let ready = self.progressed.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            if self.queue.inner.lock().unwrap().authenticating[&self.session].head == self.index {
                return;
            }
            ready.await;
        }
    }
}

impl Drop for PacketProcessingOrder {
    fn drop(&mut self) {
        let mut state = self.queue.inner.lock().unwrap();
        let link = state
            .authenticating
            .get_mut(&self.session)
            .expect("live ticket");
        let delta = self.index - link.head;
        link.finished |= 1 << delta;
        let advanced = link.finished.trailing_ones();
        if advanced == 8 {
            link.finished = 0;
        } else {
            link.finished >>= advanced;
        }
        link.head += u64::from(advanced);
        if link.head == link.issued {
            state.authenticating.remove(&self.session);
        }
        let closed = state.closed;
        drop(state);
        if advanced > 0 {
            self.progressed.notify_waiters();
            if closed {
                self.queue.notify.notify_waiters();
            } else {
                self.queue.notify.notify_one();
            }
        }
    }
}

impl PacketJobQueue {
    fn new(max_data_items: usize, parallel: bool) -> Self {
        Self {
            inner: Mutex::new(QueueState::default()),
            notify: Notify::new(),
            space: Notify::new(),
            max_data_items,
            crypto_width: if parallel { CRYPTO_PER_LINK } else { 1 },
        }
    }

    fn try_push(&self, job: ProcessJob, control_candidate: bool) -> Result<(), ProcessJob> {
        let mut state = self.inner.lock().unwrap();
        if state.closed {
            return Err(job);
        }
        let ready = state
            .authenticating
            .get(&job.incoming.session_id)
            .is_none_or(|link| link.issued - link.head < self.crypto_width);
        let job = if control_candidate {
            match state
                .control
                .push(job, CONTROL_ITEM_LIMIT, CONTROL_BYTE_LIMIT)
            {
                Ok(()) => {
                    if ready {
                        self.notify.notify_one();
                    }
                    return Ok(());
                }
                Err(job) => job,
            }
        } else {
            job
        };
        state.data.push(job, self.max_data_items, DATA_BYTE_LIMIT)?;
        if ready {
            self.notify.notify_one();
        }
        Ok(())
    }

    async fn wait_push(&self, mut job: ProcessJob, control_candidate: bool) -> bool {
        if job.bytes > DATA_BYTE_LIMIT {
            return false;
        }
        loop {
            let space = self.space.notified();
            tokio::pin!(space);
            space.as_mut().enable();
            match self.try_push(job, control_candidate) {
                Ok(()) => return true,
                Err(returned_job) => job = returned_job,
            }
            if self.inner.lock().unwrap().closed {
                return false;
            }
            space.await;
        }
    }

    async fn pop(self: &Arc<Self>) -> Option<(ProcessJob, PacketProcessingOrder)> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.inner.lock().unwrap();
                let QueueState {
                    control,
                    data,
                    control_burst,
                    authenticating,
                    closed,
                } = &mut *state;
                let mut job = None;
                if *control_burst < CONTROL_BURST || data.jobs.is_empty() {
                    job = control.pop_ready(authenticating, self.crypto_width);
                    if job.is_some() {
                        *control_burst = (*control_burst + 1).min(CONTROL_BURST);
                    }
                }
                if job.is_none() {
                    job = data.pop_ready(authenticating, self.crypto_width);
                    if job.is_some() {
                        *control_burst = 0;
                    }
                }
                if job.is_none() {
                    job = control.pop_ready(authenticating, self.crypto_width);
                    if job.is_some() {
                        *control_burst = (*control_burst + 1).min(CONTROL_BURST);
                    }
                }
                if let Some(job) = job {
                    let session = job.incoming.session_id.clone();
                    let link = authenticating.entry(session.clone()).or_default();
                    let index = link.issued;
                    link.issued += 1;
                    let progressed = link.progressed.clone();
                    self.space.notify_one();
                    return Some((
                        job,
                        PacketProcessingOrder {
                            queue: self.clone(),
                            session,
                            index,
                            progressed,
                        },
                    ));
                }
                if *closed && control.jobs.is_empty() && data.jobs.is_empty() {
                    return None;
                }
            }
            notified.await;
        }
    }

    fn close(&self) {
        self.inner.lock().unwrap().closed = true;
        self.notify.notify_waiters();
        self.space.notify_waiters();
    }

    fn discard(&self) {
        let mut state = self.inner.lock().unwrap();
        state.control = QueueLane::default();
        state.data = QueueLane::default();
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct IngressMetrics {
    /// Decoded transport frames presented to the router, including frames rejected by packet authentication.
    pub decoded_packets: u64,
    /// Packets that passed mandatory signature and applicable envelope/replay checks.
    pub authenticated_packets: u64,
    /// Authenticated addressed packets admitted to local processing.
    pub authenticated_local_packets: u64,
    pub replay_or_late_rejections: u64,
    /// Jobs refused at the processor queue due to count/byte limits or closure.
    pub processor_queue_drops: u64,
    /// Reliable links closed after ingress could not admit a frame.
    pub reliable_admission_failures: u64,
    pub processor_queue_items: usize,
    pub processor_queue_bytes: usize,
    pub processor_queue_samples: u64,
    pub processor_queue_wait_total_micros: u64,
    pub processor_queue_wait_max_micros: u64,
}

#[derive(Default)]
struct IngressCounters {
    decoded: AtomicU64,
    authenticated: AtomicU64,
    authenticated_local: AtomicU64,
    replay_or_late: AtomicU64,
    queue_drops: AtomicU64,
    reliable_admission_failures: AtomicU64,
    queue_samples: AtomicU64,
    queue_wait_total_micros: AtomicU64,
    queue_wait_max_micros: AtomicU64,
}

fn estimated_job_bytes(incoming: &IncomingPacket) -> usize {
    let packet = &incoming.packet;
    std::mem::size_of::<ProcessJob>()
        + incoming.session_id.capacity()
        + incoming.from_node.as_ref().map_or(0, String::capacity)
        + packet.data.capacity()
        + packet.signature.as_ref().map_or(0, String::capacity)
        + packet.sender.capacity()
        + packet.receiver.capacity()
        + packet.nodes.capacity() * std::mem::size_of::<String>()
        + packet.nodes.iter().map(String::capacity).sum::<usize>()
}

/// Ingress scheduling: metrics, chunk assembly, broadcast fanout, processor workers.
pub struct PacketIngressDispatcher {
    session_manager: Arc<SessionManager>,
    chunk_assembler: Arc<ChunkAssembler>,
    relay_dedup: Arc<RelayDedup>,
    job_queue: Arc<PacketJobQueue>,
    counters: Arc<IngressCounters>,
    worker_handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl PacketIngressDispatcher {
    pub fn new(
        session_manager: Arc<SessionManager>,
        packet_processor: Arc<dyn PacketProcessor>,
        chunk_assembler: Arc<ChunkAssembler>,
        relay_dedup: Arc<RelayDedup>,
        our_peer_id: impl Into<String>,
        worker_concurrency: usize,
        incoming_capacity: usize,
    ) -> Self {
        let our_peer_id = our_peer_id.into();
        let job_queue = Arc::new(PacketJobQueue::new(
            incoming_capacity.min(MAX_PENDING_JOBS),
            packet_processor.parallel_authentication(),
        ));
        let counters = Arc::new(IngressCounters::default());
        let mut worker_handles = Vec::new();

        for _ in 0..worker_concurrency.max(1) {
            let queue = job_queue.clone();
            let processor = packet_processor.clone();
            let counters = counters.clone();
            let own_peer = our_peer_id.clone();
            worker_handles.push(tokio::spawn(async move {
                loop {
                    let Some((job, order)) = queue.pop().await else {
                        break;
                    };
                    let Some(router) = job.router.upgrade() else {
                        break;
                    };
                    let micros = job.enqueued.elapsed().as_micros() as u64;
                    counters.queue_samples.fetch_add(1, Ordering::Relaxed);
                    counters
                        .queue_wait_total_micros
                        .fetch_add(micros, Ordering::Relaxed);
                    counters
                        .queue_wait_max_micros
                        .fetch_max(micros, Ordering::Relaxed);
                    let packet = &job.incoming.packet;
                    #[cfg(feature = "packet-trace")]
                    crate::packet_trace::record(packet, crate::packet_trace::Stage::Processing);
                    let local_envelope =
                        crate::crypto::secure_channel::is_secure_envelope(&packet.data)
                            && (packet.receiver == own_peer || packet.receiver.is_empty());
                    if !local_envelope && packet.nodes.is_empty() {
                        router.broadcast_legacy_packet(&job.incoming);
                    }
                    match processor
                        .process_ordered(job.incoming, router.clone(), order)
                        .await
                    {
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
                }
            }));
        }

        Self {
            session_manager,
            chunk_assembler,
            relay_dedup,
            job_queue,
            counters,
            worker_handles: Mutex::new(worker_handles),
        }
    }

    pub async fn shutdown_workers(&self, drain_timeout: std::time::Duration) {
        self.job_queue.close();
        self.chunk_assembler.clear();
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
            self.job_queue.discard();
        }
    }

    pub fn metrics(&self) -> IngressMetrics {
        let state = self.job_queue.inner.lock().unwrap();
        IngressMetrics {
            decoded_packets: self.counters.decoded.load(Ordering::Relaxed),
            authenticated_packets: self.counters.authenticated.load(Ordering::Relaxed),
            authenticated_local_packets: self.counters.authenticated_local.load(Ordering::Relaxed),
            replay_or_late_rejections: self.counters.replay_or_late.load(Ordering::Relaxed),
            processor_queue_drops: self.counters.queue_drops.load(Ordering::Relaxed),
            reliable_admission_failures: self
                .counters
                .reliable_admission_failures
                .load(Ordering::Relaxed),
            processor_queue_items: state.control.jobs.len() + state.data.jobs.len(),
            processor_queue_bytes: state.control.bytes + state.data.bytes,
            processor_queue_samples: self.counters.queue_samples.load(Ordering::Relaxed),
            processor_queue_wait_total_micros: self
                .counters
                .queue_wait_total_micros
                .load(Ordering::Relaxed),
            processor_queue_wait_max_micros: self
                .counters
                .queue_wait_max_micros
                .load(Ordering::Relaxed),
        }
    }

    pub fn record_replay_or_late(&self) {
        self.counters.replay_or_late.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_authenticated(&self, local: bool) {
        self.counters.authenticated.fetch_add(1, Ordering::Relaxed);
        if local {
            self.counters
                .authenticated_local
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn admit_relay_packet(&self, packet: &crate::packet::Packet) -> bool {
        self.relay_dedup.check_and_record(packet)
    }

    pub async fn dispatch_incoming(
        &self,
        router: Arc<Router>,
        incoming: IncomingPacket,
        deadline: tokio::time::Instant,
    ) {
        let peer = self
            .session_manager
            .get_peer_for_session(&SessionId::from(incoming.session_id.clone()));
        let Some(permit) = router.ingress_budget().legacy(
            &incoming.session_id,
            peer.as_ref().map(|peer| peer.as_str()),
            decode_retained_bytes(&incoming),
        ) else {
            self.admission_failed(&router, &SessionId::from(incoming.session_id))
                .await;
            return;
        };
        self.dispatch_admitted(router, AdmittedPacket { incoming, permit }, deadline)
            .await;
    }

    pub(crate) async fn dispatch_admitted(
        &self,
        router: Arc<Router>,
        admitted: AdmittedPacket,
        deadline: tokio::time::Instant,
    ) {
        let AdmittedPacket { incoming, permit } = admitted;
        self.counters.decoded.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "packet-trace")]
        crate::packet_trace::record(&incoming.packet, crate::packet_trace::Stage::RouterReceived);
        let session_id = SessionId::from(incoming.session_id.clone());
        let bytes_estimate = incoming.packet.wire_size_estimate();
        MetricsProvider::record_packets_received(
            self.session_manager.as_ref(),
            &session_id,
            bytes_estimate,
        );

        let (mut incoming, mut permit) = if ChunkAssembler::is_chunk_packet(&incoming.packet) {
            match self.chunk_assembler.add_admitted(incoming, Some(permit)) {
                (
                    ChunkAssemblerResult::Merged(ip) | ChunkAssemblerResult::PassThrough(ip),
                    Some(permit),
                ) => (ip, permit),
                (ChunkAssemblerResult::Rejected { .. }, _) => {
                    self.admission_failed(&router, &session_id).await;
                    return;
                }
                _ => return,
            }
        } else {
            (incoming, permit)
        };

        // A dialed session may not advertise its peer in the transport
        // object. Use the registry binding once the verified hello has set it.
        if incoming.from_node.is_none() {
            incoming.from_node = self
                .session_manager
                .get_peer_for_session(&session_id)
                .map(|peer| peer.as_str().to_owned());
        }

        // A wire hint cannot access reserved capacity before authentication.
        let control_candidate = false;
        if !permit.try_resize(decode_retained_bytes(&incoming)) {
            self.admission_failed(&router, &session_id).await;
            return;
        }
        let bytes = estimated_job_bytes(&incoming);
        let job = ProcessJob {
            incoming,
            _permit: Some(permit),
            router: Arc::downgrade(&router),
            enqueued: Instant::now(),
            bytes,
        };
        let Err(job) = self.job_queue.try_push(job, control_candidate) else {
            return;
        };
        let reliable = self
            .session_manager
            .session(&session_id)
            .is_some_and(|session| session.kind().is_reliable());
        if reliable
            && matches!(
                tokio::time::timeout_at(
                    deadline.min(tokio::time::Instant::now() + RELIABLE_ADMISSION_TIMEOUT),
                    self.job_queue.wait_push(job, control_candidate),
                )
                .await,
                Ok(true)
            )
        {
            return;
        }
        self.admission_failed(&router, &session_id).await;
    }

    async fn admission_failed(&self, router: &Router, session_id: &SessionId) {
        let reliable = self
            .session_manager
            .session(session_id)
            .is_some_and(|session| session.kind().is_reliable());
        self.counters.queue_drops.fetch_add(1, Ordering::Relaxed);
        if reliable {
            self.counters
                .reliable_admission_failures
                .fetch_add(1, Ordering::Relaxed);
            crate::warn!(
                "[Router] closing reliable session {} after ingress admission failed",
                session_id
            );
            let _ = router.teardown_session(session_id).await;
        }
    }

    pub async fn drain_incoming(
        &self,
        router: Arc<Router>,
        incoming_rx: &mut mpsc::Receiver<IncomingPacket>,
        admitted_rx: &mut mpsc::Receiver<AdmittedPacket>,
    ) {
        let mut admitted_open = true;
        let mut legacy_open = true;
        let drain_deadline = tokio::time::Instant::now() + ROUTER_DRAIN_BUDGET;
        loop {
            let remaining = drain_deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let idle = ROUTER_DRAIN_IDLE.min(remaining);
            if !admitted_open && !legacy_open {
                break;
            }
            tokio::select! {
                maybe = incoming_rx.recv(), if legacy_open => match maybe {
                    Some(packet) => self.dispatch_incoming(router.clone(), packet, drain_deadline).await,
                    None => legacy_open = false,
                },
                maybe = admitted_rx.recv(), if admitted_open => match maybe {
                    Some(packet) => self.dispatch_admitted(router.clone(), packet, drain_deadline).await,
                    None => admitted_open = false,
                },
                _ = tokio::time::sleep(idle) => break,
            }
        }
    }
    pub(crate) fn maintain(&self, router: &Router) {
        self.chunk_assembler.reap();
        router.ingress_memory();
    }

    pub(crate) fn remove_session(&self, session_id: &SessionId) {
        self.chunk_assembler.remove_session(session_id.as_str());
    }
}

impl Drop for PacketIngressDispatcher {
    fn drop(&mut self) {
        self.job_queue.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    fn job(bytes: usize) -> ProcessJob {
        ProcessJob {
            incoming: IncomingPacket {
                session_id: String::new(),
                from_node: None,
                packet: Packet {
                    signature: None,
                    data: Vec::new(),
                    nodes: Vec::new(),
                    sender: String::new(),
                    receiver: String::new(),
                    request_id: None,
                    protocol_id: None,
                    max_hops: 1,
                    chunk_stream_id: None,
                    chunk_index: None,
                    total_chunks: None,
                },
            },
            _permit: None,
            router: Weak::new(),
            enqueued: Instant::now(),
            bytes,
        }
    }

    #[tokio::test]
    async fn applies_both_limits_and_reserves_control_room() {
        let queue = Arc::new(PacketJobQueue::new(2, false));
        assert!(queue.try_push(job(DATA_BYTE_LIMIT), false).is_ok());
        assert!(queue.try_push(job(1), false).is_err());
        assert!(queue.try_push(job(200), true).is_ok());

        assert_eq!(queue.pop().await.unwrap().0.bytes, 200);
        assert_eq!(queue.pop().await.unwrap().0.bytes, DATA_BYTE_LIMIT);
        assert!(queue.try_push(job(1), false).is_ok());
        assert!(queue.try_push(job(2), false).is_ok());
        assert!(queue.try_push(job(3), false).is_err());
        queue.close();
        assert_eq!(queue.pop().await.unwrap().0.bytes, 1);
        assert_eq!(queue.pop().await.unwrap().0.bytes, 2);
        assert!(queue.pop().await.is_none());
        assert!(queue.try_push(job(1), true).is_err());
    }

    #[tokio::test]
    async fn reliable_admission_waits_for_space_or_closure() {
        let queue = Arc::new(PacketJobQueue::new(1, false));
        assert!(queue.try_push(job(1), false).is_ok());
        let waiting = queue.wait_push(job(2), false);
        tokio::pin!(waiting);
        assert!(futures::poll!(&mut waiting).is_pending());
        assert_eq!(queue.pop().await.unwrap().0.bytes, 1);
        assert!(waiting.await);

        let closing = queue.wait_push(job(3), false);
        tokio::pin!(closing);
        assert!(futures::poll!(&mut closing).is_pending());
        queue.close();
        assert!(!closing.await);
        assert_eq!(queue.pop().await.unwrap().0.bytes, 2);
    }

    #[tokio::test]
    async fn default_lane_keeps_a_sessions_authentication_order_without_blocking_others() {
        let queue = Arc::new(PacketJobQueue::new(5, false));
        assert!(queue.try_push(job(1), false).is_ok());
        assert!(queue.try_push(job(2), false).is_ok());
        let mut independent = job(3);
        independent.incoming.session_id = "another link".into();
        assert!(queue.try_push(independent, false).is_ok());
        let (first, order) = queue.pop().await.unwrap();
        assert_eq!(first.bytes, 1);
        assert_eq!(queue.pop().await.unwrap().0.bytes, 3);
        let next = queue.pop();
        tokio::pin!(next);
        assert!(futures::poll!(&mut next).is_pending());
        drop(order);
        assert_eq!(next.await.unwrap().0.bytes, 2);
    }

    #[tokio::test]
    async fn cancelled_ticket_cannot_advance_past_earlier_authentication() {
        let queue = Arc::new(PacketJobQueue::new(8, true));
        for n in 1..=4 {
            assert!(queue.try_push(job(n), false).is_ok());
        }
        let (_, first) = queue.pop().await.unwrap();
        let (_, cancelled) = queue.pop().await.unwrap();
        let (_, third) = queue.pop().await.unwrap();
        let (_, fourth) = queue.pop().await.unwrap();
        drop(cancelled);
        assert!(futures::poll!(Box::pin(third.wait_turn())).is_pending());
        assert!(futures::poll!(Box::pin(fourth.wait_turn())).is_pending());
        drop(first);
        third.wait_turn().await;
        assert!(futures::poll!(Box::pin(fourth.wait_turn())).is_pending());
        drop(third);
        fourth.wait_turn().await;
        drop(fourth);
        assert!(queue.inner.lock().unwrap().authenticating.is_empty());
    }

    #[tokio::test]
    async fn reserved_traffic_cannot_starve_data() {
        let queue = Arc::new(PacketJobQueue::new(1, false));
        assert!(queue.try_push(job(1), false).is_ok());
        for _ in 0..=CONTROL_BURST {
            assert!(queue.try_push(job(2), true).is_ok());
        }
        for _ in 0..CONTROL_BURST {
            assert_eq!(queue.pop().await.unwrap().0.bytes, 2);
        }
        assert_eq!(queue.pop().await.unwrap().0.bytes, 1);
        assert_eq!(queue.pop().await.unwrap().0.bytes, 2);
    }
}
