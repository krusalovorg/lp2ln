use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use async_trait::async_trait;
use k256::ecdsa::SigningKey;
use rand::Rng;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::{
    crypto::secure_channel::{derive_shared_key, encode_secure_envelope, is_secure_envelope},
    crypto::signature::sign_packet,
    node::direct_upgrade::{DirectUpgradeEvent, DirectUpgradeRouterSink},
    packet::Packet,
    packet_processor::{ChunkAssembler, ChunkAssemblerResult, PacketProcessor},
    protocol::control::NetworkControlPayload,
    services::{MetricsProvider, PacketPublisher, SessionRegistry, SessionSelector},
    sessions::{
        LinkKind, Session, SessionMetrics, manager::SessionManager, session::IncomingPacket,
    },
    types::{PeerId, SessionId},
};

pub const ROUTER_INCOMING_QUEUE_CAP: usize = 16384;
const ROUTER_BROADCAST_CAP: usize = 4096;
const ROUTER_PROCESS_SEMAPHORE_PERMITS: usize = 256;
const ROUTER_FALLBACK_FANOUT: usize = 4;

/// Max idle wait between packets while draining the ingress buffer at
/// shutdown. If no packet arrives within this window the queue is treated
/// as drained.
const ROUTER_DRAIN_IDLE: std::time::Duration = std::time::Duration::from_millis(200);
/// Overall budget for the shutdown drain. Kept below the supervisor's
/// per-task join timeout so the router still finishes within shutdown.
const ROUTER_DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(3);

/// Outcome of [`Router::run`]. Replaces the previous `Result<()>` plus
/// `is_ingress_closed()` side-channel so the supervised loop decides whether
/// to restart from a typed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterRunOutcome {
    /// Cancellation token fired (intentional shutdown). Buffered packets were
    /// drained before returning.
    Cancelled,
    /// `recv()` returned `None` while ingress was closed: clean shutdown.
    IngressClosed,
    /// `recv()` returned `None` while ingress was still open: unexpected, the
    /// supervised loop restarts the router.
    ChannelClosedUnexpectedly,
}

pub struct Router {
    session_manager: Arc<SessionManager>,
    packet_processor: Arc<dyn PacketProcessor>,
    signing_key: Option<Arc<SigningKey>>,
    chunk_assembler: Arc<ChunkAssembler>,
    incoming_tx: Arc<Mutex<Option<mpsc::Sender<IncomingPacket>>>>,
    incoming_broadcast_tx: broadcast::Sender<IncomingPacket>,
    next_request_id: AtomicU64,
    next_secure_seq: AtomicU64,
    our_peer_id: String,
    direct_upgrade: Option<DirectUpgradeRouterSink>,
    direct_upgrade_channel_full: AtomicU64,
    packet_tasks: TaskTracker,
    packet_cancel: CancellationToken,
}

impl Router {
    pub fn new(
        session_manager: Arc<SessionManager>,
        packet_processor: Arc<dyn PacketProcessor>,
        signing_key: Option<Arc<SigningKey>>,
        our_peer_id: impl Into<String>,
        direct_upgrade: Option<DirectUpgradeRouterSink>,
    ) -> (Self, mpsc::Receiver<IncomingPacket>) {
        let our_peer_id = our_peer_id.into();
        let (incoming_tx, incoming_rx) = mpsc::channel::<IncomingPacket>(ROUTER_INCOMING_QUEUE_CAP);
        let (incoming_broadcast_tx, _rx) =
            broadcast::channel::<IncomingPacket>(ROUTER_BROADCAST_CAP);
        let incoming_tx = Arc::new(Mutex::new(Some(incoming_tx)));

        let start_id: u64 = rand::rng().random();
        (
            Self {
                session_manager,
                packet_processor,
                signing_key,
                chunk_assembler: Arc::new(ChunkAssembler::new(our_peer_id.clone())),
                incoming_tx,
                incoming_broadcast_tx,
                next_request_id: AtomicU64::new(start_id),
                next_secure_seq: AtomicU64::new(1),
                our_peer_id,
                direct_upgrade,
                direct_upgrade_channel_full: AtomicU64::new(0),
                packet_tasks: TaskTracker::new(),
                packet_cancel: CancellationToken::new(),
            },
            incoming_rx,
        )
    }

    fn prepare_outgoing(&self, mut packet: Packet) -> Result<Packet> {
        if packet.request_id.is_none() {
            let id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
            packet.request_id = Some(id);
        }
        if !packet.data.is_empty()
            && !packet.receiver.is_empty()
            && packet.receiver != self.our_peer_id
            && !is_secure_envelope(&packet.data)
        {
            let key = derive_shared_key(
                self.signing_key
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Secure transport requires signing key"))?
                    .as_ref(),
                &packet.receiver,
            )?;
            let seq = self.next_secure_seq.fetch_add(1, Ordering::Relaxed);
            packet.data = encode_secure_envelope(&packet.data, key, seq)?;
        }
        if let Some(ref key) = self.signing_key {
            sign_packet(&mut packet, key).map_err(anyhow::Error::msg)?;
        }
        Ok(packet)
    }

    fn try_record_direct_upgrade_fallback(&self, peer_id: &PeerId, bytes: u64) {
        let Some(ref sink) = self.direct_upgrade else {
            return;
        };
        if !sink.enabled {
            return;
        }
        match sink.tx.try_send(DirectUpgradeEvent::FallbackTraffic {
            peer_id: peer_id.clone(),
            bytes,
        }) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                let n = self
                    .direct_upgrade_channel_full
                    .fetch_add(1, Ordering::Relaxed);
                if n == 0 || n % 256 == 0 {
                    let total = n.saturating_add(1);
                    crate::warn!(
                        "[Router] direct_upgrade event queue full (dropped {} events total)",
                        total
                    );
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    pub fn direct_upgrade_queue_drops(&self) -> u64 {
        self.direct_upgrade_channel_full.load(Ordering::Relaxed)
    }

    pub fn incoming_sender(&self) -> mpsc::Sender<IncomingPacket> {
        if let Ok(guard) = self.incoming_tx.lock() {
            if let Some(tx) = guard.as_ref() {
                return tx.clone();
            }
        }
        // Ingress is closed: hand out a sender whose receiver is already
        // dropped so callers get a send error instead of a panic.
        let (tx, _rx) = mpsc::channel(1);
        tx
    }

    pub fn close_incoming(&self) {
        if let Ok(mut guard) = self.incoming_tx.lock() {
            guard.take();
        }
    }

    pub fn is_ingress_closed(&self) -> bool {
        self.incoming_tx
            .lock()
            .map(|guard| guard.is_none())
            .unwrap_or(true)
    }

    /// Bounded drain of in-flight per-packet processing tasks.
    ///
    /// Lets tasks finish within `drain_timeout`; tasks still running after
    /// that are cancelled via the packet cancellation token and awaited
    /// briefly so they do not outlive shutdown.
    pub async fn shutdown_packet_tasks(&self, drain_timeout: std::time::Duration) {
        self.packet_tasks.close();
        if tokio::time::timeout(drain_timeout, self.packet_tasks.wait())
            .await
            .is_err()
        {
            crate::warn!(
                "[Router] packet tasks did not drain within {:?}, cancelling",
                drain_timeout
            );
            self.packet_cancel.cancel();
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(1), self.packet_tasks.wait())
                    .await;
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<IncomingPacket> {
        self.incoming_broadcast_tx.subscribe()
    }

    pub(crate) fn broadcast_incoming_after_decrypt(&self, incoming: IncomingPacket) {
        let _ = self.incoming_broadcast_tx.send(incoming);
    }

    pub async fn send_to_session(&self, session_id: SessionId, packet: Packet) -> Result<u64> {
        let Some(session) = SessionSelector::session(self.session_manager.as_ref(), &session_id)
        else {
            return Err(anyhow::anyhow!("Session '{}' not found", session_id));
        };
        let packet = self.prepare_outgoing(packet)?;
        let request_id = packet.request_id.ok_or_else(|| {
            anyhow::anyhow!("internal: request_id missing after prepare_outgoing")
        })?;
        match session.send(packet).await {
            Ok(bytes) => {
                MetricsProvider::record_packets_sent(
                    self.session_manager.as_ref(),
                    &session_id,
                    bytes,
                );
                Ok(request_id)
            }
            Err(e) => {
                MetricsProvider::record_send_error(self.session_manager.as_ref(), &session_id);
                let _ = self.session_manager.close_session(&session_id).await;
                Err(e)
            }
        }
    }

    pub async fn send_to_peer(
        &self,
        peer_id: PeerId,
        packet: Packet,
        exclude_from: Option<PeerId>,
    ) -> Result<u64> {
        let packet = self.prepare_outgoing(packet)?;
        let request_id = packet.request_id.ok_or_else(|| {
            anyhow::anyhow!("internal: request_id missing after prepare_outgoing")
        })?;
        let is_control_packet = NetworkControlPayload::decode(&packet.data).is_ok();
        let in_nodes = packet.nodes.iter().any(|n| n == peer_id.as_str());
        if in_nodes || exclude_from.as_ref() == Some(&peer_id) {
            return Err(anyhow::anyhow!(
                "No route to peer '{}': target on path or excluded",
                peer_id
            ));
        }
        if let Some(session) =
            SessionSelector::best_session_for_peer(self.session_manager.as_ref(), &peer_id)
        {
            let session_id = SessionId::from(session.id().to_string());
            match session.send(packet.clone()).await {
                Ok(bytes) => {
                    MetricsProvider::record_packets_sent(
                        self.session_manager.as_ref(),
                        &session_id,
                        bytes,
                    );
                    return Ok(request_id);
                }
                Err(e) => {
                    MetricsProvider::record_send_error(self.session_manager.as_ref(), &session_id);
                    let _ = self.session_manager.close_session(&session_id).await;
                    return Err(e);
                }
            }
        }

        // Control packets should not use flood fallback.
        // If we lost a direct session temporarily (e.g. during pruning), flooding
        // creates many duplicate forwards and max_hops noise.
        if is_control_packet {
            return Err(anyhow::anyhow!(
                "No direct session for control packet to '{}'",
                peer_id
            ));
        }

        let peers = SessionSelector::peers_sorted_by_score(self.session_manager.as_ref());
        if peers.is_empty() {
            return Err(anyhow::anyhow!(
                "No sessions for peer '{}' and no neighbors to broadcast",
                peer_id
            ));
        }
        self.try_record_direct_upgrade_fallback(&peer_id, packet.wire_size_estimate());
        let mut any_ok = false;
        let mut sent_count = 0usize;
        let mut last_err = None;
        for neighbor in peers {
            if exclude_from.as_ref() == Some(&neighbor) {
                continue;
            }
            if packet.nodes.iter().any(|n| n == neighbor.as_str()) {
                continue;
            }
            if let Some(session) =
                SessionSelector::best_session_for_peer(self.session_manager.as_ref(), &neighbor)
            {
                let session_id = SessionId::from(session.id().to_string());
                match session.send(packet.clone()).await {
                    Ok(bytes) => {
                        MetricsProvider::record_packets_sent(
                            self.session_manager.as_ref(),
                            &session_id,
                            bytes,
                        );
                        any_ok = true;
                        sent_count += 1;
                        if sent_count >= ROUTER_FALLBACK_FANOUT {
                            break;
                        }
                    }
                    Err(e) => {
                        MetricsProvider::record_send_error(
                            self.session_manager.as_ref(),
                            &session_id,
                        );
                        let _ = self.session_manager.close_session(&session_id).await;
                        last_err = Some(e);
                    }
                }
            }
        }
        if any_ok {
            Ok(request_id)
        } else {
            last_err.map_or_else(
                || Err(anyhow::anyhow!("No sessions for peer '{}'", peer_id)),
                Err,
            )
        }
    }

    pub fn register_session(
        &self,
        peer_id: PeerId,
        session_id: SessionId,
        session: Arc<dyn Session + Send + Sync>,
    ) {
        self.session_manager.register(peer_id, session_id, session);
    }

    pub fn register_session_only(
        &self,
        session_id: SessionId,
        session: Arc<dyn Session + Send + Sync>,
    ) {
        self.session_manager.register_session(session_id, session);
    }

    pub fn set_peer_for_session(&self, session_id: SessionId, peer_id: PeerId) {
        self.session_manager
            .set_peer_for_session(session_id, peer_id);
    }

    pub async fn teardown_session(&self, session_id: &SessionId) -> Result<()> {
        self.session_manager.close_session(session_id).await
    }

    pub fn get_metrics_for_protocol(&self, kind: LinkKind) -> Vec<SessionMetrics> {
        self.session_manager.get_metrics_for_protocol(kind)
    }

    pub fn get_metrics_by_protocol(&self) -> Vec<(LinkKind, Vec<SessionMetrics>)> {
        self.session_manager.get_metrics_by_protocol()
    }

    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.session_manager.get_all_peers()
    }

    /// Routes a single received packet: records metrics, runs chunk
    /// reassembly, broadcasts to subscribers, and spawns the bounded
    /// per-packet processing task.
    fn dispatch_incoming(
        self: &Arc<Self>,
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

        let skip_early_ipc = is_secure_envelope(&incoming.packet.data)
            && (incoming.packet.receiver == self.our_peer_id
                || incoming.packet.receiver.is_empty());
        if !skip_early_ipc {
            let _ = self.incoming_broadcast_tx.send(incoming.clone());
        }

        let processor = self.packet_processor.clone();
        let router = self.clone();
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
                    processor.process(incoming, router).await;
                } => {}
            }
        });
    }

    /// Bounded drain of the ingress buffer at shutdown. Producers are already
    /// cancelled by this point, so the queue only shrinks. Pulls and
    /// dispatches packets until the queue stays idle for `ROUTER_DRAIN_IDLE`,
    /// the channel closes, or `ROUTER_DRAIN_BUDGET` elapses — so buffered
    /// packets are processed instead of silently dropped.
    async fn drain_incoming(
        self: &Arc<Self>,
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
                Ok(Some(incoming)) => self.dispatch_incoming(incoming, semaphore),
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }

    pub async fn run(
        self: Arc<Self>,
        incoming_rx: &mut mpsc::Receiver<IncomingPacket>,
        cancel: CancellationToken,
    ) -> RouterRunOutcome {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(
            ROUTER_PROCESS_SEMAPHORE_PERMITS,
        ));

        loop {
            let incoming = tokio::select! {
                _ = cancel.cancelled() => {
                    // Intentional shutdown: drain whatever readers already
                    // enqueued before exiting so the buffer is not dropped.
                    self.drain_incoming(incoming_rx, &semaphore).await;
                    return RouterRunOutcome::Cancelled;
                }
                maybe = incoming_rx.recv() => match maybe {
                    Some(incoming) => incoming,
                    None => break,
                },
            };
            self.dispatch_incoming(incoming, &semaphore);
        }
        if self.is_ingress_closed() {
            // Intentional shutdown: ingress was closed by NodeRuntime::stop().
            RouterRunOutcome::IngressClosed
        } else {
            RouterRunOutcome::ChannelClosedUnexpectedly
        }
    }
}

#[async_trait]
impl PacketPublisher for Router {
    async fn send_to_session(&self, session_id: SessionId, packet: Packet) -> Result<u64> {
        Router::send_to_session(self, session_id, packet).await
    }

    async fn send_to_peer(
        &self,
        peer_id: PeerId,
        packet: Packet,
        exclude_from: Option<PeerId>,
    ) -> Result<u64> {
        Router::send_to_peer(self, peer_id, packet, exclude_from).await
    }
}

#[async_trait]
impl SessionRegistry for Router {
    fn register_session(
        &self,
        peer_id: PeerId,
        session_id: SessionId,
        session: Arc<dyn Session + Send + Sync>,
    ) {
        Router::register_session(self, peer_id, session_id, session);
    }

    fn register_session_only(
        &self,
        session_id: SessionId,
        session: Arc<dyn Session + Send + Sync>,
    ) {
        Router::register_session_only(self, session_id, session);
    }

    fn set_peer_for_session(&self, session_id: SessionId, peer_id: PeerId) {
        Router::set_peer_for_session(self, session_id, peer_id);
    }

    async fn teardown_session(&self, session_id: &SessionId) -> Result<()> {
        Router::teardown_session(self, session_id).await
    }
}

impl SessionSelector for Router {
    fn session(&self, session_id: &SessionId) -> Option<Arc<dyn Session + Send + Sync>> {
        SessionSelector::session(self.session_manager.as_ref(), session_id)
    }

    fn best_session_for_peer(&self, peer_id: &PeerId) -> Option<Arc<dyn Session + Send + Sync>> {
        SessionSelector::best_session_for_peer(self.session_manager.as_ref(), peer_id)
    }

    fn connected_peers(&self) -> Vec<PeerId> {
        Router::connected_peers(self)
    }

    fn peers_sorted_by_score(&self) -> Vec<PeerId> {
        SessionSelector::peers_sorted_by_score(self.session_manager.as_ref())
    }
}

impl MetricsProvider for Router {
    fn record_packets_sent(&self, session_id: &SessionId, bytes: u64) {
        MetricsProvider::record_packets_sent(self.session_manager.as_ref(), session_id, bytes);
    }

    fn record_send_error(&self, session_id: &SessionId) {
        MetricsProvider::record_send_error(self.session_manager.as_ref(), session_id);
    }

    fn record_packets_received(&self, session_id: &SessionId, bytes: u64) {
        MetricsProvider::record_packets_received(self.session_manager.as_ref(), session_id, bytes);
    }

    fn get_metrics_for_protocol(&self, kind: LinkKind) -> Vec<SessionMetrics> {
        Router::get_metrics_for_protocol(self, kind)
    }

    fn get_metrics_by_protocol(&self) -> Vec<(LinkKind, Vec<SessionMetrics>)> {
        Router::get_metrics_by_protocol(self)
    }

    fn peer_metrics_rollup(&self) -> Vec<(PeerId, Vec<SessionMetrics>)> {
        MetricsProvider::peer_metrics_rollup(self.session_manager.as_ref())
    }

    fn total_sessions_count(&self) -> usize {
        MetricsProvider::total_sessions_count(self.session_manager.as_ref())
    }
}
