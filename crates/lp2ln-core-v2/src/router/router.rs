use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

use crate::{
    crypto::peer_cache::PeerCryptoCache,
    crypto::signature::SignatureFormat,
    node::direct_upgrade::{DirectUpgradeEvent, DirectUpgradeRouterSink},
    packet::Packet,
    packet_processor::PacketProcessor,
    protocol::control::NetworkControlPayload,
    router::dispatch::PacketIngressDispatcher,
    router::egress::PacketEgressSecurity,
    services::{MetricsProvider, PacketPublisher, SessionRegistry, SessionSelector},
    sessions::{
        LinkKind, Session, SessionMetrics, manager::SessionManager, session::IncomingPacket,
    },
    transport::tcp::codec::encode_packet,
    types::{PeerId, SessionId},
};

pub const ROUTER_INCOMING_QUEUE_CAP: usize = 16384;
const ROUTER_BROADCAST_CAP: usize = 4096;
pub const ROUTER_PROCESS_SEMAPHORE_PERMITS: usize = 256;
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
    egress: PacketEgressSecurity,
    ingress: PacketIngressDispatcher,
    incoming_tx: Arc<Mutex<Option<mpsc::Sender<IncomingPacket>>>>,
    incoming_broadcast_tx: broadcast::Sender<Arc<IncomingPacket>>,
    peer_cache: Arc<PeerCryptoCache>,
    direct_upgrade: Option<DirectUpgradeRouterSink>,
    direct_upgrade_channel_full: AtomicU64,
}

impl Router {
    pub fn new(
        session_manager: Arc<SessionManager>,
        packet_processor: Arc<dyn PacketProcessor>,
        signing_key: Option<Arc<k256::ecdsa::SigningKey>>,
        our_peer_id: impl Into<String>,
        direct_upgrade: Option<DirectUpgradeRouterSink>,
    ) -> (Self, mpsc::Receiver<IncomingPacket>) {
        Self::new_with_caps(
            session_manager,
            packet_processor,
            signing_key,
            our_peer_id,
            direct_upgrade,
            PeerCryptoCache::new(),
            ROUTER_INCOMING_QUEUE_CAP,
            ROUTER_BROADCAST_CAP,
            ROUTER_PROCESS_SEMAPHORE_PERMITS,
            SignatureFormat::V2Hash,
        )
    }

    pub fn new_with_caps(
        session_manager: Arc<SessionManager>,
        packet_processor: Arc<dyn PacketProcessor>,
        signing_key: Option<Arc<k256::ecdsa::SigningKey>>,
        our_peer_id: impl Into<String>,
        direct_upgrade: Option<DirectUpgradeRouterSink>,
        peer_cache: Arc<PeerCryptoCache>,
        incoming_cap: usize,
        broadcast_cap: usize,
        worker_concurrency: usize,
        signature_format: SignatureFormat,
    ) -> (Self, mpsc::Receiver<IncomingPacket>) {
        let our_peer_id = our_peer_id.into();
        let (incoming_tx, incoming_rx) = mpsc::channel::<IncomingPacket>(incoming_cap);
        let (incoming_broadcast_tx, _rx) =
            broadcast::channel::<Arc<IncomingPacket>>(broadcast_cap);
        let incoming_tx = Arc::new(Mutex::new(Some(incoming_tx)));

        let start_id: u64 = rand::rng().random();
        let chunk_assembler = Arc::new(crate::packet_processor::ChunkAssembler::new(
            our_peer_id.clone(),
        ));
        let ingress = PacketIngressDispatcher::new(
            session_manager.clone(),
            packet_processor,
            chunk_assembler,
            incoming_broadcast_tx.clone(),
            our_peer_id.clone(),
            worker_concurrency,
        );
        let egress = PacketEgressSecurity::new(
            signing_key,
            our_peer_id.clone(),
            start_id,
            peer_cache.clone(),
            signature_format,
        );

        (
            Self {
                session_manager,
                egress,
                ingress,
                incoming_tx,
                incoming_broadcast_tx,
                peer_cache,
                direct_upgrade,
                direct_upgrade_channel_full: AtomicU64::new(0),
            },
            incoming_rx,
        )
    }

    fn prepare_outgoing(&self, packet: Packet) -> Result<Packet> {
        self.egress.prepare_outgoing(packet)
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

    pub async fn shutdown_packet_tasks(&self, drain_timeout: std::time::Duration) {
        let _ = drain_timeout;
        self.ingress.shutdown_workers().await;
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<IncomingPacket>> {
        self.incoming_broadcast_tx.subscribe()
    }

    pub(crate) fn broadcast_incoming_after_decrypt(&self, incoming: IncomingPacket) {
        self.ingress.broadcast_incoming_after_decrypt(incoming);
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
        let is_control_packet = NetworkControlPayload::is_likely_control_packet(&packet.data);
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
            let wire = encode_packet(packet)?;
            match session.send_wire(wire).await {
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
        let hop_nodes = packet.nodes.clone();
        let wire = encode_packet(packet)?;
        let mut any_ok = false;
        let mut last_err = None;
        for neighbor in peers {
            if exclude_from.as_ref() == Some(&neighbor) {
                continue;
            }
            if hop_nodes.iter().any(|n| n == neighbor.as_str()) {
                continue;
            }
            if let Some(session) =
                SessionSelector::best_session_for_peer(self.session_manager.as_ref(), &neighbor)
            {
                let session_id = SessionId::from(session.id().to_string());
                match session.send_wire(wire.clone()).await {
                    Ok(bytes) => {
                        MetricsProvider::record_packets_sent(
                            self.session_manager.as_ref(),
                            &session_id,
                            bytes,
                        );
                        any_ok = true;
                        // One successful neighbor is enough; fanning out the same
                        // wire frame duplicates secure seqs on alternate paths.
                        break;
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
        if let Some(peer_id) = self.session_manager.get_peer_for_session(session_id) {
            self.peer_cache.remove_peer(peer_id.as_str());
        }
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

    pub async fn run(
        self: Arc<Self>,
        incoming_rx: &mut mpsc::Receiver<IncomingPacket>,
        cancel: CancellationToken,
    ) -> RouterRunOutcome {
        loop {
            let incoming = tokio::select! {
                _ = cancel.cancelled() => {
                    self.ingress
                        .drain_incoming(self.clone(), incoming_rx)
                        .await;
                    return RouterRunOutcome::Cancelled;
                }
                maybe = incoming_rx.recv() => match maybe {
                    Some(incoming) => incoming,
                    None => break,
                },
            };
            self.ingress.dispatch_incoming(self.clone(), incoming);
        }
        if self.is_ingress_closed() {
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
