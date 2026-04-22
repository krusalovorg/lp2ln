use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use rand::Rng;
use k256::ecdsa::SigningKey;
use tokio::sync::{broadcast, mpsc};

use crate::{
    crypto::secure_channel::{derive_shared_key, encode_secure_envelope, is_secure_envelope},
    crypto::signature::sign_packet,
    packet::Packet,
    packet_processor::{ChunkAssembler, ChunkAssemblerResult, PacketProcessor},
    protocol::control::NetworkControlPayload,
    sessions::{
        manager::SessionManager, session::IncomingPacket, LinkKind, Session, SessionMetrics,
    },
    types::{PeerId, SessionId},
};

pub const ROUTER_INCOMING_QUEUE_CAP: usize = 16384;
const ROUTER_BROADCAST_CAP: usize = 4096;
const ROUTER_PROCESS_SEMAPHORE_PERMITS: usize = 256;
const ROUTER_FALLBACK_FANOUT: usize = 4;

pub struct Router {
    session_manager: Arc<SessionManager>,
    packet_processor: Arc<dyn PacketProcessor>,
    signing_key: Option<Arc<SigningKey>>,
    chunk_assembler: Arc<ChunkAssembler>,
    incoming_tx: mpsc::Sender<IncomingPacket>,
    incoming_broadcast_tx: broadcast::Sender<IncomingPacket>,
    next_request_id: AtomicU64,
    next_secure_seq: AtomicU64,
    our_peer_id: String,
}

impl Router {
    pub fn new(
        session_manager: Arc<SessionManager>,
        packet_processor: Arc<dyn PacketProcessor>,
        signing_key: Option<Arc<SigningKey>>,
        our_peer_id: impl Into<String>,
    ) -> (Self, mpsc::Receiver<IncomingPacket>) {
        let our_peer_id = our_peer_id.into();
        let (incoming_tx, incoming_rx) = mpsc::channel::<IncomingPacket>(ROUTER_INCOMING_QUEUE_CAP);
        let (incoming_broadcast_tx, _rx) = broadcast::channel::<IncomingPacket>(ROUTER_BROADCAST_CAP);

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

    pub fn incoming_sender(&self) -> mpsc::Sender<IncomingPacket> {
        self.incoming_tx.clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<IncomingPacket> {
        self.incoming_broadcast_tx.subscribe()
    }

    pub async fn send_to_session(&self, session_id: SessionId, packet: Packet) -> Result<u64> {
        let Some(session) = self.session_manager.get(&session_id) else {
            return Err(anyhow::anyhow!("Session '{}' not found", session_id));
        };
        let packet = self.prepare_outgoing(packet)?;
        let request_id = packet
            .request_id
            .ok_or_else(|| anyhow::anyhow!("internal: request_id missing after prepare_outgoing"))?;
        match session.send(packet).await {
            Ok(bytes) => {
                self.session_manager
                    .update_metrics(&session_id, |m| m.increment_packets_sent(bytes));
                Ok(request_id)
            }
            Err(e) => {
                self.session_manager
                    .update_metrics(&session_id, |m| m.increment_send_errors());
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
        let request_id = packet
            .request_id
            .ok_or_else(|| anyhow::anyhow!("internal: request_id missing after prepare_outgoing"))?;
        let is_control_packet = NetworkControlPayload::decode(&packet.data).is_ok();
        let in_nodes = packet.nodes.iter().any(|n| n == peer_id.as_str());
        if in_nodes || exclude_from.as_ref() == Some(&peer_id) {
            return Err(anyhow::anyhow!(
                "No route to peer '{}': target on path or excluded",
                peer_id
            ));
        }
        if let Some(session) = self.session_manager.get_best_session_for_peer(&peer_id) {
            let session_id = SessionId::from(session.id().to_string());
            match session.send(packet.clone()).await {
                Ok(bytes) => {
                    self.session_manager
                        .update_metrics(&session_id, |m| m.increment_packets_sent(bytes));
                    return Ok(request_id);
                }
                Err(e) => {
                    self.session_manager
                        .update_metrics(&session_id, |m| m.increment_send_errors());
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

        let peers = self.session_manager.get_all_peers_sorted_by_score();
        if peers.is_empty() {
            return Err(anyhow::anyhow!(
                "No sessions for peer '{}' and no neighbors to broadcast",
                peer_id
            ));
        }
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
            if let Some(session) = self.session_manager.get_best_session_for_peer(&neighbor) {
                let session_id = SessionId::from(session.id().to_string());
                match session.send(packet.clone()).await {
                    Ok(bytes) => {
                        self.session_manager
                            .update_metrics(&session_id, |m| m.increment_packets_sent(bytes));
                        any_ok = true;
                        sent_count += 1;
                        if sent_count >= ROUTER_FALLBACK_FANOUT {
                            break;
                        }
                    }
                    Err(e) => {
                        self.session_manager
                            .update_metrics(&session_id, |m| m.increment_send_errors());
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

    pub async fn run(
        self: Arc<Self>,
        incoming_rx: &mut mpsc::Receiver<IncomingPacket>,
    ) -> Result<()> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(ROUTER_PROCESS_SEMAPHORE_PERMITS));

        while let Some(incoming) = incoming_rx.recv().await {
            let session_id = SessionId::from(incoming.session_id.clone());
            let bytes_estimate = incoming.packet.wire_size_estimate();
            self.session_manager.update_metrics(&session_id, |m| {
                m.increment_packets_received(bytes_estimate)
            });

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

            let Some(incoming) = to_process else {
                continue;
            };

            let _ = self.incoming_broadcast_tx.send(incoming.clone());

            let processor = self.packet_processor.clone();
            let router = self.clone();
            let semaphore = semaphore.clone();
            tokio::spawn(async move {
                let Ok(permit) = semaphore.acquire_owned().await else {
                    return;
                };
                let _permit = permit;
                processor.process(incoming, router).await;
            });
        }
        Err(anyhow::anyhow!(
            "router incoming channel closed; router loop stopped"
        ))
    }
}
