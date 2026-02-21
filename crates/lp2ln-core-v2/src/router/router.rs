use std::sync::Arc;

use anyhow::Result;
use k256::ecdsa::SigningKey;
use tokio::sync::{broadcast, mpsc};

use crate::{
    crypto::signature::sign_packet,
    packet::Packet,
    packet_processor::{ChunkAssembler, ChunkAssemblerResult, PacketProcessor},
    sessions::{
        manager::SessionManager, session::IncomingPacket, LinkKind, Session, SessionMetrics,
    },
    types::{PeerId, SessionId},
};

pub struct Router {
    session_manager: Arc<SessionManager>,
    packet_processor: Arc<dyn PacketProcessor>,
    signing_key: Option<Arc<SigningKey>>,
    chunk_assembler: Arc<ChunkAssembler>,
    incoming_tx: mpsc::Sender<IncomingPacket>,
    incoming_broadcast_tx: broadcast::Sender<IncomingPacket>,
}

impl Router {
    pub fn new(
        session_manager: Arc<SessionManager>,
        packet_processor: Arc<dyn PacketProcessor>,
        signing_key: Option<Arc<SigningKey>>,
        our_peer_id: impl Into<String>,
    ) -> (Self, mpsc::Receiver<IncomingPacket>) {
        let (incoming_tx, incoming_rx) = mpsc::channel::<IncomingPacket>(1024);
        let (incoming_broadcast_tx, _rx) = broadcast::channel::<IncomingPacket>(1024);

        (
            Self {
                session_manager,
                packet_processor,
                signing_key,
                chunk_assembler: Arc::new(ChunkAssembler::new(our_peer_id)),
                incoming_tx,
                incoming_broadcast_tx,
            },
            incoming_rx,
        )
    }

    fn prepare_outgoing(&self, mut packet: Packet) -> Result<Packet> {
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

    pub async fn send_to_session(&self, session_id: SessionId, packet: Packet) -> Result<()> {
        let Some(session) = self.session_manager.get(&session_id) else {
            return Err(anyhow::anyhow!("Session '{}' not found", session_id));
        };
        let packet = self.prepare_outgoing(packet)?;
        match session.send(packet).await {
            Ok(bytes) => {
                self.session_manager
                    .update_metrics(&session_id, |m| m.increment_packets_sent(bytes));
                Ok(())
            }
            Err(e) => {
                self.session_manager
                    .update_metrics(&session_id, |m| m.increment_send_errors());
                Err(e)
            }
        }
    }

    pub async fn send_to_peer(
        &self,
        peer_id: PeerId,
        packet: Packet,
        exclude_from: Option<PeerId>,
    ) -> Result<()> {
        let packet = self.prepare_outgoing(packet)?;
        let in_nodes = packet.nodes.iter().any(|n| n == peer_id.as_str());
        if in_nodes || exclude_from.as_ref() == Some(&peer_id) {
        } else if let Some(session) = self.session_manager.get_best_session_for_peer(&peer_id) {
            let session_id = SessionId::from(session.id().to_string());
            match session.send(packet.clone()).await {
                Ok(bytes) => {
                    self.session_manager
                        .update_metrics(&session_id, |m| m.increment_packets_sent(bytes));
                    return Ok(());
                }
                Err(e) => {
                    self.session_manager
                        .update_metrics(&session_id, |m| m.increment_send_errors());
                    return Err(e);
                }
            }
        }

        let peers = self.session_manager.get_all_peers();
        if peers.is_empty() {
            return Err(anyhow::anyhow!(
                "No sessions for peer '{}' and no neighbors to broadcast",
                peer_id
            ));
        }
        let mut any_ok = false;
        let mut last_err = None;
        for neighbor in peers {
            if packet.nodes.iter().any(|n| n == neighbor.as_str()) {
                continue;
            }
            if exclude_from.as_ref() == Some(&neighbor) {
                continue;
            }
            if let Some(session) = self.session_manager.get_best_session_for_peer(&neighbor) {
                let session_id = SessionId::from(session.id().to_string());
                match session.send(packet.clone()).await {
                    Ok(bytes) => {
                        self.session_manager
                            .update_metrics(&session_id, |m| m.increment_packets_sent(bytes));
                        any_ok = true;
                    }
                    Err(e) => {
                        self.session_manager
                            .update_metrics(&session_id, |m| m.increment_send_errors());
                        last_err = Some(e);
                    }
                }
            }
        }
        if any_ok {
            Ok(())
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

    pub fn get_metrics_for_protocol(&self, kind: LinkKind) -> Vec<SessionMetrics> {
        self.session_manager.get_metrics_for_protocol(kind)
    }

    pub fn get_metrics_by_protocol(&self) -> Vec<(LinkKind, Vec<SessionMetrics>)> {
        self.session_manager.get_metrics_by_protocol()
    }

    pub async fn run(self: Arc<Self>, mut incoming_rx: mpsc::Receiver<IncomingPacket>) {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(100));

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
            let permit = semaphore.clone().acquire_owned().await;

            tokio::spawn(async move {
                let _permit = permit;
                processor.process(incoming, router).await;
            });
        }
    }
}
