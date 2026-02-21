use async_trait::async_trait;
use std::sync::Arc;
use crate::crypto::signature::verify_packet;
use crate::packet::Packet;
use crate::router::Router;
use crate::sessions::IncomingPacket;
use crate::types::{PeerId, SessionId};

pub const PING: &[u8] = b"ping";
pub const PONG: &[u8] = b"pong";

#[async_trait]
pub trait PacketProcessor: Send + Sync {
    async fn process(&self, incoming_packet: IncomingPacket, router: Arc<Router>);
}

pub struct DefaultPacketProcessor {
    our_peer_id: String,
    allow_unsigned_packets: bool,
}

impl DefaultPacketProcessor {
    pub fn new(our_peer_id: impl Into<String>, allow_unsigned_packets: bool) -> Self {
        Self {
            our_peer_id: our_peer_id.into(),
            allow_unsigned_packets,
        }
    }
}

#[async_trait]
impl PacketProcessor for DefaultPacketProcessor {
    async fn process(&self, incoming_packet: IncomingPacket, router: Arc<Router>) {
        if !self.allow_unsigned_packets {
            if let Err(e) = verify_packet(&incoming_packet.packet) {
                crate::processor!(
                    "Invalid or missing signature, dropping packet from {}: {}",
                    incoming_packet.packet.sender, e
                );
                return;
            }
        }

        let session_id = SessionId::from(incoming_packet.session_id.clone());
        let from = incoming_packet
            .from_node
            .as_deref()
            .unwrap_or_else(|| incoming_packet.packet.sender.as_str());
        let peer_id = PeerId::from_str(from);
        router.set_peer_for_session(session_id.clone(), peer_id.clone());

        let receiver = incoming_packet.packet.receiver.as_str();

        if receiver == self.our_peer_id || receiver.is_empty() {
            match incoming_packet.packet.data.as_slice() {
                PING => {
                    crate::processor!("Ping from {} -> sending pong", from);
                    let pong = Packet {
                        signature: None,
                        data: PONG.to_vec(),
                        nodes: vec![],
                        sender: self.our_peer_id.clone(),
                        receiver: from.to_string(),
                        max_hops: 1,
                        chunk_stream_id: None,
                        chunk_index: None,
                        total_chunks: None,
                    };
                    if let Err(e) = router.send_to_peer(peer_id, pong, None).await {
                        crate::error!("[PacketProcessor] Failed to send pong: {}", e);
                    }
                }
                PONG => {
                    crate::processor!("Pong from {}", from);
                }
                _ => {
                    crate::processor!(
                        "Received packet (for us): Session ID: {}, From: {:?}, Sender: {}, Receiver: {}, Data: {} bytes",
                        incoming_packet.session_id,
                        incoming_packet.from_node,
                        incoming_packet.packet.sender,
                        incoming_packet.packet.receiver,
                        incoming_packet.packet.data.len()
                    );
                }
            }
        } else {
            let mut packet = incoming_packet.packet.clone();
            packet.nodes.push(self.our_peer_id.clone());
            let target = PeerId::from_str(receiver);
            let sid = SessionId::from(incoming_packet.session_id.clone());
            let ok = if target == peer_id {
                router.send_to_session(sid, packet.clone()).await.is_ok()
            } else {
                false
            };
            let ok = ok || router.send_to_peer(target, packet, Some(peer_id)).await.is_ok();
            if !ok {
                crate::error!("[PacketProcessor] Failed to forward to {}: No sessions for peer", receiver);
            } else {
                crate::processor!("Forwarded packet to {}", receiver);
            }
        }
    }
}
