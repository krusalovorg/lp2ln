use async_trait::async_trait;
use std::sync::Arc;

use crate::crypto::signature::verify_packet;
use crate::router::Router;
use crate::sessions::IncomingPacket;
use crate::topology::PeerCatalog;
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
    peer_catalog: Arc<PeerCatalog>,
    peer_discovery_random_fraction: f32,
}

impl DefaultPacketProcessor {
    pub fn new(
        our_peer_id: impl Into<String>,
        allow_unsigned_packets: bool,
        peer_catalog: Arc<PeerCatalog>,
        peer_discovery_random_fraction: f32,
    ) -> Self {
        Self {
            our_peer_id: our_peer_id.into(),
            allow_unsigned_packets,
            peer_catalog,
            peer_discovery_random_fraction: peer_discovery_random_fraction.clamp(0.0, 0.9),
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

        let receiver = incoming_packet.packet.receiver.clone();

        if receiver == self.our_peer_id || receiver.is_empty() {
            if super::control::try_handle_control_packet(
                &incoming_packet.packet,
                &self.our_peer_id,
                from,
                &peer_id,
                self.peer_catalog.as_ref(),
                router.clone(),
                self.peer_discovery_random_fraction,
            )
            .await
            {
                return;
            }
            super::local::handle_local_packet(
                &incoming_packet.packet.data,
                incoming_packet.packet.request_id,
                &self.our_peer_id,
                from,
                &peer_id,
                &session_id,
                self.peer_catalog.as_ref(),
                router,
            )
            .await;
        } else {
            super::forwarding::forward_packet(
                incoming_packet.packet,
                incoming_packet.session_id.as_str(),
                &self.our_peer_id,
                &peer_id,
                PeerId::from_str(receiver.as_str()),
                router,
            )
            .await;
        }
    }
}
