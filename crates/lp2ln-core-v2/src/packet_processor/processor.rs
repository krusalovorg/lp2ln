use async_trait::async_trait;
use std::sync::Arc;

use dashmap::DashMap;

use crate::crypto::NodeKeypair;
use crate::crypto::secure_channel::{
    ReplayWindow, decode_secure_envelope, derive_shared_key, is_secure_envelope,
};
use crate::crypto::signature::verify_packet;
use crate::nat::NatTraversalState;
use crate::router::Router;
use crate::services::{PacketPublisher, SessionRegistry, SessionSelector};
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
    nat_state: Arc<NatTraversalState>,
    local_keypair: NodeKeypair,
    replay_windows: Arc<DashMap<String, ReplayWindow>>,
}

impl DefaultPacketProcessor {
    pub fn new(
        our_peer_id: impl Into<String>,
        allow_unsigned_packets: bool,
        peer_catalog: Arc<PeerCatalog>,
        peer_discovery_random_fraction: f32,
        nat_state: Arc<NatTraversalState>,
        local_keypair: NodeKeypair,
    ) -> Self {
        Self {
            our_peer_id: our_peer_id.into(),
            allow_unsigned_packets,
            peer_catalog,
            peer_discovery_random_fraction: peer_discovery_random_fraction.clamp(0.0, 0.9),
            nat_state,
            local_keypair,
            replay_windows: Arc::new(DashMap::new()),
        }
    }
}

#[async_trait]
impl PacketProcessor for DefaultPacketProcessor {
    async fn process(&self, incoming_packet: IncomingPacket, router: Arc<Router>) {
        let mut packet = incoming_packet.packet.clone();
        if !self.allow_unsigned_packets {
            if let Err(e) = verify_packet(&packet) {
                crate::processor!(
                    "Invalid or missing signature, dropping packet from {}: {}",
                    packet.sender,
                    e
                );
                return;
            }
        }

        let session_id = SessionId::from(incoming_packet.session_id.clone());

        if let Some(bound_peer) = incoming_packet.from_node.as_deref() {
            if bound_peer != packet.sender {
                crate::processor!(
                    "Session peer_id mismatch: bound={} packet.sender={}, dropping",
                    bound_peer,
                    packet.sender
                );
                return;
            }
        }

        if is_secure_envelope(&packet.data)
            && (packet.receiver == self.our_peer_id || packet.receiver.is_empty())
        {
            let key = match derive_shared_key(self.local_keypair.signing_key(), &packet.sender) {
                Ok(k) => k,
                Err(e) => {
                    crate::processor!("Failed to derive secure key from {}: {}", packet.sender, e);
                    return;
                }
            };
            let (seq, plaintext) = match decode_secure_envelope(&packet.data, key) {
                Ok(v) => v,
                Err(e) => {
                    crate::processor!(
                        "Failed to decrypt secure envelope from {}: {}",
                        packet.sender,
                        e
                    );
                    return;
                }
            };
            let mut window = self
                .replay_windows
                .entry(packet.sender.clone())
                .or_default();
            if !window.check_and_record(seq) {
                crate::processor!(
                    "Replay detected from {} with seq {}, dropping",
                    packet.sender,
                    seq
                );
                return;
            }
            packet.data = plaintext;
            router.broadcast_incoming_after_decrypt(IncomingPacket {
                session_id: incoming_packet.session_id.clone(),
                from_node: incoming_packet.from_node.clone(),
                packet: packet.clone(),
            });
        }

        let from = incoming_packet
            .from_node
            .as_deref()
            .unwrap_or_else(|| packet.sender.as_str());
        let peer_id = PeerId::from_str(from);
        let registry: &dyn SessionRegistry = router.as_ref();
        registry.set_peer_for_session(session_id.clone(), peer_id.clone());

        let receiver = packet.receiver.clone();
        let publisher: &dyn PacketPublisher = router.as_ref();
        let selector: &dyn SessionSelector = router.as_ref();

        if receiver == self.our_peer_id || receiver.is_empty() {
            if super::control::try_handle_control_packet(
                &packet,
                &self.our_peer_id,
                from,
                &peer_id,
                self.peer_catalog.as_ref(),
                publisher,
                selector,
                self.peer_discovery_random_fraction,
                self.nat_state.as_ref(),
            )
            .await
            {
                return;
            }
            super::local::handle_local_packet(
                &packet.data,
                packet.request_id,
                &self.our_peer_id,
                from,
                &peer_id,
                &session_id,
                self.peer_catalog.as_ref(),
                publisher,
            )
            .await;
        } else {
            super::forwarding::forward_packet(
                packet,
                incoming_packet.session_id.as_str(),
                &self.our_peer_id,
                &peer_id,
                PeerId::from_str(receiver.as_str()),
                publisher,
            )
            .await;
        }
    }
}
