use async_trait::async_trait;
use std::sync::Arc;

use dashmap::DashMap;

use crate::crypto::NodeKeypair;
use crate::crypto::peer_cache::PeerCryptoCache;
use crate::crypto::secure_channel::{ReplayWindow, is_secure_envelope};
use crate::crypto::signature::verify_packet_with_key;
use crate::nat::NatTraversalState;
use crate::router::Router;
use crate::services::{PacketPublisher, SessionRegistry, SessionSelector};
use crate::sessions::IncomingPacket;
use crate::topology::PeerCatalog;
use crate::types::{PeerId, SessionId};

pub const PING: &[u8] = b"ping";
pub const PONG: &[u8] = b"pong";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessAction {
    Delivered,
    Dropped {
        reason: &'static str,
    },
    CloseSession {
        session_id: SessionId,
        reason: &'static str,
    },
}

#[async_trait]
pub trait PacketProcessor: Send + Sync {
    async fn process(&self, incoming_packet: IncomingPacket, router: Arc<Router>) -> ProcessAction;
}

pub struct DefaultPacketProcessor {
    our_peer_id: String,
    allow_unsigned_packets: bool,
    peer_catalog: Arc<PeerCatalog>,
    peer_discovery_random_fraction: f32,
    nat_state: Arc<NatTraversalState>,
    local_keypair: NodeKeypair,
    peer_cache: Arc<PeerCryptoCache>,
    replay_windows: Arc<DashMap<String, ReplayWindow>>,
    session_drop_counts: Arc<DashMap<SessionId, u32>>,
    forward_hop_resolver: Option<Arc<dyn Fn(&str, &str) -> Option<String> + Send + Sync>>,
}

impl DefaultPacketProcessor {
    pub fn new(
        our_peer_id: impl Into<String>,
        allow_unsigned_packets: bool,
        peer_catalog: Arc<PeerCatalog>,
        peer_discovery_random_fraction: f32,
        nat_state: Arc<NatTraversalState>,
        local_keypair: NodeKeypair,
        peer_cache: Arc<PeerCryptoCache>,
    ) -> Self {
        Self {
            our_peer_id: our_peer_id.into(),
            allow_unsigned_packets,
            peer_catalog,
            peer_discovery_random_fraction: peer_discovery_random_fraction.clamp(0.0, 0.9),
            nat_state,
            local_keypair,
            peer_cache,
            replay_windows: Arc::new(DashMap::new()),
            session_drop_counts: Arc::new(DashMap::new()),
            forward_hop_resolver: None,
        }
    }

    pub fn with_forward_hop_resolver(
        mut self,
        resolver: Arc<dyn Fn(&str, &str) -> Option<String> + Send + Sync>,
    ) -> Self {
        self.forward_hop_resolver = Some(resolver);
        self
    }

    pub fn peer_cache(&self) -> &Arc<PeerCryptoCache> {
        &self.peer_cache
    }

    fn record_drop(&self, session_id: SessionId, reason: &'static str) -> ProcessAction {
        let count = self
            .session_drop_counts
            .entry(session_id.clone())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        if *count >= 3 {
            self.session_drop_counts.remove(&session_id);
            ProcessAction::CloseSession { session_id, reason }
        } else {
            ProcessAction::Dropped { reason }
        }
    }
}

#[async_trait]
impl PacketProcessor for DefaultPacketProcessor {
    async fn process(&self, incoming_packet: IncomingPacket, router: Arc<Router>) -> ProcessAction {
        let session_id = SessionId::from(incoming_packet.session_id.clone());
        let mut packet = incoming_packet.packet;

        if !self.allow_unsigned_packets {
            let vk = self.peer_cache.verifying_key(&packet.sender).ok();
            if let Err(e) = verify_packet_with_key(&packet, vk.as_ref()) {
                crate::processor!(
                    "Invalid or missing signature, dropping packet from {}: {}",
                    packet.sender,
                    e
                );
                return self.record_drop(session_id, "invalid signature");
            }
        }

        // `from_node` is the immediate link neighbor. On relay hops it differs from
        // `packet.sender` (the original author). Enforce equality only on the first
        // hop where the neighbor must be the logical sender; signature checks still
        // apply on every hop.
        if packet.nodes.is_empty() {
            if let Some(bound_peer) = incoming_packet.from_node.as_deref() {
                if bound_peer != packet.sender {
                    crate::processor!(
                        "Session peer_id mismatch: bound={} packet.sender={}, dropping",
                        bound_peer,
                        packet.sender
                    );
                    return self.record_drop(session_id, "session peer mismatch");
                }
            }
        }

        if is_secure_envelope(&packet.data)
            && (packet.receiver == self.our_peer_id || packet.receiver.is_empty())
        {
            let (seq, plaintext) = match self.peer_cache.decode_secure(
                self.local_keypair.signing_key(),
                &packet.sender,
                &packet.data,
            ) {
                Ok(v) => v,
                Err(e) => {
                    crate::processor!(
                        "Failed to decrypt secure envelope from {}: {}",
                        packet.sender,
                        e
                    );
                    return self.record_drop(session_id, "decrypt failed");
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
                return self.record_drop(session_id, "replay detected");
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
                self.session_drop_counts.remove(&session_id);
                return ProcessAction::Delivered;
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
            let forward_target = self
                .forward_hop_resolver
                .as_ref()
                .and_then(|resolve| resolve(&self.our_peer_id, receiver.as_str()))
                .map(|hop| PeerId::from_str(hop.as_str()))
                .unwrap_or_else(|| PeerId::from_str(receiver.as_str()));
            super::forwarding::forward_packet(
                packet,
                incoming_packet.session_id.as_str(),
                &self.our_peer_id,
                &peer_id,
                forward_target,
                publisher,
            )
            .await;
        }
        self.session_drop_counts.remove(&session_id);
        ProcessAction::Delivered
    }
}
