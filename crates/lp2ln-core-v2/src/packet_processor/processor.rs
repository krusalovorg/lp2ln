use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::DashMap;

use crate::crypto::NodeKeypair;
use crate::crypto::peer_cache::PeerCryptoCache;
use crate::crypto::secure_channel::{ReplayWindow, is_secure_envelope};
use crate::crypto::signature::verify_packet_with_key;
use crate::nat::NatTraversalState;
use crate::router::{PacketProcessingOrder, Router};
use crate::services::{PacketPublisher, SessionRegistry, SessionSelector};
use crate::sessions::IncomingPacket;
use crate::topology::PeerCatalog;
use crate::types::{PeerId, SessionId};

pub const PING: &[u8] = b"ping";
pub const PONG: &[u8] = b"pong";
const MAX_LEGACY_ORIGINS: usize = 65_536;
const MAX_DEFERRED_INVALID_SESSIONS: usize = 16_384;
const MAX_RESERVED_CONTROL_PAYLOAD: usize = 32 * 1024;

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
    #[doc(hidden)]
    fn parallel_authentication(&self) -> bool {
        false
    }

    #[doc(hidden)]
    async fn process_ordered(
        &self,
        incoming_packet: IncomingPacket,
        router: Arc<Router>,
        _order: PacketProcessingOrder,
    ) -> ProcessAction {
        self.process(incoming_packet, router).await
    }
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
    replay_origins: AtomicUsize,
    session_drop_counts: Arc<DashMap<SessionId, u32>>,
    invalid_session_admission: std::sync::Mutex<()>,
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
            replay_origins: AtomicUsize::new(0),
            session_drop_counts: Arc::new(DashMap::new()),
            invalid_session_admission: std::sync::Mutex::new(()),
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

    fn commit_replay(&self, author: &str, seq: u64) -> Result<bool, ()> {
        use dashmap::mapref::entry::Entry;
        if let Some(mut window) = self.replay_windows.get_mut(author) {
            return Ok(window.check_and_record(seq));
        }
        match self.replay_windows.entry(author.to_owned()) {
            Entry::Occupied(mut entry) => Ok(entry.get_mut().check_and_record(seq)),
            Entry::Vacant(entry) => {
                // Refuse new origins when full; eviction could accept old replays.
                self.replay_origins
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                        (count < MAX_LEGACY_ORIGINS).then(|| count + 1)
                    })
                    .map_err(|_| ())?;
                Ok(entry.insert(ReplayWindow::default()).check_and_record(seq))
            }
        }
    }

    fn record_drop(&self, session_id: SessionId, reason: &'static str) -> ProcessAction {
        let _admit = self.invalid_session_admission.lock().unwrap();
        if self.session_drop_counts.len() >= MAX_DEFERRED_INVALID_SESSIONS
            && !self.session_drop_counts.contains_key(&session_id)
        {
            return ProcessAction::CloseSession { session_id, reason };
        }
        let count = {
            let count = self
                .session_drop_counts
                .entry(session_id.clone())
                .and_modify(|c| *c += 1)
                .or_insert(1);
            *count
        };
        if count >= 3 {
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
        self.handle(incoming_packet, router, None).await
    }

    fn parallel_authentication(&self) -> bool {
        true
    }

    async fn process_ordered(
        &self,
        incoming_packet: IncomingPacket,
        router: Arc<Router>,
        order: PacketProcessingOrder,
    ) -> ProcessAction {
        self.handle(incoming_packet, router, Some(order)).await
    }
}

impl DefaultPacketProcessor {
    async fn handle(
        &self,
        incoming_packet: IncomingPacket,
        router: Arc<Router>,
        order: Option<PacketProcessingOrder>,
    ) -> ProcessAction {
        let session_id = SessionId::from(incoming_packet.session_id.clone());
        let mut packet = incoming_packet.packet;

        let local = packet.receiver == self.our_peer_id || packet.receiver.is_empty();
        let locally_encrypted = is_secure_envelope(&packet.data) && local;
        let authenticating = || {
            if !self.allow_unsigned_packets {
                let vk = self.peer_cache.verifying_key(&packet.sender).ok();
                if let Err(error) = verify_packet_with_key(&packet, vk.as_ref()) {
                    crate::processor!("Invalid signature from {}: {}", packet.sender, error);
                    #[cfg(feature = "packet-trace")]
                    crate::packet_trace::record(
                        &packet,
                        crate::packet_trace::Stage::SignatureRejected,
                    );
                    return Err("invalid signature");
                }
            }

            // Relays preserve a distinct adjacent authenticated peer.
            if packet.nodes.is_empty()
                && incoming_packet
                    .from_node
                    .as_deref()
                    .is_some_and(|peer| peer != packet.sender)
            {
                return Err("session peer mismatch");
            }

            if locally_encrypted {
                let envelope = self
                    .peer_cache
                    .decode_secure(
                        self.local_keypair.signing_key(),
                        &packet.sender,
                        &packet.data,
                    )
                    .map_err(|error| {
                        crate::processor!(
                            "Envelope decryption failed from {}: {}",
                            packet.sender,
                            error
                        );
                        "decrypt failed"
                    })?;
                Ok(Some(envelope))
            } else {
                Ok(None)
            }
        };
        let authenticated = authenticating();

        // No signature result, crypto error, or cancelled job can mutate
        // deduplication / replay state out of order on this input link.
        if let Some(ticket) = &order {
            ticket.wait_turn().await;
        }
        let decrypted = match authenticated {
            Ok(envelope) => envelope,
            Err(reason) => return self.record_drop(session_id, reason),
        };
        if !self.allow_unsigned_packets
            && packet
                .signature
                .as_deref()
                .is_some_and(|s| s.starts_with("v4:"))
        {
            self.peer_cache.mark_routed_signatures(&packet.sender);
        }
        if !packet.nodes.is_empty() {
            if !router.admit_relay_packet(&packet) {
                #[cfg(feature = "packet-trace")]
                crate::packet_trace::record(&packet, crate::packet_trace::Stage::RelayDuplicate);
                return ProcessAction::Dropped {
                    reason: "duplicate relay packet",
                };
            }
            if !locally_encrypted {
                router.broadcast_relay_packet(
                    &incoming_packet.session_id,
                    incoming_packet.from_node.as_deref(),
                    &packet,
                );
            }
        }

        if let Some((seq, plaintext)) = decrypted {
            let accepted = match self.commit_replay(&packet.sender, seq) {
                Ok(accepted) => accepted,
                Err(()) => {
                    return ProcessAction::CloseSession {
                        session_id,
                        reason: "legacy replay origin capacity",
                    };
                }
            };
            if !accepted {
                router.record_replay_or_late();
                #[cfg(feature = "packet-trace")]
                crate::packet_trace::record(&packet, crate::packet_trace::Stage::ReplayRejected);
                crate::processor!(
                    "Replay detected from {} with seq {}, dropping",
                    packet.sender,
                    seq
                );
                return ProcessAction::Dropped {
                    reason: "replay or late packet",
                };
            }
            #[cfg(feature = "packet-trace")]
            crate::packet_trace::record(&packet, crate::packet_trace::Stage::EnvelopeAccepted);
            packet.data = plaintext;
            router.broadcast_incoming_after_decrypt(
                &incoming_packet.session_id,
                incoming_packet.from_node.as_deref(),
                &packet,
            );
        }

        if !self.allow_unsigned_packets {
            router.record_authenticated_ingress(local);
        }

        let from = incoming_packet
            .from_node
            .as_deref()
            .unwrap_or(packet.sender.as_str());
        let peer_id = PeerId::from_str(from);
        let registry: &dyn SessionRegistry = router.as_ref();
        // The signed origin of a relayed frame is not the adjacent peer.
        if incoming_packet.from_node.is_some() || packet.nodes.is_empty() {
            registry.set_peer_for_session(session_id.clone(), peer_id.clone());
        }

        // Preserve the per-link replay order without holding it during
        // forwarding, network writes or control handlers.
        drop(order);
        let receiver = packet.receiver.clone();
        let publisher: &dyn PacketPublisher = router.as_ref();
        let selector: &dyn SessionSelector = router.as_ref();

        if local {
            // Reserve handler memory for small, direct, authenticated control.
            // Neither protocol_id nor an encrypted wire hint grants access.
            let eligible_for_reserve = !self.allow_unsigned_packets
                && packet.nodes.is_empty()
                && packet.protocol_id.is_none()
                && packet.data.len() <= MAX_RESERVED_CONTROL_PAYLOAD;
            if let Ok(control) =
                crate::protocol::control::NetworkControlPayload::decode(&packet.data)
            {
                let _control_charge = if eligible_for_reserve {
                    let Some(charge) = router.ingress_budget().verified_control(
                        &packet.sender,
                        packet.data.len().saturating_mul(4) + 4096,
                    ) else {
                        return ProcessAction::CloseSession {
                            session_id,
                            reason: "verified control admission exhausted",
                        };
                    };
                    Some(charge)
                } else {
                    None
                };
                super::control::handle_verified_control(
                    packet.request_id,
                    control,
                    &self.our_peer_id,
                    from,
                    &peer_id,
                    self.peer_catalog.as_ref(),
                    publisher,
                    selector,
                    self.peer_discovery_random_fraction,
                    self.nat_state.as_ref(),
                )
                .await;
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

#[cfg(test)]
mod reconnect_regression_tests {
    use super::*;

    #[test]
    fn third_invalid_packet_closes_session_without_deadlocking() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let keypair = NodeKeypair::generate();
            let processor = DefaultPacketProcessor::new(
                keypair.peer_id().to_owned(),
                false,
                Arc::new(PeerCatalog::with_max_peers(16)),
                0.0,
                NatTraversalState::new(),
                keypair,
                PeerCryptoCache::new(),
            );
            let session = SessionId::from("reconnect-regression");
            let actions: Vec<_> = (0..4)
                .map(|_| processor.record_drop(session.clone(), "invalid signature"))
                .collect();
            tx.send((session, actions)).unwrap();
        });
        let (session, actions) = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("packet rejection must not deadlock a runtime worker");
        assert_eq!(
            actions,
            vec![
                ProcessAction::Dropped {
                    reason: "invalid signature"
                },
                ProcessAction::Dropped {
                    reason: "invalid signature"
                },
                ProcessAction::CloseSession {
                    session_id: session,
                    reason: "invalid signature"
                },
                ProcessAction::Dropped {
                    reason: "invalid signature"
                },
            ]
        );
    }
}
