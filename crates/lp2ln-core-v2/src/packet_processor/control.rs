use crate::packet::Packet;
use crate::protocol::control::{NatCandidate, NatCandidateKind, NetworkControlPayload};
use crate::services::{NatTraversalPort, PacketPublisher, SessionSelector};
use crate::topology::{
    PeerCatalog, now_ms, parse_observed_addr_line, select_peers_for_discovery_response,
};
use crate::types::PeerId;

fn make_control_packet(
    our_peer_id: &str,
    receiver: &str,
    data: Vec<u8>,
    reply_to_request_id: Option<u64>,
) -> Packet {
    Packet {
        signature: None,
        data,
        nodes: vec![],
        sender: our_peer_id.to_string(),
        receiver: receiver.to_string(),
        max_hops: 2,
        request_id: reply_to_request_id,
        chunk_stream_id: None,
        chunk_index: None,
        total_chunks: None,
        protocol_id: None,
    }
}

pub async fn try_handle_control_packet(
    packet: &Packet,
    our_peer_id: &str,
    from: &str,
    peer_id: &PeerId,
    peer_catalog: &PeerCatalog,
    publisher: &dyn PacketPublisher,
    sessions: &dyn SessionSelector,
    peer_discovery_random_fraction: f32,
    nat_state: &dyn NatTraversalPort,
) -> bool {
    let data = packet.data.as_slice();
    let reply_to_request_id = packet.request_id;
    let Ok(ctrl) = NetworkControlPayload::decode(data) else {
        return false;
    };

    nat_state.cleanup_expired();

    let local_nat_candidates = || -> Vec<NatCandidate> {
        let our_desc = peer_catalog
            .descriptors()
            .into_iter()
            .find(|d| d.peer_id == our_peer_id);
        let Some(desc) = our_desc else {
            return vec![];
        };
        desc.observed_addrs
            .iter()
            .filter_map(|s| parse_observed_addr_line(s))
            .filter(|(proto, _)| proto == "udp")
            .map(|(proto, addr)| NatCandidate {
                protocol: proto,
                addr: addr.to_string(),
                kind: NatCandidateKind::Host,
                priority: 100,
            })
            .collect()
    };

    match ctrl {
        NetworkControlPayload::AnnounceNodeDescriptor { descriptor } => {
            if let Ok(accepted) = peer_catalog.upsert_descriptor(descriptor.clone()) {
                if accepted {
                    crate::processor!(
                        "Accepted descriptor v{} from {}",
                        descriptor.version,
                        descriptor.peer_id
                    );
                }
            }
        }
        NetworkControlPayload::AnnounceEvidence { evidence } => {
            let _ = peer_catalog.add_evidence(evidence);
        }
        NetworkControlPayload::RequestAdjacency {} => {
            let neighbors: Vec<String> = sessions
                .connected_peers()
                .into_iter()
                .map(|p| p.to_string())
                .filter(|s| s != from)
                .collect();
            let response = NetworkControlPayload::AdjacencyResponse { neighbors };
            if let Ok(encoded) = response.encode() {
                let packet = make_control_packet(our_peer_id, from, encoded, reply_to_request_id);
                let _ = publisher.send_to_peer(peer_id.clone(), packet, None).await;
            }
        }
        NetworkControlPayload::AdjacencyResponse { .. } => {}
        NetworkControlPayload::RequestPeers { limit }
        | NetworkControlPayload::RequestDescriptors { limit }
        | NetworkControlPayload::RequestCapabilities { limit }
        | NetworkControlPayload::FindRelays { limit }
        | NetworkControlPayload::FindProviders { limit } => {
            let lim = (limit as usize).clamp(1, 64);
            let descriptors = peer_catalog.descriptors();
            let descriptors = select_peers_for_discovery_response(
                descriptors,
                Some(from),
                lim,
                peer_discovery_random_fraction,
            );
            let response = NetworkControlPayload::PeersResponse { descriptors };
            if let Ok(encoded) = response.encode() {
                let packet = make_control_packet(our_peer_id, from, encoded, reply_to_request_id);
                let _ = publisher.send_to_peer(peer_id.clone(), packet, None).await;
            }
        }
        NetworkControlPayload::PeersResponse { descriptors } => {
            for descriptor in descriptors {
                let _ = peer_catalog.upsert_descriptor(descriptor);
            }
        }
        NetworkControlPayload::PingPeerQuality {
            nonce,
            timestamp_ms,
        } => {
            let elapsed = now_ms().saturating_sub(timestamp_ms) as u32;
            let resp = NetworkControlPayload::PongPeerQuality {
                nonce,
                timestamp_ms: now_ms(),
                observed_rtt_ms: elapsed,
            };
            if let Ok(encoded) = resp.encode() {
                let packet = make_control_packet(our_peer_id, from, encoded, reply_to_request_id);
                let _ = publisher.send_to_peer(peer_id.clone(), packet, None).await;
            }
        }
        NetworkControlPayload::PongPeerQuality {
            nonce: _,
            timestamp_ms: _,
            observed_rtt_ms,
        } => {
            peer_catalog.observe_success(peer_id, observed_rtt_ms.max(1));
        }
        NetworkControlPayload::NatOffer { offer } => {
            let answer = nat_state.handle_offer(from, &offer, local_nat_candidates());
            let response = NetworkControlPayload::NatAnswer { answer };
            if let Ok(encoded) = response.encode() {
                let packet = make_control_packet(our_peer_id, from, encoded, reply_to_request_id);
                let _ = publisher.send_to_peer(peer_id.clone(), packet, None).await;
            }
        }
        NetworkControlPayload::NatAnswer { answer } => {
            if let Some(start_after_ms) = nat_state.handle_answer(from, &answer) {
                nat_state.mark_punch_start(&answer.session_id, start_after_ms);
                let response = NetworkControlPayload::NatPunchStart {
                    session_id: answer.session_id.clone(),
                    start_after_ms,
                };
                if let Ok(encoded) = response.encode() {
                    let packet =
                        make_control_packet(our_peer_id, from, encoded, reply_to_request_id);
                    let _ = publisher.send_to_peer(peer_id.clone(), packet, None).await;
                }
            }
        }
        NetworkControlPayload::NatPunchStart {
            session_id,
            start_after_ms,
        } => {
            nat_state.mark_punch_start(&session_id, start_after_ms);
            nat_state.mark_punching(&session_id);
        }
        NetworkControlPayload::NatPunchResult {
            session_id,
            success,
            selected_addr,
            reason,
        } => {
            nat_state.mark_result(&session_id, success, selected_addr, reason);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use anyhow::Result;
    use async_trait::async_trait;

    use super::*;
    use crate::protocol::control::{NatAnswerPayload, NatOfferPayload};
    use crate::sessions::Session;
    use crate::types::SessionId;

    struct RecordingPublisher {
        sent: Mutex<Vec<(PeerId, Packet, Option<PeerId>)>>,
    }

    impl RecordingPublisher {
        fn new() -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl PacketPublisher for RecordingPublisher {
        async fn send_to_session(&self, _session_id: SessionId, _packet: Packet) -> Result<u64> {
            Ok(1)
        }

        async fn send_to_peer(
            &self,
            peer_id: PeerId,
            packet: Packet,
            exclude_from: Option<PeerId>,
        ) -> Result<u64> {
            self.sent
                .lock()
                .expect("sent lock")
                .push((peer_id, packet, exclude_from));
            Ok(1)
        }
    }

    struct StaticSelector {
        peers: Vec<PeerId>,
    }

    impl SessionSelector for StaticSelector {
        fn session(&self, _session_id: &SessionId) -> Option<Arc<dyn Session + Send + Sync>> {
            None
        }

        fn best_session_for_peer(
            &self,
            _peer_id: &PeerId,
        ) -> Option<Arc<dyn Session + Send + Sync>> {
            None
        }

        fn connected_peers(&self) -> Vec<PeerId> {
            self.peers.clone()
        }

        fn peers_sorted_by_score(&self) -> Vec<PeerId> {
            self.peers.clone()
        }
    }

    struct NoopNat;

    impl NatTraversalPort for NoopNat {
        fn cleanup_expired(&self) {}

        fn create_offer(
            &self,
            session_id: String,
            _peer_id: String,
            local_candidates: Vec<NatCandidate>,
        ) -> NatOfferPayload {
            NatOfferPayload {
                session_id,
                candidates: local_candidates,
            }
        }

        fn handle_offer(
            &self,
            _from: &str,
            offer: &NatOfferPayload,
            local_candidates: Vec<NatCandidate>,
        ) -> NatAnswerPayload {
            NatAnswerPayload {
                session_id: offer.session_id.clone(),
                candidates: local_candidates,
            }
        }

        fn handle_answer(&self, _from: &str, _answer: &NatAnswerPayload) -> Option<u64> {
            None
        }

        fn mark_punch_start(&self, _session_id: &str, _start_after_ms: u64) {}

        fn mark_punching(&self, _session_id: &str) {}

        fn mark_result(
            &self,
            _session_id: &str,
            _success: bool,
            _selected_addr: Option<String>,
            _reason: Option<String>,
        ) {
        }
    }

    #[tokio::test]
    async fn adjacency_request_uses_service_ports_without_router() {
        let request = NetworkControlPayload::RequestAdjacency {}
            .encode()
            .expect("encode control");
        let packet = Packet {
            signature: None,
            data: request,
            nodes: vec![],
            sender: "peer-a".to_string(),
            receiver: "self".to_string(),
            max_hops: 2,
            request_id: Some(42),
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
            protocol_id: None,
        };
        let publisher = RecordingPublisher::new();
        let selector = StaticSelector {
            peers: vec![PeerId::from("peer-a"), PeerId::from("peer-b")],
        };
        let catalog = PeerCatalog::new();
        let peer_id = PeerId::from("peer-a");

        let handled = try_handle_control_packet(
            &packet, "self", "peer-a", &peer_id, &catalog, &publisher, &selector, 0.0, &NoopNat,
        )
        .await;

        assert!(handled);
        let sent = publisher.sent.lock().expect("sent lock");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, peer_id);
        assert_eq!(sent[0].1.request_id, Some(42));
        let response =
            NetworkControlPayload::decode(&sent[0].1.data).expect("decode adjacency response");
        let NetworkControlPayload::AdjacencyResponse { neighbors } = response else {
            panic!("expected adjacency response");
        };
        assert_eq!(neighbors, vec!["peer-b".to_string()]);
    }
}
