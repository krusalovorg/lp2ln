use std::sync::Arc;

use crate::packet::Packet;
use crate::protocol::control::NetworkControlPayload;
use crate::router::Router;
use crate::topology::{now_ms, select_peers_for_discovery_response, PeerCatalog};
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
    }
}

pub async fn try_handle_control_packet(
    packet: &Packet,
    our_peer_id: &str,
    from: &str,
    peer_id: &PeerId,
    peer_catalog: &PeerCatalog,
    router: Arc<Router>,
    peer_discovery_random_fraction: f32,
) -> bool {
    let data = packet.data.as_slice();
    let reply_to_request_id = packet.request_id;
    let Ok(ctrl) = NetworkControlPayload::decode(data) else {
        return false;
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
            let neighbors: Vec<String> = router
                .connected_peers()
                .into_iter()
                .map(|p| p.to_string())
                .filter(|s| s != from)
                .collect();
            let response = NetworkControlPayload::AdjacencyResponse { neighbors };
            if let Ok(encoded) = response.encode() {
                let packet = make_control_packet(our_peer_id, from, encoded, reply_to_request_id);
                let _ = router.send_to_peer(peer_id.clone(), packet, None).await;
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
                let _ = router.send_to_peer(peer_id.clone(), packet, None).await;
            }
        }
        NetworkControlPayload::PeersResponse { descriptors } => {
            for descriptor in descriptors {
                let _ = peer_catalog.upsert_descriptor(descriptor);
            }
        }
        NetworkControlPayload::PingPeerQuality { nonce, timestamp_ms } => {
            let elapsed = now_ms().saturating_sub(timestamp_ms) as u32;
            let resp = NetworkControlPayload::PongPeerQuality {
                nonce,
                timestamp_ms: now_ms(),
                observed_rtt_ms: elapsed,
            };
            if let Ok(encoded) = resp.encode() {
                let packet = make_control_packet(our_peer_id, from, encoded, reply_to_request_id);
                let _ = router.send_to_peer(peer_id.clone(), packet, None).await;
            }
        }
        NetworkControlPayload::PongPeerQuality {
            nonce: _,
            timestamp_ms: _,
            observed_rtt_ms,
        } => {
            peer_catalog.observe_success(peer_id, observed_rtt_ms.max(1));
        }
    }
    true
}
