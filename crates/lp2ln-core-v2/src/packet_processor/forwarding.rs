use crate::packet::Packet;
use crate::protocol::control::NetworkControlPayload;
use crate::services::PacketPublisher;
use crate::types::{PeerId, SessionId};

pub async fn forward_packet(
    mut packet: Packet,
    incoming_session_id: &str,
    our_peer_id: &str,
    source_peer_id: &PeerId,
    target_peer_id: PeerId,
    publisher: &dyn PacketPublisher,
) {
    if packet.max_hops == 0 {
        let is_control_packet = NetworkControlPayload::decode(&packet.data).is_ok();
        if is_control_packet {
            crate::debug!(
                "[PacketProcessor] Drop control forward to {}: max_hops exhausted (sender={} receiver={} nodes={:?})",
                target_peer_id,
                packet.sender,
                packet.receiver,
                packet.nodes,
            );
        } else {
            crate::warn!(
                "[PacketProcessor] Drop forward to {}: max_hops exhausted (sender={} receiver={} nodes={:?})",
                target_peer_id,
                packet.sender,
                packet.receiver,
                packet.nodes,
            );
        }
        return;
    }
    packet.max_hops -= 1;
    packet.nodes.push(our_peer_id.to_string());
    let sid = SessionId::from(incoming_session_id.to_string());
    let ok = if target_peer_id == *source_peer_id {
        publisher.send_to_session(sid, packet.clone()).await.is_ok()
    } else {
        false
    };
    let ok = ok
        || publisher
            .send_to_peer(target_peer_id.clone(), packet, Some(source_peer_id.clone()))
            .await
            .is_ok();

    if !ok {
        crate::error!(
            "[PacketProcessor] Failed to forward to {}: No sessions for peer",
            target_peer_id
        );
    } else {
        crate::processor!("Forwarded packet to {}", target_peer_id);
    }
}
