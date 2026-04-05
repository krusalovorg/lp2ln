use std::sync::Arc;

use crate::packet::Packet;
use crate::router::Router;
use crate::topology::PeerCatalog;
use crate::types::{PeerId, SessionId};

pub async fn handle_local_packet(
    payload: &[u8],
    our_peer_id: &str,
    from: &str,
    peer_id: &PeerId,
    session_id: &SessionId,
    peer_catalog: &PeerCatalog,
    router: Arc<Router>,
) {
    match payload {
        [] => {
            let ack = Packet {
                signature: None,
                data: b"hs_ack".to_vec(),
                nodes: vec![],
                sender: our_peer_id.to_string(),
                receiver: from.to_string(),
                max_hops: 1,
                chunk_stream_id: None,
                chunk_index: None,
                total_chunks: None,
            };
            if let Err(e) = router.send_to_session(session_id.clone(), ack).await {
                let msg = e.to_string();
                if msg.contains("not found") {
                    crate::debug!(
                        "[PacketProcessor] handshake ack skipped (session closed): {}",
                        session_id
                    );
                } else {
                    crate::error!("[PacketProcessor] Failed to send handshake ack: {}", e);
                }
            }
        }
        b"hs_ack" => {
            peer_catalog.observe_success(peer_id, 30);
        }
        b"ping" => {
            crate::processor!("Ping from {} -> sending pong", from);
            let pong = Packet {
                signature: None,
                data: b"pong".to_vec(),
                nodes: vec![],
                sender: our_peer_id.to_string(),
                receiver: from.to_string(),
                max_hops: 1,
                chunk_stream_id: None,
                chunk_index: None,
                total_chunks: None,
            };
            if let Err(e) = router.send_to_peer(peer_id.clone(), pong, None).await {
                crate::error!("[PacketProcessor] Failed to send pong: {}", e);
            }
        }
        b"pong" => {
            crate::processor!("Pong from {}", from);
            peer_catalog.observe_success(peer_id, 60);
        }
        _ => {
            crate::processor!(
                "Received packet (for us): Session ID: {}, Sender: {}, Receiver: {}, Data: {} bytes",
                session_id,
                from,
                our_peer_id,
                payload.len()
            );
        }
    }
}
