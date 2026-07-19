use std::collections::HashMap;
use std::sync::Arc;

use crate::packet::Packet;
use crate::sessions::manager::SessionManager;
use crate::topology::PeerCatalog;
use crate::types::PeerId;

pub(super) fn control_packet(
    sender: &str,
    receiver: String,
    data: Vec<u8>,
    max_hops: u8,
) -> Packet {
    Packet {
        signature: None,
        data,
        nodes: vec![],
        sender: sender.to_string(),
        receiver,
        max_hops,
        request_id: None,
        chunk_stream_id: None,
        chunk_index: None,
        total_chunks: None,
        protocol_id: None,
    }
}

pub(super) fn handshake_packet(sender: &str, payload: &[u8]) -> Packet {
    control_packet(sender, String::new(), payload.to_vec(), 8)
}

#[allow(dead_code)]
pub(super) async fn observe_failure_and_close(
    catalog: &Arc<PeerCatalog>,
    sm: &Arc<SessionManager>,
    dial_cooldown_until: &mut HashMap<PeerId, u64>,
    pid: &PeerId,
    cooldown_until: u64,
) {
    catalog.observe_failure(pid);
    dial_cooldown_until.insert(pid.clone(), cooldown_until);
    let _ = sm.close_all_sessions_for_peer(pid).await;
}
