// DHT record types (roadmap 03 — DHT-0/1)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 256-bit XOR-metric node identifier (SHA-256 of peer_id string bytes).
pub type NodeId = [u8; 32];

/// Derive NodeId from a PeerId string.
pub fn node_id_of(peer_id: &str) -> NodeId {
    let mut h = Sha256::new();
    h.update(peer_id.as_bytes());
    h.finalize().into()
}

/// XOR distance between two NodeIds.
pub fn xor_distance(a: &NodeId, b: &NodeId) -> NodeId {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Number of leading zero bits in a NodeId (bucket index in Kademlia).
pub fn leading_zeros(id: &NodeId) -> usize {
    for (byte_idx, &byte) in id.iter().enumerate() {
        if byte != 0 {
            return byte_idx * 8 + byte.leading_zeros() as usize;
        }
    }
    256
}

/// A signed, TTL-bearing announcement of a node's presence and addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node_id: NodeId,
    pub peer_id: String,
    /// Listen addresses ("tcp:127.0.0.1:8080", etc.)
    pub addrs: Vec<String>,
    /// Monotonically increasing — rejects replays.
    pub seq: u64,
    /// Unix seconds when this record expires.
    pub expires_at: u64,
    /// ECDSA signature over canonical postcard form (without this field).
    pub signature: Vec<u8>,
}

impl NodeRecord {
    /// Bytes that are signed: postcard of (node_id, peer_id, addrs, seq, expires_at).
    pub fn signable(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Signable<'a> {
            node_id: &'a NodeId,
            peer_id: &'a str,
            addrs: &'a [String],
            seq: u64,
            expires_at: u64,
        }
        postcard::to_allocvec(&Signable {
            node_id: &self.node_id,
            peer_id: &self.peer_id,
            addrs: &self.addrs,
            seq: self.seq,
            expires_at: self.expires_at,
        })
        .expect("signable encode")
    }

    pub fn is_expired(&self) -> bool {
        unix_now() >= self.expires_at
    }
}

/// A claim that `provider` can serve `content_id` bytes.
/// Correctness is the client's job: ContentId = SHA-256(bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRecord {
    pub content_id: [u8; 32],
    pub provider: NodeRecord,
}

/// DHT wire messages (postcard-encoded, riding on packets with protocol_id = DHT_PROTOCOL_ID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtMsg {
    FindNode {
        target: NodeId,
        request_id: u64,
    },
    FindNodeReply {
        request_id: u64,
        /// Up to K closest nodes the responder knows.
        closer: Vec<NodeRecord>,
    },
    PutRecord {
        record: NodeRecord,
    },
    GetRecord {
        node_id: NodeId,
        request_id: u64,
    },
    GetRecordReply {
        request_id: u64,
        record: Option<NodeRecord>,
    },
    AnnounceProvider {
        record: ProviderRecord,
    },
    FindProviders {
        content_id: [u8; 32],
        request_id: u64,
    },
    FindProvidersReply {
        request_id: u64,
        providers: Vec<ProviderRecord>,
    },
}

/// protocol_id used for DHT packets inside the App Plane.
pub const DHT_PROTOCOL_ID: u16 = 0x4448; // "DH"

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
