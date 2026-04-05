use serde::{Deserialize, Serialize};

use crate::topology::{NodeDescriptor, PeerEvidence};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum NetworkControlPayload {
    AnnounceNodeDescriptor {
        descriptor: NodeDescriptor,
    },
    RequestPeers {
        limit: u16,
    },
    PeersResponse {
        descriptors: Vec<NodeDescriptor>,
    },
    AnnounceEvidence {
        evidence: PeerEvidence,
    },
    PingPeerQuality {
        nonce: u64,
        timestamp_ms: u64,
    },
    PongPeerQuality {
        nonce: u64,
        timestamp_ms: u64,
        observed_rtt_ms: u32,
    },
    RequestDescriptors {
        limit: u16,
    },
    RequestCapabilities {
        limit: u16,
    },
    FindRelays {
        limit: u16,
    },
    FindProviders {
        limit: u16,
    },
    RequestAdjacency {},
    AdjacencyResponse {
        neighbors: Vec<String>,
    },
}

impl NetworkControlPayload {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| e.to_string())
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| e.to_string())
    }
}
