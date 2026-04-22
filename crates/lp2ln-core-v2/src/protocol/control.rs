use serde::{Deserialize, Serialize};

use crate::topology::{NodeDescriptor, PeerEvidence};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NatCandidateKind {
    Host,
    Srflx,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NatCandidate {
    pub protocol: String,
    pub addr: String,
    pub kind: NatCandidateKind,
    #[serde(default)]
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatOfferPayload {
    pub session_id: String,
    pub candidates: Vec<NatCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatAnswerPayload {
    pub session_id: String,
    pub candidates: Vec<NatCandidate>,
}

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
    NatOffer {
        offer: NatOfferPayload,
    },
    NatAnswer {
        answer: NatAnswerPayload,
    },
    NatPunchStart {
        session_id: String,
        start_after_ms: u64,
    },
    NatPunchResult {
        session_id: String,
        success: bool,
        selected_addr: Option<String>,
        reason: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_offer_roundtrip() {
        let payload = NetworkControlPayload::NatOffer {
            offer: NatOfferPayload {
                session_id: "sess-1".to_string(),
                candidates: vec![NatCandidate {
                    protocol: "udp".to_string(),
                    addr: "1.2.3.4:4000".to_string(),
                    kind: NatCandidateKind::Srflx,
                    priority: 300,
                }],
            },
        };
        let encoded = payload.encode().expect("encode");
        let decoded = NetworkControlPayload::decode(&encoded).expect("decode");
        match decoded {
            NetworkControlPayload::NatOffer { offer } => {
                assert_eq!(offer.session_id, "sess-1");
                assert_eq!(offer.candidates.len(), 1);
                assert_eq!(offer.candidates[0].protocol, "udp");
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }
}
