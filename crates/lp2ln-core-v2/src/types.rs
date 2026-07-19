use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// 256-bit XOR-metric node identifier: SHA-256 of the peer_id UTF-8 bytes.
///
/// Canonical derivation: always use [`PeerId::to_node_id`] or [`crate::dht::node_id_of`].
/// Never XOR raw hex bytes of a PeerId string — the entropy distribution is wrong.
pub type NodeId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PeerId(String);

impl PeerId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(id: &str) -> Self {
        Self(id.to_string())
    }

    /// Derive the [`NodeId`] for this peer (SHA-256 of the peer_id UTF-8 bytes).
    pub fn to_node_id(&self) -> NodeId {
        let mut h = Sha256::new();
        h.update(self.0.as_bytes());
        h.finalize().into()
    }
}

impl From<String> for PeerId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

impl From<&str> for PeerId {
    fn from(id: &str) -> Self {
        Self(id.to_string())
    }
}

impl From<PeerId> for String {
    fn from(peer_id: PeerId) -> Self {
        peer_id.0
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for SessionId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

impl From<&str> for SessionId {
    fn from(id: &str) -> Self {
        Self(id.to_string())
    }
}

impl From<SessionId> for String {
    fn from(session_id: SessionId) -> Self {
        session_id.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
