use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeFeatures {
    pub obfuscation_negotiation: bool,
    pub enabled_transport_obfuscation: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_obfs_mode: Option<String>,
    #[serde(default)]
    pub secure_channel: bool,
    #[serde(default)]
    pub anti_replay: bool,
    #[serde(default)]
    pub peer_id_binding: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeHello {
    pub version: u16,
    pub features: HandshakeFeatures,
}

pub const HANDSHAKE_VERSION: u16 = 1;

pub fn encode_hello(enabled_transport_obfuscation: Vec<String>, quic_obfs_mode: Option<String>) -> Vec<u8> {
    let hello = HandshakeHello {
        version: HANDSHAKE_VERSION,
        features: HandshakeFeatures {
            obfuscation_negotiation: true,
            enabled_transport_obfuscation,
            quic_obfs_mode,
            secure_channel: true,
            anti_replay: true,
            peer_id_binding: true,
        },
    };

    serde_json::to_vec(&hello).unwrap_or_default()
}

pub fn decode_hello(data: &[u8]) -> Option<HandshakeHello> {
    if data.is_empty() {
        return None;
    }
    serde_json::from_slice::<HandshakeHello>(data).ok()
}
