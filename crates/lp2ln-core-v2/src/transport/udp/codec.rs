use anyhow::Result;
use crate::packet::Packet;

pub fn encode_packet(packet: Packet) -> Result<Vec<u8>> {
    serde_json::to_vec(&packet).map_err(|e| anyhow::anyhow!("Failed to encode packet: {}", e))
}

pub fn decode_packet(bytes: Vec<u8>) -> Result<Packet> {
    serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!("Failed to decode packet: {}", e))
}