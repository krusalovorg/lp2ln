use crate::packet::Packet;
use anyhow::Result;

pub fn encode_packet(packet: Packet) -> Result<Vec<u8>> {
    postcard::to_allocvec(&packet).map_err(|e| anyhow::anyhow!("Failed to encode packet: {}", e))
}

pub fn decode_packet(bytes: Vec<u8>) -> Result<Packet> {
    postcard::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("Failed to decode packet: {}", e))
}
