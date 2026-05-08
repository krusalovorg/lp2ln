use crate::packet::Packet;
use hex;
use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::Serialize;

#[derive(Serialize)]
struct SigningPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Vec<u8>>,
    nodes: Vec<String>,
    sender: String,
    receiver: String,
    max_hops: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chunk_stream_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chunk_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_chunks: Option<u32>,
}

fn packet_to_signing_payload(packet: &Packet) -> SigningPayload {
    SigningPayload {
        data: Some(packet.data.clone()),
        nodes: packet.nodes.clone(),
        sender: packet.sender.clone(),
        receiver: packet.receiver.clone(),
        max_hops: packet.max_hops,
        request_id: packet.request_id,
        chunk_stream_id: packet.chunk_stream_id,
        chunk_index: packet.chunk_index,
        total_chunks: packet.total_chunks,
    }
}

pub fn sign_packet(packet: &mut Packet, signing_key: &SigningKey) -> Result<(), String> {
    let payload = packet_to_signing_payload(packet);
    let data = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
    let signature: Signature = signing_key.sign(&data);
    packet.signature = Some(hex::encode(signature.to_bytes()));
    Ok(())
}

pub fn verify_packet(packet: &Packet) -> Result<(), String> {
    let sig_hex = packet
        .signature
        .as_ref()
        .ok_or_else(|| "Missing signature".to_string())?;
    let payload = packet_to_signing_payload(packet);
    let data = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
    let sig_bytes = hex::decode(sig_hex).map_err(|e| e.to_string())?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|e| e.to_string())?;
    let pub_bytes = hex::decode(&packet.sender).map_err(|e| e.to_string())?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&pub_bytes).map_err(|e| e.to_string())?;
    verifying_key
        .verify(&data, &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))
}
