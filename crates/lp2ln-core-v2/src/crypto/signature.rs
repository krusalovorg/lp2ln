use crate::packet::Packet;
use hex;
use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Wire signature format for new packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureFormat {
    #[default]
    V1Json,
    V2Hash,
}

const V2_SIGNATURE_PREFIX: &str = "v2:";

#[derive(Serialize)]
struct SigningPayloadV1 {
    data: Option<Vec<u8>>,
    nodes: Vec<String>,
    sender: String,
    receiver: String,
    max_hops: u8,
    request_id: Option<u64>,
    chunk_stream_id: Option<u64>,
    chunk_index: Option<u32>,
    total_chunks: Option<u32>,
}

#[derive(Serialize)]
struct SigningPayloadV2 {
    data_hash: [u8; 32],
    nodes: Vec<String>,
    sender: String,
    receiver: String,
    max_hops: u8,
    request_id: Option<u64>,
    chunk_stream_id: Option<u64>,
    chunk_index: Option<u32>,
    total_chunks: Option<u32>,
}

fn packet_to_signing_payload_v1(packet: &Packet) -> SigningPayloadV1 {
    SigningPayloadV1 {
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

fn packet_to_signing_payload_v2(packet: &Packet) -> SigningPayloadV2 {
    let data_hash = Sha256::digest(&packet.data);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data_hash);
    SigningPayloadV2 {
        data_hash: hash,
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
    sign_packet_with_format(packet, signing_key, SignatureFormat::V1Json)
}

pub fn sign_packet_with_format(
    packet: &mut Packet,
    signing_key: &SigningKey,
    format: SignatureFormat,
) -> Result<(), String> {
    match format {
        SignatureFormat::V1Json => {
            let payload = packet_to_signing_payload_v1(packet);
            let data = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
            let signature: Signature = signing_key.sign(&data);
            packet.signature = Some(hex::encode(signature.to_bytes()));
        }
        SignatureFormat::V2Hash => {
            let payload = packet_to_signing_payload_v2(packet);
            let data = postcard::to_allocvec(&payload).map_err(|e| e.to_string())?;
            let signature: Signature = signing_key.sign(&data);
            packet.signature = Some(format!(
                "{V2_SIGNATURE_PREFIX}{}",
                hex::encode(signature.to_bytes())
            ));
        }
    }
    Ok(())
}

pub fn verify_packet(packet: &Packet) -> Result<(), String> {
    verify_packet_with_key(packet, None)
}

pub fn verify_packet_with_key(
    packet: &Packet,
    verifying_key: Option<&VerifyingKey>,
) -> Result<(), String> {
    let sig_hex = packet
        .signature
        .as_ref()
        .ok_or_else(|| "Missing signature".to_string())?;

    if let Some(rest) = sig_hex.strip_prefix(V2_SIGNATURE_PREFIX) {
        return verify_packet_v2(packet, rest, verifying_key);
    }

    verify_packet_v1(packet, sig_hex, verifying_key)
}

fn verify_packet_v1(
    packet: &Packet,
    sig_hex: &str,
    verifying_key: Option<&VerifyingKey>,
) -> Result<(), String> {
    let payload = packet_to_signing_payload_v1(packet);
    let data = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
    let sig_bytes = hex::decode(sig_hex).map_err(|e| e.to_string())?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|e| e.to_string())?;
    let verifying_key = match verifying_key {
        Some(k) => k.clone(),
        None => {
            let pub_bytes = hex::decode(&packet.sender).map_err(|e| e.to_string())?;
            VerifyingKey::from_sec1_bytes(&pub_bytes).map_err(|e| e.to_string())?
        }
    };
    verifying_key
        .verify(&data, &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))
}

fn verify_packet_v2(
    packet: &Packet,
    sig_hex: &str,
    verifying_key: Option<&VerifyingKey>,
) -> Result<(), String> {
    let payload = packet_to_signing_payload_v2(packet);
    let data = postcard::to_allocvec(&payload).map_err(|e| e.to_string())?;
    let sig_bytes = hex::decode(sig_hex).map_err(|e| e.to_string())?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|e| e.to_string())?;
    let verifying_key = match verifying_key {
        Some(k) => k.clone(),
        None => {
            let pub_bytes = hex::decode(&packet.sender).map_err(|e| e.to_string())?;
            VerifyingKey::from_sec1_bytes(&pub_bytes).map_err(|e| e.to_string())?
        }
    };
    verifying_key
        .verify(&data, &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::NodeKeypair;

    #[test]
    fn v2_sign_verify_roundtrip() {
        let kp = NodeKeypair::generate();
        let mut packet = Packet {
            signature: None,
            data: vec![1, 2, 3, 4],
            nodes: vec![],
            sender: kp.peer_id().to_string(),
            receiver: "peer-b".into(),
            max_hops: 4,
            request_id: Some(1),
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };
        sign_packet_with_format(&mut packet, kp.signing_key(), SignatureFormat::V2Hash).unwrap();
        verify_packet(&packet).unwrap();
    }

    #[test]
    fn v1_still_verifies() {
        let kp = NodeKeypair::generate();
        let mut packet = Packet {
            signature: None,
            data: b"hello".to_vec(),
            nodes: vec![],
            sender: kp.peer_id().to_string(),
            receiver: String::new(),
            max_hops: 8,
            request_id: None,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };
        sign_packet(&mut packet, kp.signing_key()).unwrap();
        verify_packet(&packet).unwrap();
    }
}
