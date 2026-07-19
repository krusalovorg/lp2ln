use crate::packet::Packet;
use hex;
use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Wire signature format for outgoing packets.
///
/// Only V3 is supported. Older V1/V2 formats were removed before any public
/// network deployment (no compatibility burden).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureFormat {
    #[default]
    V3Hash,
}

const V3_SIGNATURE_PREFIX: &str = "v3:";

#[derive(Serialize)]
struct SigningPayloadV3 {
    data_hash: [u8; 32],
    nodes: Vec<String>,
    sender: String,
    receiver: String,
    max_hops: u8,
    request_id: Option<u64>,
    chunk_stream_id: Option<u64>,
    chunk_index: Option<u32>,
    total_chunks: Option<u32>,
    protocol_id: Option<u16>,
}

fn packet_to_signing_payload_v3(packet: &Packet) -> SigningPayloadV3 {
    let data_hash = Sha256::digest(&packet.data);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data_hash);
    SigningPayloadV3 {
        data_hash: hash,
        nodes: packet.nodes.clone(),
        sender: packet.sender.clone(),
        receiver: packet.receiver.clone(),
        max_hops: packet.max_hops,
        request_id: packet.request_id,
        chunk_stream_id: packet.chunk_stream_id,
        chunk_index: packet.chunk_index,
        total_chunks: packet.total_chunks,
        protocol_id: packet.protocol_id,
    }
}

pub fn sign_packet(packet: &mut Packet, signing_key: &SigningKey) -> Result<(), String> {
    sign_packet_with_format(packet, signing_key, SignatureFormat::V3Hash)
}

pub fn sign_packet_with_format(
    packet: &mut Packet,
    signing_key: &SigningKey,
    format: SignatureFormat,
) -> Result<(), String> {
    match format {
        SignatureFormat::V3Hash => {
            let payload = packet_to_signing_payload_v3(packet);
            let data = postcard::to_allocvec(&payload).map_err(|e| e.to_string())?;
            let signature: Signature = signing_key.sign(&data);
            packet.signature = Some(format!(
                "{V3_SIGNATURE_PREFIX}{}",
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

    let rest = sig_hex
        .strip_prefix(V3_SIGNATURE_PREFIX)
        .ok_or_else(|| "Unsupported signature format (only v3: is accepted)".to_string())?;

    verify_packet_v3(packet, rest, verifying_key)
}

fn resolve_verifying_key(
    packet: &Packet,
    verifying_key: Option<&VerifyingKey>,
) -> Result<VerifyingKey, String> {
    match verifying_key {
        Some(k) => Ok(*k),
        None => {
            let pub_bytes = hex::decode(&packet.sender).map_err(|e| e.to_string())?;
            VerifyingKey::from_sec1_bytes(&pub_bytes).map_err(|e| e.to_string())
        }
    }
}

fn verify_packet_v3(
    packet: &Packet,
    sig_hex: &str,
    verifying_key: Option<&VerifyingKey>,
) -> Result<(), String> {
    let payload = packet_to_signing_payload_v3(packet);
    let data = postcard::to_allocvec(&payload).map_err(|e| e.to_string())?;
    let sig_bytes = hex::decode(sig_hex).map_err(|e| e.to_string())?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|e| e.to_string())?;
    let verifying_key = resolve_verifying_key(packet, verifying_key)?;
    verifying_key
        .verify(&data, &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::NodeKeypair;

    fn sample_packet(kp: &NodeKeypair, protocol_id: Option<u16>) -> Packet {
        Packet {
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
            protocol_id,
        }
    }

    #[test]
    fn v3_sign_verify_roundtrip() {
        let kp = NodeKeypair::generate();
        let mut packet = sample_packet(&kp, Some(0x4448));
        sign_packet_with_format(&mut packet, kp.signing_key(), SignatureFormat::V3Hash).unwrap();
        assert!(
            packet
                .signature
                .as_ref()
                .unwrap()
                .starts_with(V3_SIGNATURE_PREFIX)
        );
        verify_packet(&packet).unwrap();
    }

    #[test]
    fn v3_sign_verify_none_protocol_id() {
        let kp = NodeKeypair::generate();
        let mut packet = sample_packet(&kp, None);
        sign_packet(&mut packet, kp.signing_key()).unwrap();
        verify_packet(&packet).unwrap();
    }

    #[test]
    fn v3_rejects_protocol_id_tamper() {
        let kp = NodeKeypair::generate();
        let mut packet = sample_packet(&kp, Some(0x4448));
        sign_packet_with_format(&mut packet, kp.signing_key(), SignatureFormat::V3Hash).unwrap();
        packet.protocol_id = Some(0x9999);
        assert!(verify_packet(&packet).is_err());
    }

    #[test]
    fn v3_rejects_clearing_protocol_id() {
        let kp = NodeKeypair::generate();
        let mut packet = sample_packet(&kp, Some(0x4448));
        sign_packet_with_format(&mut packet, kp.signing_key(), SignatureFormat::V3Hash).unwrap();
        packet.protocol_id = None;
        assert!(verify_packet(&packet).is_err());
    }

    #[test]
    fn rejects_legacy_v2_prefix() {
        let kp = NodeKeypair::generate();
        let mut packet = sample_packet(&kp, None);
        sign_packet(&mut packet, kp.signing_key()).unwrap();
        let hex = packet
            .signature
            .as_ref()
            .unwrap()
            .strip_prefix(V3_SIGNATURE_PREFIX)
            .unwrap();
        packet.signature = Some(format!("v2:{hex}"));
        assert!(verify_packet(&packet).is_err());
    }

    #[test]
    fn rejects_bare_hex_legacy_v1() {
        let kp = NodeKeypair::generate();
        let mut packet = sample_packet(&kp, None);
        sign_packet(&mut packet, kp.signing_key()).unwrap();
        let hex = packet
            .signature
            .as_ref()
            .unwrap()
            .strip_prefix(V3_SIGNATURE_PREFIX)
            .unwrap();
        packet.signature = Some(hex.to_string());
        assert!(verify_packet(&packet).is_err());
    }
}
