use crate::packet::Packet;
use hex;
use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Wire signature format for outgoing packets.
///
/// V3 keeps direct-link compatibility. V4 authenticates the immutable payload
/// while allowing relays to update the hop path and budget. A verified V4
/// packet opts that peer into V4 replies; other peers continue receiving V3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureFormat {
    #[default]
    V3Hash,
    V4Hash,
}

const V3_SIGNATURE_PREFIX: &str = "v3:";
const V4_SIGNATURE_PREFIX: &str = "v4:";

fn packet_to_signing_payload_v4(packet: &Packet) -> SigningPayloadV3 {
    let mut payload = packet_to_signing_payload_v3(packet);
    // Routers update these hop-local fields. The author's signature protects
    // the encrypted body, endpoints, request ID and stream/protocol metadata.
    payload.nodes.clear();
    payload.max_hops = 0;
    payload
}

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
        SignatureFormat::V3Hash | SignatureFormat::V4Hash => {
            let (prefix, payload) = match format {
                SignatureFormat::V3Hash => (V3_SIGNATURE_PREFIX, packet_to_signing_payload_v3(packet)),
                SignatureFormat::V4Hash => (V4_SIGNATURE_PREFIX, packet_to_signing_payload_v4(packet)),
            };
            let data = postcard::to_allocvec(&payload).map_err(|e| e.to_string())?;
            let signature: Signature = signing_key.sign(&data);
            packet.signature = Some(format!(
                "{prefix}{}",
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

    if let Some(rest) = sig_hex.strip_prefix(V4_SIGNATURE_PREFIX) {
        return verify_signed_payload(packet, rest, verifying_key, packet_to_signing_payload_v4(packet));
    }
    let rest = sig_hex.strip_prefix(V3_SIGNATURE_PREFIX)
        .ok_or_else(|| "Unsupported signature format".to_string())?;
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
    verify_signed_payload(packet, sig_hex, verifying_key, payload)
}

fn verify_signed_payload(
    packet: &Packet, sig_hex: &str, verifying_key: Option<&VerifyingKey>, payload: SigningPayloadV3,
) -> Result<(), String> {
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
    fn v4_preserves_author_authentication_across_relay_hops() {
        let key = NodeKeypair::generate();
        let mut packet = sample_packet(&key, Some(0x4c46));
        sign_packet_with_format(&mut packet, key.signing_key(), SignatureFormat::V4Hash).unwrap();
        packet.nodes.push("relay".into());
        packet.max_hops -= 1;
        verify_packet(&packet).unwrap();
        let mut changed = packet.clone();
        changed.receiver = "attacker".into();
        assert!(verify_packet(&changed).is_err());
        packet.data[0] ^= 1;
        assert!(verify_packet(&packet).is_err());
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
