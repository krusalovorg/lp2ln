use crate::packets::TransportPacket;
use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use hex;

pub fn sign_packet(packet: &mut TransportPacket, signing_key: &SigningKey) -> Result<(), String> {
    let unsigned = TransportPacket {
        act: packet.act.clone(),
        to: packet.to.clone(),
        data: packet.data.clone(),
        protocol: packet.protocol.clone(),
        peer_key: packet.peer_key.clone(),
        uuid: packet.uuid.clone(),
        nodes: vec![],
        signature: None,
    };
    let data = serde_json::to_vec(&unsigned).map_err(|e| e.to_string())?;
    let signature: Signature = signing_key.sign(&data);
    packet.signature = Some(hex::encode(signature.to_bytes()));
    Ok(())
}

pub fn verify_packet(packet: &TransportPacket) -> Result<(), String> {
    let sig_hex = packet
        .signature
        .as_ref()
        .ok_or_else(|| "Missing signature".to_string())?;
    let unsigned = TransportPacket {
        act: packet.act.clone(),
        to: packet.to.clone(),
        data: packet.data.clone(),
        protocol: packet.protocol.clone(),
        peer_key: packet.peer_key.clone(),
        uuid: packet.uuid.clone(),
        nodes: vec![],
        signature: None,
    };
    let data = serde_json::to_vec(&unsigned).map_err(|e| e.to_string())?;
    let sig_bytes = hex::decode(sig_hex).map_err(|e| e.to_string())?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|e| e.to_string())?;
    let pub_bytes = hex::decode(&packet.peer_key).map_err(|e| e.to_string())?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&pub_bytes).map_err(|e| e.to_string())?;
    verifying_key
        .verify(&data, &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))
}
