use crate::packets::StorageToken;
use base64;
use hex;
use k256;
use serde_json;
use k256::ecdsa::signature::Verifier;

pub async fn get_metadata_from_token(token: String) -> Result<StorageToken, String> {
    let token_bytes = base64::decode(&token).map_err(|e| e.to_string())?;
    let token_str = String::from_utf8(token_bytes).map_err(|e| e.to_string())?;
    let token: StorageToken = serde_json::from_str(&token_str).map_err(|e| e.to_string())?;
    Ok(token)
}

pub async fn validate_signature_token(token: String, db: &crate::db::P2PDatabase) -> Result<StorageToken, String> {
    let token_bytes = base64::decode(&token).map_err(|e| e.to_string())?;
    let token_str = String::from_utf8(token_bytes).map_err(|e| e.to_string())?;
    let mut token: StorageToken = serde_json::from_str(&token_str).map_err(|e| e.to_string())?;
    
    let signature = token.signature.clone();
    token.signature = Vec::new();
    
    let token_bytes = serde_json::to_vec(&token).map_err(|e| e.to_string())?;
    
    let pub_key_bytes = hex::decode(&token.storage_provider)
        .map_err(|e| format!("Invalid public key hex: {}", e))?;
    let verifying_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pub_key_bytes)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    
    let signature = k256::ecdsa::Signature::from_slice(&signature)
        .map_err(|e| format!("Invalid signature format: {}", e))?;
    
    verifying_key
        .verify(&token_bytes, &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))?;

    token.signature = signature.to_bytes().to_vec();
    Ok(token)
}


