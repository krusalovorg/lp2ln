use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;
use k256::ecdsa::{SigningKey, VerifyingKey};

use super::secure_channel::{decode_secure_envelope, derive_shared_key, encode_secure_envelope};

/// Per-peer crypto material reused across packets (ECDH, verifying keys).
#[derive(Default)]
pub struct PeerCryptoCache {
    shared_keys: DashMap<String, [u8; 32]>,
    verifying_keys: DashMap<String, VerifyingKey>,
}

impl PeerCryptoCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn shared_key(&self, local: &SigningKey, remote_peer_id: &str) -> Result<[u8; 32]> {
        if let Some(entry) = self.shared_keys.get(remote_peer_id) {
            return Ok(*entry);
        }
        let key = derive_shared_key(local, remote_peer_id)?;
        self.shared_keys.insert(remote_peer_id.to_string(), key);
        Ok(key)
    }

    pub fn verifying_key(&self, sender_peer_id: &str) -> Result<VerifyingKey> {
        if let Some(entry) = self.verifying_keys.get(sender_peer_id) {
            return Ok(*entry.value());
        }
        let pub_bytes = hex::decode(sender_peer_id)
            .map_err(|e| anyhow::anyhow!("Invalid sender peer_id hex: {}", e))?;
        let vk = VerifyingKey::from_sec1_bytes(&pub_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid sender public key: {}", e))?;
        self.verifying_keys.insert(sender_peer_id.to_string(), vk);
        Ok(vk)
    }

    pub fn encode_secure(
        &self,
        local: &SigningKey,
        remote_peer_id: &str,
        plaintext: &[u8],
        seq: u64,
    ) -> Result<Vec<u8>> {
        let key = self.shared_key(local, remote_peer_id)?;
        encode_secure_envelope(plaintext, key, seq)
    }

    pub fn decode_secure(
        &self,
        local: &SigningKey,
        sender_peer_id: &str,
        data: &[u8],
    ) -> Result<(u64, Vec<u8>)> {
        let key = self.shared_key(local, sender_peer_id)?;
        decode_secure_envelope(data, key)
    }

    pub fn remove_peer(&self, peer_id: &str) {
        self.shared_keys.remove(peer_id);
        self.verifying_keys.remove(peer_id);
    }
}
