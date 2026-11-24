use std::sync::{Arc, Mutex};

use anyhow::Result;
use dashmap::DashMap;
use k256::ecdsa::{SigningKey, VerifyingKey};

const MAX_CACHED_PEERS: usize = 16_384;
const MAX_PEER_ID_LEN: usize = 130;

use super::secure_channel::{decode_secure_envelope, derive_shared_key, encode_secure_envelope};

/// Per-peer crypto material reused across packets (ECDH, verifying keys).
#[derive(Default)]
pub struct PeerCryptoCache {
    shared_keys: DashMap<String, [u8; 32]>,
    verifying_keys: DashMap<String, VerifyingKey>,
    routed_signatures: DashMap<String, ()>,
    insert: Mutex<()>,
}

impl PeerCryptoCache {
    pub fn mark_routed_signatures(&self, peer: &str) {
        if peer.len() <= MAX_PEER_ID_LEN && !self.routed_signatures.contains_key(peer) {
            self.cache(&self.routed_signatures, peer, ());
        }
    }

    pub fn supports_routed_signatures(&self, peer: &str) -> bool {
        self.routed_signatures.contains_key(peer)
    }

    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn cache<T>(&self, map: &DashMap<String, T>, peer: &str, value: T) {
        let _insert = self.insert.lock().unwrap();
        if map.len() < MAX_CACHED_PEERS {
            map.insert(peer.to_owned(), value);
        }
    }

    pub fn shared_key(&self, local: &SigningKey, remote_peer_id: &str) -> Result<[u8; 32]> {
        if let Some(entry) = self.shared_keys.get(remote_peer_id) {
            return Ok(*entry);
        }
        anyhow::ensure!(
            remote_peer_id.len() <= MAX_PEER_ID_LEN,
            "invalid peer identity length"
        );
        let key = derive_shared_key(local, remote_peer_id)?;
        self.cache(&self.shared_keys, remote_peer_id, key);
        Ok(key)
    }

    pub fn verifying_key(&self, sender_peer_id: &str) -> Result<VerifyingKey> {
        if let Some(entry) = self.verifying_keys.get(sender_peer_id) {
            return Ok(*entry.value());
        }
        anyhow::ensure!(
            sender_peer_id.len() <= MAX_PEER_ID_LEN,
            "invalid peer identity length"
        );
        let pub_bytes = hex::decode(sender_peer_id)
            .map_err(|e| anyhow::anyhow!("Invalid sender peer_id hex: {}", e))?;
        let vk = VerifyingKey::from_sec1_bytes(&pub_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid sender public key: {}", e))?;
        self.cache(&self.verifying_keys, sender_peer_id, vk);
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
