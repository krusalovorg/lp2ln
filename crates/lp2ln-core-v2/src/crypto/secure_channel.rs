use anyhow::Result;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::ecdh::diffie_hellman;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{EncodedPoint, PublicKey};
use rand::TryRngCore;
use rand_core::OsRng;
use sha2::{Digest, Sha256};

const ENVELOPE_MAGIC: &[u8; 4] = b"LPSC";
const ENVELOPE_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 4 + 1 + 8 + NONCE_LEN;
const REPLAY_WINDOW_BITS: u64 = 128;

pub fn derive_shared_key(private: &SigningKey, remote_peer_id_hex: &str) -> Result<[u8; 32]> {
    let peer_bytes = hex::decode(remote_peer_id_hex)
        .map_err(|e| anyhow::anyhow!("Invalid remote peer_id hex: {}", e))?;
    let point = EncodedPoint::from_bytes(&peer_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid encoded remote public key: {}", e))?;
    let public = PublicKey::from_encoded_point(&point)
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("Invalid remote public key point"))?;
    let secret_scalar = private.as_nonzero_scalar();
    let shared = diffie_hellman(secret_scalar, public.as_affine());
    let hash = Sha256::digest(shared.raw_secret_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    Ok(out)
}

pub fn is_secure_envelope(data: &[u8]) -> bool {
    data.len() >= HEADER_LEN && &data[..4] == ENVELOPE_MAGIC
}

pub fn encode_secure_envelope(plaintext: &[u8], key: [u8; 32], seq: u64) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to generate nonce: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Secure payload encryption failed: {}", e))?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(ENVELOPE_MAGIC);
    out.push(ENVELOPE_VERSION);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decode_secure_envelope(data: &[u8], key: [u8; 32]) -> Result<(u64, Vec<u8>)> {
    if !is_secure_envelope(data) {
        return Err(anyhow::anyhow!("Not a secure envelope"));
    }
    let version = data[4];
    if version != ENVELOPE_VERSION {
        return Err(anyhow::anyhow!(
            "Unsupported secure envelope version {}",
            version
        ));
    }
    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&data[5..13]);
    let seq = u64::from_be_bytes(seq_bytes);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&data[13..25]);
    let ciphertext = &data[25..];
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Secure payload decryption failed: {}", e))?;
    Ok((seq, plaintext))
}

#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    highest: u64,
    bitmap: u128,
    initialized: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::NodeKeypair;

    #[test]
    fn secure_envelope_roundtrip() {
        let a = NodeKeypair::generate();
        let b = NodeKeypair::generate();
        let key_ab = derive_shared_key(a.signing_key(), b.peer_id()).expect("derive key_ab");
        let key_ba = derive_shared_key(b.signing_key(), a.peer_id()).expect("derive key_ba");
        let payload = b"hello secure world".to_vec();
        let enc = encode_secure_envelope(&payload, key_ab, 7).expect("encrypt");
        let (seq, dec) = decode_secure_envelope(&enc, key_ba).expect("decrypt");
        assert_eq!(seq, 7);
        assert_eq!(dec, payload);
    }

    #[test]
    fn replay_window_rejects_duplicates() {
        let mut rw = ReplayWindow::default();
        assert!(rw.check_and_record(10));
        assert!(rw.check_and_record(11));
        assert!(!rw.check_and_record(10));
        assert!(!rw.check_and_record(11));
        assert!(rw.check_and_record(12));
    }
}

impl ReplayWindow {
    pub fn check_and_record(&mut self, seq: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.highest = seq;
            self.bitmap = 1;
            return true;
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            if shift >= REPLAY_WINDOW_BITS {
                self.bitmap = 0;
            } else {
                self.bitmap <<= shift as u32;
            }
            self.bitmap |= 1;
            self.highest = seq;
            return true;
        }
        let distance = self.highest - seq;
        if distance >= REPLAY_WINDOW_BITS {
            return false;
        }
        let bit = 1u128 << (distance as u32);
        if self.bitmap & bit != 0 {
            return false;
        }
        self.bitmap |= bit;
        true
    }
}
