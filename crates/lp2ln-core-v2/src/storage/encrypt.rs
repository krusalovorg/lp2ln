//! content encryption invariant
//!
//! # Strategy (chosen)
//!
//! **XChaCha20Poly1305** with a **unique random 24-byte nonce per chunk**.
//! The nonce is stored in the chunk envelope (not derived from `chunk_index`).
//!
//! Wire envelope (what `ContentId` hashes):
//!
//! ```text
//! [ nonce: 24 bytes ][ ciphertext || Poly1305 tag ]
//! ```
//!
//! `chunk_index` is bound only as **AAD** (associated data). It authenticates
//! chunk position / reorder attempts, but must never be used as the nonce:
//! re-encrypting the same index under a reused file key would otherwise
//! collide nonces (catastrophic for stream ciphers).
//!
//! # Invariants
//!
//! - encrypting the same `(key, chunk_index, plaintext)` twice must yield
//!   **different** envelopes (different nonces);
//! - decryption of untrusted envelopes returns `Result` (no panic / `expect`);
//! - wrong key, wrong AAD index, or truncated envelope → auth failure.
//!
//! Per-file key remains the capability (`FileManifest.file_key`).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;

/// MVP plaintext chunk size before encryption.
pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

/// XChaCha20 extended nonce length (bytes).
pub const NONCE_LEN: usize = 24;

pub type ChunkKey = [u8; 32];

pub fn generate_key() -> ChunkKey {
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    key
}

fn aad_for_index(chunk_index: u32) -> [u8; 4] {
    chunk_index.to_le_bytes()
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// Encrypt `plaintext` for `chunk_index`.
///
/// Returns the full wire envelope: `nonce || ciphertext||tag`.
/// Never panics on normal inputs; AEAD failure is returned as `Err`.
pub fn encrypt_chunk(
    key: &ChunkKey,
    chunk_index: u32,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let nonce_bytes = random_nonce();
    let nonce = XNonce::from_slice(&nonce_bytes);
    let aad = aad_for_index(chunk_index);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("chunk {chunk_index} encryption failed"))?;

    let mut envelope = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Decrypt a chunk envelope produced by [`encrypt_chunk`].
///
/// `chunk_index` must match the AAD used at encrypt time.
pub fn decrypt_chunk(key: &ChunkKey, chunk_index: u32, envelope: &[u8]) -> anyhow::Result<Vec<u8>> {
    if envelope.len() <= NONCE_LEN {
        anyhow::bail!(
            "chunk {chunk_index} envelope too short ({} bytes)",
            envelope.len()
        );
    }
    let (nonce_bytes, ciphertext) = envelope.split_at(NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_bytes);
    let aad = aad_for_index(chunk_index);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("chunk {chunk_index} decryption failed"))
}

/// Extract the stored nonce from an envelope (for tests / diagnostics).
pub fn envelope_nonce(envelope: &[u8]) -> Option<&[u8]> {
    (envelope.len() > NONCE_LEN).then(|| &envelope[..NONCE_LEN])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn roundtrip() {
        let key = generate_key();
        let plain = b"hello content-encrypted world";
        let ct = encrypt_chunk(&key, 0, plain).unwrap();
        assert_ne!(&ct[NONCE_LEN..], plain.as_slice());
        assert_eq!(decrypt_chunk(&key, 0, &ct).unwrap(), plain);
    }

    #[test]
    fn wrong_aad_index_fails() {
        let key = generate_key();
        let ct = encrypt_chunk(&key, 0, b"data").unwrap();
        assert!(decrypt_chunk(&key, 1, &ct).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let ct = encrypt_chunk(&key1, 0, b"secret").unwrap();
        assert!(decrypt_chunk(&key2, 0, &ct).is_err());
    }

    #[test]
    fn truncated_envelope_fails() {
        let key = generate_key();
        assert!(decrypt_chunk(&key, 0, &[]).is_err());
        assert!(decrypt_chunk(&key, 0, &[0u8; NONCE_LEN]).is_err());
        let ct = encrypt_chunk(&key, 0, b"x").unwrap();
        assert!(decrypt_chunk(&key, 0, &ct[..ct.len() - 1]).is_err());
    }

    #[test]
    fn same_index_reencrypt_uses_fresh_nonce() {
        // Cross-version / in-place rewrite under the same file key must not
        // reuse a nonce (the old chunk_index-derived scheme failed this).
        let key = generate_key();
        let a = encrypt_chunk(&key, 0, b"version-a").unwrap();
        let b = encrypt_chunk(&key, 0, b"version-b").unwrap();
        assert_ne!(a, b);
        assert_ne!(envelope_nonce(&a), envelope_nonce(&b));
        assert_eq!(decrypt_chunk(&key, 0, &a).unwrap(), b"version-a");
        assert_eq!(decrypt_chunk(&key, 0, &b).unwrap(), b"version-b");
    }

    #[test]
    fn identical_plaintext_still_gets_unique_nonces() {
        let key = generate_key();
        let mut nonces = HashSet::new();
        for _ in 0..64 {
            let env = encrypt_chunk(&key, 7, b"same bytes").unwrap();
            let n = envelope_nonce(&env).unwrap().to_vec();
            assert!(nonces.insert(n), "nonce reused under same key+index");
            assert_eq!(decrypt_chunk(&key, 7, &env).unwrap(), b"same bytes");
        }
    }

    #[test]
    fn cross_file_keys_independent() {
        // Two files (distinct keys) encrypting chunk 0 must not share nonce space
        // in a way that couples security — each envelope carries its own nonce.
        let key_a = generate_key();
        let key_b = generate_key();
        let a = encrypt_chunk(&key_a, 0, b"file-a").unwrap();
        let b = encrypt_chunk(&key_b, 0, b"file-b").unwrap();
        assert!(decrypt_chunk(&key_a, 0, &b).is_err());
        assert!(decrypt_chunk(&key_b, 0, &a).is_err());
        assert_eq!(decrypt_chunk(&key_a, 0, &a).unwrap(), b"file-a");
        assert_eq!(decrypt_chunk(&key_b, 0, &b).unwrap(), b"file-b");
    }

    #[test]
    fn nonce_len_is_xchacha() {
        assert_eq!(NONCE_LEN, 24);
        let env = encrypt_chunk(&generate_key(), 0, b"x").unwrap();
        assert_eq!(envelope_nonce(&env).unwrap().len(), NONCE_LEN);
    }
}
