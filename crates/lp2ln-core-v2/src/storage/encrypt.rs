// M5 — per-chunk ChaCha20Poly1305 encryption
//
// Roadmap: plaintext → encrypt → chunk; ContentId = SHA-256(ciphertext).
// Key is the capability; nonce is derived from chunk index so the same
// chunk position always decrypts correctly without storing extra state.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB MVP

pub type ChunkKey = [u8; 32];

fn make_nonce(chunk_index: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&chunk_index.to_le_bytes());
    n
}

pub fn generate_key() -> ChunkKey {
    use rand::Rng;
    rand::rng().random()
}

pub fn encrypt_chunk(key: &ChunkKey, chunk_index: u32, plaintext: &[u8]) -> Vec<u8> {
    let n = make_nonce(chunk_index);
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(Nonce::from_slice(&n), plaintext)
        .expect("encrypt")
}

pub fn decrypt_chunk(
    key: &ChunkKey,
    chunk_index: u32,
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let n = make_nonce(chunk_index);
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(&n), ciphertext)
        .map_err(|_| anyhow::anyhow!("chunk {} decryption failed", chunk_index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = generate_key();
        let plain = b"hello content-encrypted world";
        let ct = encrypt_chunk(&key, 0, plain);
        assert_ne!(ct.as_slice(), plain.as_slice());
        assert_eq!(decrypt_chunk(&key, 0, &ct).unwrap(), plain);
    }

    #[test]
    fn wrong_nonce_fails() {
        let key = generate_key();
        let ct = encrypt_chunk(&key, 0, b"data");
        assert!(decrypt_chunk(&key, 1, &ct).is_err());
    }
}
