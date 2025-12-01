use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use k256::elliptic_curve::ecdh::diffie_hellman;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::EncodedPoint;
use k256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use uuid::Uuid;


pub fn get_shared_secret(private: &SecretKey, peer_pub_bytes: &[u8]) -> [u8; 32] {
    let secret_scalar = private.to_nonzero_scalar();
    let pub_point = EncodedPoint::from_bytes(peer_pub_bytes).expect("invalid public key bytes");
    let peer_pub = PublicKey::from_encoded_point(&pub_point).expect("invalid public key");

    let shared = diffie_hellman(secret_scalar, peer_pub.as_affine());

    let hash = Sha256::digest(shared.raw_secret_bytes());
    hash.into()
}

pub fn encrypt(plaintext: &[u8], key_bytes: [u8; 32]) -> (Vec<u8>, [u8; 12]) {
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failure!");
    (ciphertext, nonce_bytes)
}

pub fn decrypt(ciphertext: &[u8], key_bytes: [u8; 32], nonce_bytes: [u8; 12]) -> Vec<u8> {
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .expect("decryption failure!")
}


pub fn generate_uuid() -> String {
    Uuid::new_v4().to_string()
}