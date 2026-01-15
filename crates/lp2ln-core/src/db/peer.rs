use crate::db::tables::PEER_INFO_TABLE;
use redb::Error;
use anyhow::Result;
use uuid::Uuid;
use std::io::Read;

use hex::{decode as hex_decode, encode as hex_encode};
use k256::{
    elliptic_curve::rand_core::OsRng,
    SecretKey,
    PublicKey,
};
use k256::ecdsa::{SigningKey};
use k256::elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint};

use super::P2PDatabase;
use crate::crypto::crypto::{get_shared_secret, encrypt, decrypt};

impl P2PDatabase {
    pub fn get_or_create_peer_id(&self) -> Result<String, Error> {
        let db = self.db.lock().unwrap();
        let read_txn = db.begin_read()?;
        let table = read_txn.open_table(PEER_INFO_TABLE)?;

        if let Some(data) = table.get("private_key")? {
            let priv_key_hex = String::from_utf8(data.value().to_vec()).unwrap();
            let priv_key_bytes = hex_decode(&priv_key_hex).unwrap();

            let secret = SecretKey::from_bytes(priv_key_bytes.as_slice().try_into().unwrap()).unwrap();
            let signing_key = SigningKey::from(secret);
            let verifying_key = signing_key.verifying_key();
            let pub_key = verifying_key.to_encoded_point(true);
            let pub_key_hex = hex_encode(pub_key.as_bytes());
            return Ok(pub_key_hex);
        } else {
            drop(read_txn);

            let signing_key = SigningKey::random(&mut OsRng);
            let priv_key_bytes = signing_key.to_bytes();
            let priv_key_hex = hex_encode(priv_key_bytes);

            let verifying_key = signing_key.verifying_key();
            let pub_key = verifying_key.to_encoded_point(true);
            let pub_key_hex = hex_encode(pub_key.as_bytes());

            let write_txn = db.begin_write()?;
            {
                let mut table = write_txn.open_table(PEER_INFO_TABLE)?;
                table.insert("private_key", priv_key_hex.as_bytes())?;
            }
            write_txn.commit()?;

            Ok(pub_key_hex)
        }
    }

    pub fn generate_uuid(&self) -> Result<String, Error> {
        let uuid = Uuid::new_v4();
        let uuid_hex = uuid.to_string();
        Ok(uuid_hex)
    }

    pub fn get_private_key(&self) -> Result<SecretKey, Error> {
        let db = self.db.lock().unwrap();
        let read_txn = db.begin_read()?;
        let table = read_txn.open_table(PEER_INFO_TABLE)?;

        let data = table.get("private_key")?.ok_or_else(|| Error::Corrupted("Private key not found".to_string()))?;
        let priv_key_hex = String::from_utf8(data.value().to_vec()).unwrap();
        let priv_key_bytes = hex_decode(&priv_key_hex).unwrap();
        Ok(SecretKey::from_bytes(priv_key_bytes.as_slice().try_into().unwrap()).unwrap())
    }

    pub fn get_private_signing_key(&self) -> Result<SigningKey, Error> {
        let db = self.db.lock().unwrap();
        let read_txn = db.begin_read()?;
        let table = read_txn.open_table(PEER_INFO_TABLE)?;

        let data = table.get("private_key")?.ok_or_else(|| Error::Corrupted("Private key not found".to_string()))?;
        let priv_key_hex = String::from_utf8(data.value().to_vec()).unwrap();
        let priv_key_bytes = hex_decode(&priv_key_hex).unwrap();
        Ok(SigningKey::from_bytes(priv_key_bytes.as_slice().try_into().unwrap()).unwrap())
    }

    pub fn encrypt_data(&self, data: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
        let private_key = self.get_private_key()?;
        let signing_key = SigningKey::from(&private_key);
        let verifying_key = signing_key.verifying_key();
        let pub_key = verifying_key.to_encoded_point(true);
        let pub_key_bytes: [u8; 32] = pub_key.as_bytes()[1..33].try_into().unwrap();
        Ok(encrypt(data, pub_key_bytes))
    }

    pub fn decrypt_data(&self, data: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let private_key = self.get_private_key()?;
        let signing_key = SigningKey::from(&private_key);
        let verifying_key = signing_key.verifying_key();
        let pub_key = verifying_key.to_encoded_point(true);
        let pub_key_bytes: [u8; 32] = pub_key.as_bytes()[1..33].try_into().unwrap();
        Ok(decrypt(data, pub_key_bytes, *nonce))
    }

    pub fn encrypt_message(&self, message: &[u8], peer_public_key: &str) -> Result<(Vec<u8>, [u8; 12])> {
        let private_key = self.get_private_key()?;
        let peer_pub_key_bytes = hex_decode(peer_public_key)?;
        
        let pub_point = k256::EncodedPoint::from_bytes(&peer_pub_key_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid public key bytes"))?;
        let peer_pub_key = PublicKey::from_encoded_point(&pub_point)
            .unwrap();
        
        let signing_key = SigningKey::from(&private_key);
        let shared_secret = get_shared_secret(&private_key, &peer_pub_key_bytes);
        Ok(encrypt(message, shared_secret))
    }

    pub fn decrypt_message(&self, ciphertext: &[u8], nonce: [u8; 12], peer_public_key: &str) -> Result<Vec<u8>> {
        let private_key = self.get_private_key()?;
        let peer_pub_key_bytes = hex_decode(peer_public_key)?;
        let peer_pub_key = PublicKey::from_sec1_bytes(&peer_pub_key_bytes)?;
        let encoded_point = peer_pub_key.to_encoded_point(false);
        let peer_pub_key_bytes = encoded_point.as_bytes();
        
        let signing_key = SigningKey::from(&private_key);
        let shared_secret = get_shared_secret(&private_key, peer_pub_key_bytes);
        Ok(decrypt(ciphertext, shared_secret, nonce))
    }

    pub fn uncompress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = flate2::read::GzDecoder::new(data);
        let mut decompressed_data = Vec::new();
        decoder.read_to_end(&mut decompressed_data)
            .map_err(|e| anyhow::anyhow!("Failed to decompress data: {}", e))?;
        Ok(decompressed_data)
    }
}
