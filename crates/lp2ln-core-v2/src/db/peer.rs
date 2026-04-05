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
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::generic_array::{GenericArray, typenum::U32};

use super::P2PDatabase;
use crate::crypto::crypto::{get_shared_secret, encrypt, decrypt};
use crate::crypto::NodeKeypair;

impl P2PDatabase {
    fn get_private_key_bytes(&self) -> Result<Vec<u8>, Error> {
        let db = self.db.lock().unwrap();
        let read_txn = db.begin_read()?;
        let table = read_txn.open_table(PEER_INFO_TABLE)?;

        let data = table.get("private_key")?
            .ok_or_else(|| Error::Corrupted("Private key not found".to_string()))?;
        let priv_key_hex = String::from_utf8(data.value().to_vec())
            .map_err(|_| Error::Corrupted("Invalid UTF-8 in private key".to_string()))?;
        hex_decode(&priv_key_hex)
            .map_err(|e| Error::Corrupted(format!("Failed to decode private key: {}", e)))
    }

    /// Получить публичный ключ из приватного ключа (внутренний метод)
    fn private_to_public_key_bytes(secret_key: &SecretKey) -> [u8; 32] {
        let signing_key = SigningKey::from(secret_key);
        let verifying_key = signing_key.verifying_key();
        let pub_key = verifying_key.to_encoded_point(true);
        pub_key.as_bytes()[1..33].try_into().unwrap()
    }

    /// Получить или создать peer ID (публичный ключ)
    pub fn get_or_create_peer_id(&self) -> Result<String, Error> {
        let key_exists = {
            let db = self.db.lock().unwrap();
            let read_txn = db.begin_read()?;
            let table = read_txn.open_table(PEER_INFO_TABLE)?;
            table.get("private_key")?.is_some()
        };

        if key_exists {
            let secret_key = self.get_private_key()?;
            let pub_key_bytes = Self::private_to_public_key_bytes(&secret_key);
            Ok(hex_encode(pub_key_bytes))
        } else {
            let signing_key = SigningKey::random(&mut OsRng);
            let priv_key_bytes = signing_key.to_bytes();
            let priv_key_hex = hex_encode(priv_key_bytes);

            let db = self.db.lock().unwrap();
            let write_txn = db.begin_write()?;
            {
                let mut table = write_txn.open_table(PEER_INFO_TABLE)?;
                table.insert("private_key", priv_key_hex.as_bytes())?;
            }
            write_txn.commit()?;

            let verifying_key = signing_key.verifying_key();
            let pub_key = verifying_key.to_encoded_point(true);
            Ok(hex_encode(pub_key.as_bytes()))
        }
    }

    /// Генерация UUID (не требует доступа к БД)
    pub fn generate_uuid() -> String {
        Uuid::new_v4().to_string()
    }

    /// Получить приватный ключ
    pub fn get_private_key(&self) -> Result<SecretKey, Error> {
        let priv_key_bytes = self.get_private_key_bytes()?;
        let key_array: [u8; 32] = priv_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Corrupted("Invalid private key length".to_string()))?;
        let generic_array = GenericArray::<u8, U32>::from_slice(&key_array);
        SecretKey::from_bytes(generic_array)
            .map_err(|e| Error::Corrupted(format!("Failed to parse private key: {}", e)))
    }

    /// Получить приватный ключ для подписи
    pub fn get_private_signing_key(&self) -> Result<SigningKey, Error> {
        let priv_key_bytes = self.get_private_key_bytes()?;
        let key_array: [u8; 32] = priv_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Corrupted("Invalid private key length".to_string()))?;
        let generic_array = GenericArray::<u8, U32>::from_slice(&key_array);
        SigningKey::from_bytes(generic_array)
            .map_err(|e| Error::Corrupted(format!("Failed to parse signing key: {}", e)))
    }

    /// Получить или создать ключевую пару узла (приватный ключ из БД, при отсутствии — генерация и сохранение).
    pub fn get_or_create_node_keypair(&self) -> Result<NodeKeypair, Error> {
        self.get_or_create_peer_id()?;
        let signing_key = self.get_private_signing_key()?;
        Ok(NodeKeypair::from_signing_key(signing_key))
    }

    /// Зашифровать данные используя свой публичный ключ
    pub fn encrypt_data(&self, data: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
        let private_key = self.get_private_key()?;
        let pub_key_bytes = Self::private_to_public_key_bytes(&private_key);
        Ok(encrypt(data, pub_key_bytes))
    }

    /// Расшифровать данные используя свой приватный ключ
    pub fn decrypt_data(&self, data: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let private_key = self.get_private_key()?;
        let pub_key_bytes = Self::private_to_public_key_bytes(&private_key);
        Ok(decrypt(data, pub_key_bytes, *nonce))
    }

    /// Зашифровать сообщение для другого пира
    pub fn encrypt_message(&self, message: &[u8], peer_public_key: &str) -> Result<(Vec<u8>, [u8; 12])> {
        let private_key = self.get_private_key()?;
        let peer_pub_key_bytes = hex_decode(peer_public_key)
            .map_err(|e| anyhow::anyhow!("Failed to decode peer public key: {}", e))?;
        
        let shared_secret = get_shared_secret(&private_key, &peer_pub_key_bytes);
        Ok(encrypt(message, shared_secret))
    }

    /// Расшифровать сообщение от другого пира
    pub fn decrypt_message(&self, ciphertext: &[u8], nonce: [u8; 12], peer_public_key: &str) -> Result<Vec<u8>> {
        let private_key = self.get_private_key()?;
        let peer_pub_key_bytes = hex_decode(peer_public_key)
            .map_err(|e| anyhow::anyhow!("Failed to decode peer public key: {}", e))?;
        let peer_pub_key = PublicKey::from_sec1_bytes(&peer_pub_key_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid peer public key: {}", e))?;
        let encoded_point = peer_pub_key.to_encoded_point(false);
        let peer_pub_key_bytes = encoded_point.as_bytes();
        
        let shared_secret = get_shared_secret(&private_key, peer_pub_key_bytes);
        Ok(decrypt(ciphertext, shared_secret, nonce))
    }

    /// Распаковать сжатые данные
    pub fn uncompress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = flate2::read::GzDecoder::new(data);
        let mut decompressed_data = Vec::new();
        decoder.read_to_end(&mut decompressed_data)
            .map_err(|e| anyhow::anyhow!("Failed to decompress data: {}", e))?;
        Ok(decompressed_data)
    }
}
