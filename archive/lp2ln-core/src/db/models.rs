use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Storage {
    pub file_hash: String, // sha256
    pub filename: String,
    pub mime: String, // mime type for http proxy
    pub public: bool, // true if file is public (not encrypted)
    pub encrypted: bool, // true if file is encrypted
    pub compressed: bool, // true if file is compressed
    pub auto_decompress: bool, // true if file should be automatically decompressed
    pub owner_key: String, // owner public key
    pub storage_peer_key: String, // provider peer key
    pub uploaded_via_token: Option<String>, // base64 token
    pub token: String, // base64 token
    pub token_hash: Option<String>, // hash of the token
    pub size: u64,
    pub groups: Vec<String>,
    pub tags: Vec<String>,
    pub is_contract: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenInfo {
    pub token: String,
    pub free_space: u64,
    pub used_space: u64,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValidatorStorageInfo {
    pub peer_id: String,
    pub free_space: u64,
    pub total_space: u64,
    pub last_update: u64,
    pub is_online: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerStats {
    pub public_key: String,
    pub total_space: u64,
    pub free_space: u64,
    pub stored_files: Vec<String>, // хэши файлов
    pub last_update: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContractMetadata {
    pub contract_id: String,
    pub action: String,
    pub timestamp: u64,
    pub data: HashMap<String, String>,
    pub success: bool,
    pub message: String,
} 