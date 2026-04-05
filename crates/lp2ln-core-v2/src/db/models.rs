use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Storage {
    pub file_hash: String, // sha256 хеш файла
    pub fragment_hashes: Vec<String>, // массив с хешами фрагментов файла
    pub size: u64, // вес файла
    pub storage_peer_key: String, // адрес файла в сети где он был (peer key)
} 