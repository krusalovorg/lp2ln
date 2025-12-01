use serde::{Deserialize, Serialize};
use p2p_server::packets::{Protocol, TransportData};

#[derive(Debug, Serialize, Deserialize)]
pub struct PacketRequest {
    pub to: Option<String>,
    pub data: Option<TransportData>,
    pub protocol: Protocol,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileAccessRequest {
    pub public: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UploadRequest {
    pub filename: String,
    pub contents: Vec<u8>,
    pub public: bool,
    pub encrypted: bool,
    pub compressed: bool,
    pub auto_decompress: bool,
    pub token: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct UpdateRequest {
    pub file_hash: String,
    pub contents: Vec<u8>,
    pub public: bool,
    pub encrypted: bool,
    pub compressed: bool,
    pub auto_decompress: bool,
    pub token: String,
}

#[derive(serde::Serialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub host_type: String,
    pub status: String,
    pub connection_type: String,
    pub last_switch: String,
} 