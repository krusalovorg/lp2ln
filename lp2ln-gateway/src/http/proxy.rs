use std::sync::Arc;
use std::io::Read;
use flate2::read::GzEncoder;
use flate2::Compression;

use p2p_server::manager::connection_manager::ConnectionManager;
use p2p_server::packets::{Protocol, ProxyMessage, TransportData, TransportPacket};

pub async fn handle_http_proxy_response(
    packet: TransportPacket,
    manager: Arc<ConnectionManager>,
    path_blobs: String,
) -> Result<(), String> {
    if let Some(TransportData::FileRequest(msg)) = packet.data {
        println!("[HTTP Proxy] Received file request: {:?}", msg);

        let file_hash = msg.file_hash;
        let file_path = format!("{}/{}", path_blobs, file_hash);
        println!("[HTTP Proxy] File path: {}", file_path);
        
        if !std::path::Path::new(&file_path).exists() {
            return Err("File not found".to_string());
        }

        let file_content = match std::fs::read(&file_path) {
            Ok(content) => content,
            Err(e) => {
                return Err(format!("Failed to read file: {}", e));
            }
        };

        let mime_type = match manager.db.search_fragment_in_virtual_storage(&file_hash, Some(true)) {
            Ok(fragments) => {
                if let Some(fragment) = fragments.first() {
                    fragment.mime.clone()
                } else {
                    "application/octet-stream".to_string()
                }
            },
            Err(_) => "application/octet-stream".to_string()
        };

        let mut encoder = GzEncoder::new(&file_content[..], Compression::best());
        let mut compressed = Vec::new();
        encoder.read_to_end(&mut compressed).unwrap();

        let (encrypted_response, nonce) = manager
            .db
            .encrypt_message(&compressed, &msg.from_peer_id)
            .map_err(|e| format!("Failed to encrypt message: {}", e))?;

        let response_packet = TransportPacket {
            act: "http_proxy_response".to_string(),
            to: Some(msg.from_peer_id.clone()),
            data: Some(TransportData::ProxyMessage(ProxyMessage {
                text: encrypted_response,
                nonce: nonce,
                mime: mime_type,
                from_peer_id: manager
                    .db
                    .get_or_create_peer_id()
                    .map_err(|e| format!("Failed to get peer ID: {}", e))?,
                end_peer_id: msg.from_peer_id.clone(),
                request_id: msg.request_id.clone(),
            })),
            protocol: Protocol::TURN,
            peer_key: manager
                .db
                .get_or_create_peer_id()
                .map_err(|e| format!("Failed to get peer ID: {}", e))?,
            uuid: manager
                .db
                .generate_uuid()
                .map_err(|e| format!("Failed to generate UUID: {}", e))?,
            nodes: vec![],
            signature: None,
        };

        manager
            .auto_send_packet(response_packet)
            .await
            .map_err(|e| e.to_string())
    } else {
        Ok(())
    }
}