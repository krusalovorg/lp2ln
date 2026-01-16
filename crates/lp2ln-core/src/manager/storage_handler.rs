use super::connection_manager::ConnectionManager;
use crate::crypto::crypto::generate_uuid;
use crate::packets::{
    FragmentMetadata, FragmentMetadataSync, Protocol, StorageReservationRequest, StorageReservationResponse, StorageToken, StorageValidTokenResponse, TransportData, TransportPacket
};
use base64;
use hex;
use k256;
use k256::ecdsa::signature::SignerMut;
use serde_json;

impl ConnectionManager {
    pub async fn handle_storage_reservation_request(
        &self,
        request: StorageReservationRequest,
    ) -> Result<(), String> {
        let free_space = self.db.get_storage_free_space().await.unwrap();
        println!("[Peer] Free space: {}", free_space);

        if free_space < request.size_in_bytes {
            println!("[Peer] Not enough storage space available");
            return Err("Not enough storage space".to_string());
        }

        let mut signing_key = self.db.get_private_signing_key().unwrap();
        let pub_key = signing_key.verifying_key().to_sec1_bytes();
        let pub_key_hex = hex::encode(pub_key);

        let storage_token = StorageToken {
            file_size: request.size_in_bytes as u64,
            storage_provider: pub_key_hex,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: Vec::new(),
        };

        let mut token_bytes = serde_json::to_vec(&storage_token).unwrap();
        let signature: k256::ecdsa::Signature = signing_key.sign(&token_bytes);

        let mut final_token = storage_token;
        final_token.signature = signature.to_bytes().to_vec();

        let token_base64 = base64::encode(serde_json::to_vec(&final_token).unwrap());

        if let Err(e) = self.db.add_token(&request.peer_id, &token_base64, free_space) {
            println!("[Peer] Failed to save token to database: {}", e);
            return Err(format!("Failed to save token: {}", e));
        }

        let response = TransportPacket {
            act: "reserve_storage_response".to_string(),
            to: Some(request.peer_id.clone()),
            data: Some(TransportData::StorageReservationResponse(
                StorageReservationResponse {
                    peer_id: request.peer_id,
                    token: token_base64,
                    size_in_bytes: request.size_in_bytes,
                },
            )),
            protocol: Protocol::SIGNAL,
            peer_key: self.db.get_or_create_peer_id().unwrap(),
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        self.auto_send_packet(response).await.map_err(|e| e.to_string())
    }

    pub async fn handle_storage_valid_token_request(
        &self,
        token: String,
        from_uuid: String,
    ) -> Result<(), String> {
        let token_bytes = base64::decode(&token).unwrap();
        let token_str = String::from_utf8(token_bytes).unwrap();
        let token: StorageToken = serde_json::from_str(&token_str).unwrap();
        
        let mut signing_key = self.db.get_private_signing_key().unwrap();
        let pub_key = signing_key.verifying_key().to_sec1_bytes();
        let pub_key_hex = hex::encode(pub_key);

        let status = pub_key_hex == token.storage_provider;

        let response = TransportPacket {
            act: "storage_valid_token_response".to_string(),
            to: Some(from_uuid),
            data: Some(TransportData::StorageValidTokenResponse(
                StorageValidTokenResponse {
                    peer_id: self.db.get_or_create_peer_id().unwrap(),
                    status,
                },
            )),
            protocol: Protocol::SIGNAL,
            peer_key: self.db.get_or_create_peer_id().unwrap(),
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        self.auto_send_packet(response).await.map_err(|e| e.to_string())
    }

    pub async fn handle_fragments_request(
        &self,
        packet_request: TransportPacket,
    ) -> Result<(), String> {
        let mut fragments = self.db.get_my_fragments()
            .map_err(|e| format!("Ошибка при получении фрагментов: {}", e))?;
        let storage_fragments = self.db.get_storage_fragments()
            .map_err(|e| format!("Ошибка при получении фрагментов: {}", e))?;
        
        fragments.extend(storage_fragments);

        let metadata_fragments: Vec<FragmentMetadata> = fragments
            .into_iter()
            .map(|f| FragmentMetadata {
                file_hash: f.file_hash,
                mime: f.mime,
                public: f.public,
                encrypted: f.encrypted,
                compressed: f.compressed,
                auto_decompress: f.auto_decompress,
                owner_key: f.owner_key,
                storage_peer_key: f.storage_peer_key,
                size: f.size,
                is_contract: f.is_contract,
            })
            .collect();

        let sync_data = FragmentMetadataSync {
            fragments: metadata_fragments,
            peer_id: self.db.get_or_create_peer_id().unwrap(),
        };

        let packet = TransportPacket {
            act: "sync_fragments".to_string(),
            to: Some(packet_request.peer_key.clone()),
            data: Some(TransportData::FragmentMetadataSync(sync_data)),
            protocol: Protocol::SIGNAL,
            peer_key: self.db.get_or_create_peer_id().unwrap(),
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        let to_peer = packet.to.clone().unwrap();
        println!("[Peer] Send fragments to {}", to_peer);
        self.auto_send_packet(packet).await.map_err(|e| e.to_string())
    }
} 