use super::connection_manager::ConnectionManager;
use crate::{
    crypto::crypto::generate_uuid, packets::{Message, Protocol, TransportData, TransportPacket}
};
use colored::*;

impl ConnectionManager {
    pub async fn handle_message(
        &self,
        data: Message,
        from_uuid: String,
    ) -> Result<(), String> {
        println!("{}", format!("[Peer] Message: {}", data.text).green());

        let response_packet = TransportPacket {
            act: "message_response".to_string(),
            to: Some(from_uuid),
            data: Some(TransportData::Message(Message {
                text: "Message received".to_string(),
                nonce: None,
            })),
            protocol: Protocol::TURN,
            peer_key: self.db.get_or_create_peer_id().unwrap(),
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        self.auto_send_packet(response_packet).await.map_err(|e| e.to_string())
    }

    pub async fn handle_message_response(&self) -> Result<(), String> {
        println!("{}", "[Peer] Message sent successfully".green());
        Ok(())
    }
}
