use super::connection_manager::ConnectionManager;
use crate::connection::Connection;
use crate::crypto::crypto::generate_uuid;
use crate::logger::{debug, error, info, peer, storage, turn};
use crate::manager::packet_handler::PacketHandlerResult;
use crate::manager::types::{ConnectionTurnStatus, ConnectionType};
use crate::packets::{
    Message, Protocol, StorageToken,
    TransportData, TransportPacket,
};
use colored::Colorize;
use futures::stream::{FuturesUnordered, StreamExt};
use hex;
use serde_json;
use std::sync::Arc;
use tokio::sync::Semaphore;

impl ConnectionManager {
    pub async fn handle_incoming_packets(&self) {
        let incoming_packet_rx = self.incoming_packet_rx.clone();
        let mut rx = incoming_packet_rx.lock().await;
        debug("Starting to handle incoming packets...");

        let semaphore = Arc::new(Semaphore::new(32));
        let mut tasks = FuturesUnordered::new();

        loop {
            if let Some((connection_type, packet, connection)) = rx.recv().await {
                let semaphore = semaphore.clone();
                let self_clone = Arc::new(self.clone());

                let task = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    self_clone
                        .process_packet(connection_type, packet, connection)
                        .await;
                });

                tasks.push(task);

                while let Some(result) = tasks.next().await {
                    if let Err(e) = result {
                        error(&format!("Task error: {}", e));
                    }
                }
            } else {
                debug("No messages received, sleeping...");
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
    }

    async fn process_packet(
        &self,
        connection_type: ConnectionType,
        packet: TransportPacket,
        connection: Option<Arc<Connection>>,
    ) {
        // Сначала проверяем пользовательские обработчики
        for entry in self.packet_handlers.iter() {
            let handler = entry.value();
            let result = handler.handle_packet(&packet, &connection_type, &connection).await;
            
            match result {
                PacketHandlerResult::Handled => {
                    debug(&format!("Packet handled by custom handler: {}", entry.key()));
                    return; // Пакет обработан, стандартная обработка не нужна
                }
                PacketHandlerResult::HandledWithResponse(response_packet) => {
                    debug(&format!("Packet handled by custom handler with response: {}", entry.key()));
                    // Отправляем ответ
                    if let Err(e) = self.auto_send_packet(response_packet).await {
                        error(&format!("Failed to send handler response: {}", e));
                    }
                    return; // Пакет обработан, стандартная обработка не нужна
                }
                PacketHandlerResult::Pass => {
                    // Продолжаем проверку других обработчиков или стандартную обработку
                    continue;
                }
            }
        }

        // Если ни один обработчик не обработал пакет, используем стандартную обработку
        match connection_type {
            ConnectionType::Signal(_id) => {
                debug(&format!("Received signal packet: {:?}", packet));
                let from_peer_key = packet.peer_key.clone();
                let protocol_connection = packet.protocol.clone();

                if let Some(data) = &packet.data {
                    match data {
                        TransportData::PeerUploadFile(data) => {
                            if let Err(e) = self
                                .handle_file_upload(
                                    &self.db,
                                    data.clone(),
                                    packet.uuid.clone(),
                                    from_peer_key.clone(),
                                )
                                .await
                            {
                                let formatted_error =
                                    format!("Failed to handle file upload: {}", e);
                                error(&formatted_error);

                                let packet_error = TransportPacket {
                                    act: "message".to_string(),
                                    to: Some(from_peer_key.clone()),
                                    data: Some(TransportData::Message(Message {
                                        text: formatted_error,
                                        nonce: None,
                                    })),
                                    protocol: Protocol::TURN,
                                    peer_key: self.db.get_or_create_peer_id().unwrap(),
                                    uuid: generate_uuid(),
                                    nodes: vec![],
                                    signature: None,
                                };

                                let _ = self.auto_send_packet(packet_error).await;
                            }
                        }
                        TransportData::PeerFileUpdate(data) => {
                            if let Err(e) = self
                                .handle_file_update(data.clone(), from_peer_key.clone())
                                .await
                            {
                                error(&format!("Failed to handle file update: {}", e));
                            }
                        }
                        TransportData::ProxyMessage(_data) => {
                            // Обработка ProxyMessage - теперь в gateway демоне
                        }
                        TransportData::FragmentSearchResponse(_response) => {
                            // Обработка FragmentSearchResponse - теперь в gateway демоне
                        }
                        TransportData::StorageReservationRequest(request) => {
                            if let Err(e) = self
                                .handle_storage_reservation_request(request.clone())
                                .await
                            {
                                error(&format!(
                                    "Failed to handle storage reservation request: {}",
                                    e
                                ));
                            }
                        }
                        TransportData::StorageValidTokenRequest(token) => {
                            if let Err(e) = self
                                .handle_storage_valid_token_request(
                                    token.token.clone(),
                                    from_peer_key.clone(),
                                )
                                .await
                            {
                                error(&format!(
                                    "Failed to handle storage valid token request: {}",
                                    e
                                ));
                            }
                        }
                        TransportData::PeerFileGet(data) => {
                            if let Err(e) = self
                                .handle_file_get(
                                    packet.uuid.clone(),
                                    data.clone(),
                                    from_peer_key.clone(),
                                )
                                .await
                            {
                                error(&format!("Failed to handle file get: {}", e));
                            }
                        }
                        TransportData::FileData(data) => {
                            let peer_id = data.peer_id.clone();
                            if let Err(e) = self.handle_file_data(data.clone()).await {
                                error(&format!("Failed to handle file data: {}", e));
                            } else {
                                if let Ok(free_space) = self.db.get_storage_free_space().await {
                                    if let Err(e) =
                                        self.db.update_token_free_space(&peer_id, free_space)
                                    {
                                        error(&format!("Failed to update token free space: {}", e));
                                    }
                                }
                            }
                        }
                        TransportData::PeerFileDelete(data) => {
                            if let Err(e) = self
                                .handle_file_delete(data.clone(), from_peer_key.clone())
                                .await
                            {
                                error(&format!("Failed to handle file delete: {}", e));
                            }
                        }
                        TransportData::PeerFileMove(data) => {
                            if let Err(e) = self
                                .handle_file_move(data.clone(), from_peer_key.clone())
                                .await
                            {
                                error(&format!("Failed to handle file move: {}", e));
                            }
                        }
                        TransportData::PeerFileAccessChange(data) => {
                            if let Err(e) = self
                                .handle_file_access_change(data.clone(), from_peer_key.clone())
                                .await
                            {
                                error(&format!("Failed to handle file access change: {}", e));
                            }
                        }
                        TransportData::StorageValidTokenResponse(response) => {
                            storage(
                                "\n╔════════════════════════════════════════════════════════════╗",
                            );
                            storage("║                    ВАЛИДАЦИЯ ТОКЕНА ХРАНИЛИЩА                  ║");
                            storage(
                                "╠════════════════════════════════════════════════════════════╣",
                            );
                            storage(&format!(
                                "║ Статус: {} ║",
                                if response.status {
                                    "✅ ТОКЕН ВАЛИДЕН"
                                } else {
                                    "❌ ТОКЕН НЕВАЛИДЕН"
                                }
                            ));
                            storage(
                                "╚════════════════════════════════════════════════════════════╝\n",
                            );
                        }
                        TransportData::PeerSearchResponse(response) => {
                            peer(
                                "\n╔════════════════════════════════════════════════════════════╗",
                            );
                            peer("║                      РЕЗУЛЬТАТЫ ПОИСКА ПИРА                    ║");
                            peer("╠════════════════════════════════════════════════════════════╣");
                            peer(&format!(
                                "║ {} ║",
                                format!("Статус: {}", "✅ ПИР НАЙДЕН").yellow()
                            ));
                            peer(&format!(
                                "║ {} ║",
                                format!("UUID пира: {}", response.peer_id).cyan()
                            ));
                            peer(&format!(
                                "║ {} ║",
                                format!(
                                    "Адрес ноды: {}:{}",
                                    response.public_ip, response.public_port
                                )
                                .cyan()
                            ));
                            peer(&format!(
                                "║ {} ║",
                                format!("Прыжков: {}", response.hops).cyan()
                            ));
                            peer(
                                "╚════════════════════════════════════════════════════════════╝\n",
                            );
                        }
                        TransportData::StorageReservationResponse(response) => {
                            storage(&format!("\n{}", "=".repeat(80).yellow()));
                            storage(&format!("{}", "ВНИМАНИЕ! ВЫ ПОЛУЧИЛИ УНИКАЛЬНЫЙ ТОКЕН ДЛЯ ХРАНЕНИЯ И ПОЛУЧЕНИЯ ДАННЫХ С P2P ПИРА".red().bold()));
                            storage(&format!(
                                "{}",
                                "ЕСЛИ ВЫ ПОТЕРЯЕТЕ КЛЮЧ ВЫ НЕ СМОЖЕТЕ ПОЛУЧИТЬ ДОСТУП К ДАННЫМ"
                                    .red()
                                    .bold()
                            ));
                            storage(&format!("{}", "=".repeat(80).yellow()));

                            if let Ok(token_bytes) = base64::decode(&response.token) {
                                if let Ok(token_str) = String::from_utf8(token_bytes) {
                                    if let Ok(token) =
                                        serde_json::from_str::<StorageToken>(&token_str)
                                    {
                                        storage(&format!("\n{}", "ДЕТАЛИ ТОКЕНА:".cyan().bold()));
                                        storage(&format!(
                                            "{} {}",
                                            "Размер файла:".yellow(),
                                            format!("{} байт", token.file_size).white()
                                        ));
                                        storage(&format!(
                                            "{} {}",
                                            "Провайдер хранилища:".yellow(),
                                            token.storage_provider.white()
                                        ));
                                        storage(&format!(
                                            "{} {}",
                                            "Временная метка:".yellow(),
                                            format!("{}", token.timestamp).white()
                                        ));
                                        storage(&format!(
                                            "{} {}",
                                            "Подпись:".yellow(),
                                            hex::encode(&token.signature).white()
                                        ));

                                        if let Err(e) = self.db.add_token(
                                            &response.peer_id,
                                            &response.token,
                                            token.file_size,
                                        ) {
                                            error(&format!(
                                                "Failed to save token to database: {}",
                                                e
                                            ));
                                        }
                                    }
                                }
                            }

                            storage(&format!("\n{}", "=".repeat(80).yellow()));
                            storage(&format!("{}", "ТОКЕН В BASE64:".cyan().bold()));
                            storage(&format!("{}", response.token.white()));
                            storage(&format!("{}", "=".repeat(80).yellow()));
                        }
                        TransportData::PeerFileSaved(data) => {
                            if let Err(e) = self.handle_file_saved(data.clone()).await {
                                println!("[Peer] Failed to handle file saved: {}", e);
                            }
                        }
                        TransportData::Message(data) => {
                            if packet.act == "message" {
                                if let Err(e) = self
                                    .handle_message(data.clone(), from_peer_key.clone())
                                    .await
                                {
                                    error(&format!("Failed to handle message: {}", e));
                                }
                            }
                        }
                        TransportData::ContractExecutionRequest(request) => {
                            if let Err(e) = self
                                .handle_contract_execution_request(
                                    request.clone(),
                                    packet.clone(),
                                )
                                .await
                            {
                                error(&format!(
                                    "Failed to handle contract execution request: {}",
                                    e
                                ));
                            }
                        }
                        TransportData::ContractExecutionResponse(response) => {
                            println!("{}", "=".repeat(80).yellow());
                            println!("{}", "КОНТРАКТ ВЫПОЛНЕН".cyan().bold());
                            println!("{}", "=".repeat(80).yellow());
                            println!("{}", String::from_utf8_lossy(&response.result).white());
                            println!("{}", "=".repeat(80).yellow());
                        }
                        _ => {}
                    }
                }

                if packet.act == "request_fragments" {
                    let _ = self.handle_fragments_request(packet).await;
                } else if packet.act == "message_response" {
                    if let Err(e) = self.handle_message_response().await {
                        error(&format!("Failed to handle message response: {}", e));
                    }
                } else if packet.act == "peer_list" {
                    if let Some(TransportData::SyncPeerInfoData(peer_info_data)) = packet.data {
                        peer("Received peer list:");
                        for peer_info in peer_info_data.peers {
                            peer(&format!("Peer - KEY: {}", peer_info.uuid));
                        }
                    } else {
                        error("Peer list data is missing.");
                    }
                } else if protocol_connection == Protocol::STUN {
                    debug("Processing STUN packet");
                    match packet.act.as_str() {
                        "wait_connection" => {
                            debug(&format!("Received wait_connection from {}", from_peer_key));
                            let result = async {
                                self.send_wait_connection(
                                    packet.peer_key.clone(),
                                    self.db.get_or_create_peer_id().unwrap(),
                                )
                                .await
                            }
                            .await;

                            if let Err(e) = result {
                                error(&format!("Failed to send wait_connection: {}", e));
                            } else {
                                debug("Successfully sent wait_connection");
                            }
                        }
                        "accept_connection" => {
                            debug(&format!(
                                "Received accept_connection from {}",
                                from_peer_key
                            ));
                            let result = self
                                .receive_accept_connection(
                                    packet,
                                    self.db.get_or_create_peer_id().unwrap(),
                                )
                                .await;

                            match result {
                                Ok(_) => {
                                    debug("Connection established successfully");
                                }
                                Err(e) => {
                                    error(&format!("Failed to establish connection: {}", e));
                                    self.connections_turn.insert(
                                        from_peer_key.clone(),
                                        ConnectionTurnStatus {
                                            connected: false,
                                            stun_connection: false,
                                            is_signal: false,
                                        },
                                    );
                                }
                            }
                        }
                        _ => {
                            debug(&format!("Unknown STUN act: {}", packet.act));
                        }
                    }
                } else if protocol_connection == Protocol::TURN && packet.act == "wait_connection" {
                    // self.connections_turn.insert(
                    //     from_peer_key.clone(),
                    //     ConnectionTurnStatus {
                    //         connected: false,
                    //         stun_connection: false,
                    //     },
                    // );
                }

                debug(&format!("From peer_key: {}", from_peer_key.clone()));
            }
            ConnectionType::Stun => {
                debug(&format!("Received message from Tunnel: {:?}", packet));
            }
        }
    }
}
