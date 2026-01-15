// Пример демона пира с кастомными обработчиками пакетов (в стиле libp2p)
// Этот пример показывает, как регистрировать свои обработчики для перехвата и обработки пакетов

use lp2ln_core::config::Config;
use lp2ln_core::db::P2PDatabase;
use lp2ln_core::logger;
use lp2ln_core::peer::{Peer, PeerOptions};
use std::net::SocketAddr;
use lp2ln_core::packets::{TransportPacket, TransportData, Protocol, Message};
use lp2ln_core::manager::packet_handler::{PacketHandler, PacketHandlerResult};
use lp2ln_core::manager::types::ConnectionType;
use lp2ln_core::crypto::crypto::generate_uuid;
use lp2ln_core::connection::Connection;
use std::path::PathBuf;
use std::sync::Arc;

// Пример кастомного обработчика для сообщений
struct CustomMessageHandler {
    db: Arc<P2PDatabase>,
}

#[async_trait::async_trait]
impl PacketHandler for CustomMessageHandler {
    async fn handle_packet(
        &self,
        packet: &TransportPacket,
        _connection_type: &ConnectionType,
        _connection: &Option<Arc<Connection>>,
    ) -> PacketHandlerResult {
        // Логируем все пакеты для отладки
        logger::debug(&format!(
            "[CustomMessageHandler] Проверка пакета: act={}, from={}",
            packet.act, packet.peer_key
        ));
        
        // Обрабатываем только сообщения с act="message"
        if packet.act == "message" {
            if let Some(TransportData::Message(msg)) = &packet.data {
                println!("[CustomMessageHandler] Получено сообщение от {}: {}", packet.peer_key, msg.text);
                logger::info(&format!(
                    "[CustomMessageHandler] Получено сообщение от {}: {}",
                    packet.peer_key, msg.text
                ));

                // Отправляем ответ
                let response = TransportPacket {
                    act: "message_response".to_string(),
                    to: Some(packet.peer_key.clone()),
                    data: Some(TransportData::Message(Message {
                        text: format!("Ответ на: {}", msg.text),
                        nonce: None,
                    })),
                    protocol: Protocol::SIGNAL,
                    peer_key: self.db.get_or_create_peer_id().unwrap(),
                    uuid: generate_uuid(),
                    nodes: vec![],
                    signature: None,
                };

                return PacketHandlerResult::HandledWithResponse(response);
            }
        }

        // Пропускаем все остальные пакеты для стандартной обработки
        PacketHandlerResult::Pass
    }
}

// Пример обработчика для кастомных событий
struct CustomEventHandler {
    db: Arc<P2PDatabase>,
}

#[async_trait::async_trait]
impl PacketHandler for CustomEventHandler {
    async fn handle_packet(
        &self,
        packet: &TransportPacket,
        _connection_type: &ConnectionType,
        _connection: &Option<Arc<Connection>>,
    ) -> PacketHandlerResult {
        // Логируем все пакеты для отладки
        logger::debug(&format!(
            "[CustomEventHandler] Проверка пакета: act={}, from={}",
            packet.act, packet.peer_key
        ));
        
        // Обрабатываем только кастомные события (например, act начинается с "custom_")
        if packet.act.starts_with("custom_") {
            println!("[CustomEventHandler] Обработка кастомного события: {} от {}", packet.act, packet.peer_key);
            logger::info(&format!(
                "[CustomEventHandler] Обработка кастомного события: {} от {}",
                packet.act, packet.peer_key
            ));

            // Можно обработать и вернуть ответ или просто обработать
            match packet.act.as_str() {
                "custom_ping" => {
                    let response = TransportPacket {
                        act: "custom_pong".to_string(),
                        to: Some(packet.peer_key.clone()),
                        data: Some(TransportData::Message(Message {
                            text: "pong".to_string(),
                            nonce: None,
                        })),
                        protocol: Protocol::SIGNAL,
                        peer_key: self.db.get_or_create_peer_id().unwrap(),
                        uuid: generate_uuid(),
                        nodes: vec![],
                        signature: None,
                    };
                    return PacketHandlerResult::HandledWithResponse(response);
                }
                "custom_event" => {
                    logger::info("[CustomEventHandler] Кастомное событие обработано");
                    return PacketHandlerResult::Handled; // Обработано без ответа
                }
                _ => {}
            }
        }

        // Пропускаем все остальные пакеты
        PacketHandlerResult::Pass
    }
}

#[tokio::main]
async fn main() {
    // Инициализация логирования
    logger::set_log_file(Some("./peer_with_custom_handlers.log"));
    logger::info("Запуск P2P пира с кастомными обработчиками...");

    // Загрузка конфигурации
    let config = Config::from_file("config.toml");
    
    // Создание пути к базе данных
    let db_path = "./storage_peer";
    let path = PathBuf::from(db_path);
    if !path.exists() {
        std::fs::create_dir_all(&path).expect("Не удалось создать директорию для БД");
    }

    // Инициализация базы данных
    let db = P2PDatabase::new(path.to_str().unwrap())
        .expect("Не удалось создать базу данных");

    // Получение или создание ID пира
    let peer_id = db.get_or_create_peer_id().unwrap();
    println!("[Peer] UUID пира: {}", peer_id);
    logger::info(&format!("[Peer] UUID пира: {}", peer_id));

    // Создание пира
    println!("[Peer] Инициализация пира...");
    logger::info("[Peer] Инициализация пира...");
    let signal_addr = SocketAddr::new(
        config.signal_server_ip.parse().expect("Invalid signal server IP"),
        config.signal_server_port as u16,
    );
    let options = PeerOptions::new(signal_addr, config.storage_size);
    let peer = Peer::new(options, &db).await;
    println!("[Peer] Пир создан успешно");
    
    // Получение ConnectionManager для регистрации обработчиков
    let connection_manager = peer.get_connection_manager();
    
    // Регистрация кастомных обработчиков
    logger::info("[Peer] Регистрация кастомных обработчиков...");
    
    let db_clone = Arc::new(db.clone());
    let message_handler = Arc::new(CustomMessageHandler {
        db: db_clone.clone(),
    });
    connection_manager.register_packet_handler("custom_message".to_string(), message_handler);
    
    let event_handler = Arc::new(CustomEventHandler {
        db: db_clone,
    });
    connection_manager.register_packet_handler("custom_events".to_string(), event_handler);
    
    println!("[Peer] Кастомные обработчики зарегистрированы");
    logger::info("[Peer] Кастомные обработчики зарегистрированы");
    
    println!("[Peer] Пытаюсь подключиться к сигнальному серверу: {}:{}", 
        config.signal_server_ip, config.signal_server_port);
    logger::info(&format!("[Peer] Пытаюсь подключиться к сигнальному серверу: {}:{}", 
        config.signal_server_ip, config.signal_server_port));
    
    println!("[Peer] Убедитесь, что сигнальный сервер запущен!");
    println!("[Peer] Для запуска сигнального сервера используйте: cargo run --example daemon_example");
    logger::info("[Peer] Убедитесь, что сигнальный сервер запущен!");
    logger::info("[Peer] Для запуска сигнального сервера используйте: cargo run --example daemon_example");
    
    println!("[Peer] P2P пир запущен и готов к работе");
    logger::info("[Peer] P2P пир запущен и готов к работе");

    // Запуск основного цикла обработки пакетов
    // Все входящие пакеты будут сначала проверяться кастомными обработчиками,
    // а затем передаваться стандартной обработке, если обработчики вернули Pass
    println!("[Peer] Запуск основного цикла обработки пакетов...");
    logger::info("[Peer] Запуск основного цикла обработки пакетов...");
    peer.run().await;
}

