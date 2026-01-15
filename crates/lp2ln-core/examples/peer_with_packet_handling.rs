// Расширенный пример демона пира с возможностью отправки и обработки пакетов
// Этот пример показывает, как использовать библиотеку для работы с пакетами

use lp2ln_core::config::Config;
use lp2ln_core::db::P2PDatabase;
use lp2ln_core::logger;
use lp2ln_core::peer::{Peer, PeerOptions};
use std::net::SocketAddr;
use lp2ln_core::peer::peer_api::PeerAPI;
use lp2ln_core::packets::{TransportPacket, TransportData, Protocol, Message};
use lp2ln_core::crypto::crypto::generate_uuid;
use std::path::PathBuf;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() {
    // Инициализация логирования
    logger::set_log_file(Some("./peer_with_packets.log"));
    logger::info("Запуск P2P пира с обработкой пакетов...");

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
    logger::info(&format!("[Peer] UUID пира: {}", peer_id));

    // Создание пира
    logger::info("[Peer] Инициализация пира...");
    let signal_addr = SocketAddr::new(
        config.signal_server_ip.parse().expect("Invalid signal server IP"),
        config.signal_server_port as u16,
    );
    let options = PeerOptions::new(signal_addr, config.storage_size);
    let peer = Peer::new(options, &db).await;
    
    // Получение ConnectionManager для работы с пакетами
    let connection_manager = peer.get_connection_manager();
    
    // Получение Connection для прямой отправки
    let connection = peer.get_connection();
    
    // Создание PeerAPI для работы с высокоуровневыми операциями
    let peer_api = PeerAPI::new(connection.clone(), &db, &connection_manager);
    
    logger::info("[Peer] P2P пир запущен и готов к работе");
    logger::info(&format!("[Peer] Подключен к сигнальному серверу: {}:{}", 
        config.signal_server_ip, config.signal_server_port));

    // Пример 1: Отправка кастомного сообщения через ConnectionManager
    let connection_manager_clone = connection_manager.clone();
    let db_clone = db.clone();
    tokio::spawn(async move {
        sleep(Duration::from_secs(5)).await; // Ждем подключения
        
        logger::info("[Example] Отправка тестового сообщения...");
        
        // Создаем кастомный пакет с сообщением
        let custom_packet = TransportPacket {
            act: "message".to_string(),
            to: None, // Broadcast - всем пирам
            data: Some(TransportData::Message(Message {
                text: "Привет от пира!".to_string(),
                nonce: None,
            })),
            protocol: Protocol::SIGNAL,
            peer_key: db_clone.get_or_create_peer_id().unwrap(),
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };
        
        // Отправляем пакет
        if let Err(e) = connection_manager_clone.auto_send_packet(custom_packet).await {
            logger::error(&format!("[Example] Ошибка отправки пакета: {}", e));
        } else {
            logger::info("[Example] Пакет успешно отправлен");
        }
    });

    // Пример 2: Регистрация кастомного обработчика пакетов (в стиле libp2p)
    // См. пример peer_with_custom_handlers.rs для подробностей
    // 
    // use lp2ln_core::manager::packet_handler::{PacketHandler, PacketHandlerResult};
    // 
    // struct MyHandler;
    // #[async_trait::async_trait]
    // impl PacketHandler for MyHandler {
    //     async fn handle_packet(...) -> PacketHandlerResult {
    //         // Обработать пакет или вернуть Pass для стандартной обработки
    //         PacketHandlerResult::Pass
    //     }
    // }
    // 
    // connection_manager.register_packet_handler("my_handler".to_string(), Arc::new(MyHandler));

    // Пример 3: Использование PeerAPI для работы с файлами
    let peer_api_clone = peer_api.clone();
    tokio::spawn(async move {
        sleep(Duration::from_secs(10)).await;
        
        logger::info("[Example] Пример использования PeerAPI:");
        
        // Поиск пира (пример)
        // peer_api_clone.search_peer("some-peer-id".to_string()).await;
        
        // Запрос списка пиров
        if let Err(e) = peer_api_clone.request_peer_list().await {
            logger::error(&format!("[Example] Ошибка запроса списка пиров: {}", e));
        }
    });

    // Запуск основного цикла обработки пакетов
    // Это блокирующий вызов, который обрабатывает все входящие пакеты
    peer.run().await;
}

