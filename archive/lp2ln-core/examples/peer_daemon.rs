// Демон для демонстрации работы P2P пира
// Этот пример показывает, как использовать библиотеку для создания обычного пира

use lp2ln_core::config::Config;
use lp2ln_core::db::P2PDatabase;
use lp2ln_core::logger;
use lp2ln_core::peer::{Peer, PeerOptions};
use std::net::SocketAddr;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    // Инициализация логирования
    logger::set_log_file(Some("./peer_daemon.log"));
    logger::info("Запуск P2P пира...");

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
    
    logger::info("[Peer] P2P пир запущен и готов к работе");
    logger::info(&format!("[Peer] Подключен к сигнальному серверу: {}:{}", 
        config.signal_server_ip, config.signal_server_port));
    
    // Запуск пира (блокирующий вызов)
    // Пир будет обрабатывать входящие пакеты и поддерживать соединения
    peer.run().await;
}

