use p2p_server::config::Config;
use p2p_server::db::P2PDatabase;
use p2p_server::logger;
use p2p_server::signal::SignalServer;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    // Инициализация логирования
    logger::info("Запуск P2P демона...");
    logger::set_log_file(Some("./daemon.log"));
    logger::info("Запуск P2P демона...");

    // Загрузка конфигурации
    let config = Config::from_file("config.toml");
    
    // Создание пути к базе данных
    let db_path = "./storage";
    let path = PathBuf::from(db_path);
    if !path.exists() {
        std::fs::create_dir_all(&path).expect("Не удалось создать директорию для БД");
    }

    // Инициализация базы данных
    let db = P2PDatabase::new(path.to_str().unwrap())
        .expect("Не удалось создать базу данных");

    // Пример 1: Создание обычного пира
    // let peer = Peer::new(&config, &db).await;
    // logger::info("P2P демон запущен и готов к работе");
    // peer.run().await;

    // Пример 2: Создание сигнального сервера
    let signal_server = SignalServer::new(&config, &db).await;
    logger::info("Сигнальный сервер запущен");
    signal_server.run().await;
}

