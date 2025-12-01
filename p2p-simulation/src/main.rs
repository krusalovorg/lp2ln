use p2p_server::config::Config;
use p2p_server::db::P2PDatabase;
use p2p_server::logger;
use p2p_server::signal::SignalServer;
use p2p_server::peer::Peer;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;

struct NetworkSimulation {
    signal_servers: HashMap<String, Arc<SignalServer>>,
    peers: HashMap<String, Arc<Mutex<Peer>>>,
    db_paths: HashMap<String, PathBuf>,
}

impl NetworkSimulation {
    fn new() -> Self {
        Self {
            signal_servers: HashMap::new(),
            peers: HashMap::new(),
            db_paths: HashMap::new(),
        }
    }

    async fn add_signal_server(
        &mut self,
        config: &Config,
        id: String,
        db_path: PathBuf,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !db_path.exists() {
            std::fs::create_dir_all(&db_path)?;
        }
        let db = P2PDatabase::new(db_path.to_str().unwrap())?;
        let signal_server = SignalServer::new(config, &db).await;
        self.signal_servers.insert(id.clone(), signal_server);
        self.db_paths.insert(id, db_path);
        Ok(())
    }

    async fn add_peer(
        &mut self,
        config: &Config,
        id: String,
        db_path: PathBuf,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !db_path.exists() {
            std::fs::create_dir_all(&db_path)?;
        }
        let db = P2PDatabase::new(db_path.to_str().unwrap())?;
        let peer = Peer::new(config, &db).await;
        self.peers.insert(id.clone(), Arc::new(Mutex::new(peer)));
        self.db_paths.insert(id, db_path);
        Ok(())
    }

    async fn run_simulation(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut handles = vec![];

        logger::info("[Simulation] Запуск сигнальных серверов...");
        // Запускаем сигнальные серверы
        for (id, server) in &self.signal_servers {
            let server = server.clone();
            let id = id.clone();
            handles.push(tokio::spawn(async move {
                logger::info(&format!("[Simulation] Запуск сигнального сервера: {}", id));
                server.run().await;
            }));
        }

        logger::info("[Simulation] Запуск пиров...");
        // Запускаем пиры
        for (id, peer) in &self.peers {
            let peer = peer.clone();
            let id = id.clone();
            handles.push(tokio::spawn(async move {
                logger::info(&format!("[Simulation] Запуск пира: {}", id));
                peer.lock().await.run().await;
            }));
        }

        logger::info(&format!(
            "[Simulation] Симуляция запущена: {} сигнальных серверов, {} пиров",
            self.signal_servers.len(),
            self.peers.len()
        ));

        // Ждем завершения всех задач
        for handle in handles {
            handle.await?;
        }

        Ok(())
    }

    fn get_peer(&self, id: &str) -> Option<&Arc<Mutex<Peer>>> {
        self.peers.get(id)
    }
}

#[tokio::main]
async fn main() {
    // Инициализация логирования
    logger::set_log_file(Some("./simulation.log"));
    logger::info("Запуск P2P Network Simulation демона...");

    // Загрузка конфигурации
    let config = Config::from_file("config.toml");

    // Создание симуляции
    let mut simulation = NetworkSimulation::new();

    // Настройка симуляции через переменные окружения или конфиг
    // Можно добавить файл конфигурации для симуляции
    let num_signal_servers = std::env::var("NUM_SIGNAL_SERVERS")
        .unwrap_or_else(|_| "1".to_string())
        .parse::<usize>()
        .unwrap_or(1);

    let num_peers = std::env::var("NUM_PEERS")
        .unwrap_or_else(|_| "3".to_string())
        .parse::<usize>()
        .unwrap_or(3);

    logger::info(&format!(
        "[Simulation] Конфигурация: {} сигнальных серверов, {} пиров",
        num_signal_servers, num_peers
    ));

    // Создание сигнальных серверов
    for i in 0..num_signal_servers {
        let server_id = format!("signal_server_{}", i);
        let db_path = PathBuf::from(format!("./simulation_storage/signal_server_{}", i));
        
        logger::info(&format!(
            "[Simulation] Создание сигнального сервера: {}",
            server_id
        ));
        
        if let Err(e) = simulation
            .add_signal_server(&config, server_id.clone(), db_path)
            .await
        {
            logger::error(&format!(
                "[Simulation] Ошибка создания сигнального сервера {}: {}",
                server_id, e
            ));
        } else {
            logger::info(&format!(
                "[Simulation] Сигнальный сервер {} создан",
                server_id
            ));
        }
    }

    // Небольшая задержка для запуска серверов
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Создание пиров
    for i in 0..num_peers {
        let peer_id = format!("peer_{}", i);
        let db_path = PathBuf::from(format!("./simulation_storage/peer_{}", i));
        
        logger::info(&format!("[Simulation] Создание пира: {}", peer_id));
        
        if let Err(e) = simulation.add_peer(&config, peer_id.clone(), db_path).await {
            logger::error(&format!(
                "[Simulation] Ошибка создания пира {}: {}",
                peer_id, e
            ));
        } else {
            logger::info(&format!("[Simulation] Пир {} создан", peer_id));
        }
    }

    logger::info("[Simulation] Все узлы созданы, запуск симуляции...");

    // Запуск симуляции
    if let Err(e) = simulation.run_simulation().await {
        logger::error(&format!("[Simulation] Ошибка выполнения симуляции: {}", e));
        std::process::exit(1);
    }
}

