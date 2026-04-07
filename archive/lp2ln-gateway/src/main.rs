use async_trait::async_trait;
use lp2ln_core::config::Config;
use lp2ln_core::connection::Connection;
use lp2ln_core::db::P2PDatabase;
use lp2ln_core::logger;
use lp2ln_core::manager::packet_handler::{PacketHandler, PacketHandlerResult};
use lp2ln_core::manager::types::ConnectionType;
use lp2ln_core::packets::TransportPacket;
use lp2ln_core::peer::peer_options::PeerOptions;
use lp2ln_core::peer::Peer;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

mod http;
use http::http_api::HttpApi;
use http::http_proxy::HttpProxy;

struct GatewayPacketHandler {
    http_proxy: Arc<HttpProxy>,
    http_api: Arc<HttpApi>,
}

#[async_trait]
impl PacketHandler for GatewayPacketHandler {
    async fn handle_packet(
        &self,
        packet: &TransportPacket,
        _connection_type: &ConnectionType,
        _connection: &Option<Arc<Connection>>,
    ) -> PacketHandlerResult {
        if let Some(data) = &packet.data {
            match data {
                lp2ln_core::packets::TransportData::ProxyMessage(msg) => {
                    logger::info(&format!(
                        "[Gateway] Получен ProxyMessage для HTTP серверов: {}",
                        msg.request_id
                    ));
                    self.http_proxy
                        .set_response(msg.request_id.clone(), packet.clone())
                        .await;
                    self.http_api
                        .set_response(msg.request_id.clone(), packet.clone())
                        .await;
                    return PacketHandlerResult::Handled;
                }
                lp2ln_core::packets::TransportData::FragmentSearchResponse(_) => {
                    logger::info(&format!(
                        "[Gateway] Получен FragmentSearchResponse для HTTP серверов: {}",
                        packet.uuid
                    ));
                    self.http_proxy
                        .set_response(packet.uuid.clone(), packet.clone())
                        .await;
                    self.http_api
                        .set_response(packet.uuid.clone(), packet.clone())
                        .await;
                    return PacketHandlerResult::Handled;
                }
                lp2ln_core::packets::TransportData::FileData(_) => {
                    logger::info(&format!(
                        "[Gateway] Получен FileData для HTTP серверов: {}",
                        packet.uuid
                    ));
                    self.http_api
                        .set_response(packet.uuid.clone(), packet.clone())
                        .await;
                    return PacketHandlerResult::Handled;
                }
                _ => {}
            }
        }

        if packet.act == "http_proxy_response" {
            logger::info(&format!(
                "[Gateway] Получен http_proxy_response: {}",
                packet.uuid
            ));
            if let Some(data) = &packet.data {
                if let lp2ln_core::packets::TransportData::ProxyMessage(msg) = data {
                    self.http_proxy
                        .set_response(msg.request_id.clone(), packet.clone())
                        .await;
                }
            }
            return lp2ln_core::manager::packet_handler::PacketHandlerResult::Handled;
        }

        PacketHandlerResult::Pass
    }
}

#[tokio::main]
async fn main() {
    // Инициализация логирования
    logger::set_log_file(Some("./gateway.log"));
    logger::info("Запуск P2P Gateway демона...");

    // Загрузка конфигурации
    let config = Config::from_file("config.toml");

    // Создание пути к базе данных
    let db_path = "./gateway_storage";
    let path = PathBuf::from(db_path);
    if !path.exists() {
        std::fs::create_dir_all(&path).expect("Не удалось создать директорию для БД");
    }

    // Инициализация базы данных
    let db = P2PDatabase::new(path.to_str().unwrap()).expect("Не удалось создать базу данных");

    // Получение или создание ID пира
    let peer_id = db.get_or_create_peer_id().unwrap();
    logger::info(&format!("[Gateway] UUID пира: {}", peer_id));

    // Создание пира для подключения к P2P сети
    logger::info("[Gateway] Инициализация P2P пира...");
    let peer = Peer::new(
        PeerOptions::new(SocketAddr::from(([0, 0, 0, 0], 8080)), config.storage_size),
        &db,
    )
    .await;
    let connection_manager = peer.get_connection_manager();

    logger::info("[Gateway] P2P пир подключен к сети");

    // Создание каналов для HTTP серверов
    let (proxy_http_tx, mut proxy_http_rx) = mpsc::channel::<TransportPacket>(4096);
    let (api_http_tx, mut api_http_rx) = mpsc::channel::<TransportPacket>(4096);

    // Получение публичного IP
    let public_ip = lp2ln_core::tunnel::Tunnel::new().await.get_public_ip();
    let path_blobs = format!("{}/blobs", db_path);

    // Создание HTTP Proxy сервера
    let http_proxy = Arc::new(HttpProxy::new(
        Arc::new(db.clone()),
        proxy_http_tx.clone(),
        path_blobs.clone(),
    ));
    let http_proxy_clone = http_proxy.clone();
    let http_proxy_for_handler = http_proxy.clone();

    // Создание HTTP API сервера
    let http_api = Arc::new(
        HttpApi::new(
            Arc::new(db.clone()),
            public_ip.clone(),
            api_http_tx.clone(),
            path_blobs.clone(),
        )
        .await,
    );
    let http_api_clone = http_api.clone();
    let http_api_for_handler = http_api.clone();

    connection_manager.register_packet_handler(
        "gateway_http_handler".to_string(),
        Arc::new(GatewayPacketHandler {
            http_proxy: http_proxy_for_handler,
            http_api: http_api_for_handler,
        }),
    );

    // Запуск HTTP Proxy сервера
    tokio::spawn(async move {
        http_proxy_clone.start().await;
    });

    // Запуск HTTP API сервера
    tokio::spawn(async move {
        http_api_clone.start().await;
    });

    // Обработка пакетов от HTTP Proxy
    let connection_manager_for_proxy = connection_manager.clone();
    tokio::spawn(async move {
        while let Some(packet) = proxy_http_rx.recv().await {
            logger::info(&format!(
                "[Gateway] Получен пакет от HTTP Proxy: {:?}",
                packet.to
            ));
            if let Err(e) = connection_manager_for_proxy.auto_send_packet(packet).await {
                logger::error(&format!("[Gateway] Ошибка отправки пакета: {}", e));
            }
        }
    });

    // Обработка пакетов от HTTP API
    let connection_manager_for_api = connection_manager.clone();
    tokio::spawn(async move {
        while let Some(packet) = api_http_rx.recv().await {
            logger::info(&format!(
                "[Gateway] Получен пакет от HTTP API: {:?}",
                packet.to
            ));
            if let Err(e) = connection_manager_for_api.auto_send_packet(packet).await {
                logger::error(&format!("[Gateway] Ошибка отправки пакета: {}", e));
            }
        }
    });

    logger::info("[Gateway] Gateway демон запущен и готов к работе");
    logger::info(&format!(
        "[Gateway] Подключен к сигнальному серверу: {}:{}",
        config.signal_server_ip, config.signal_server_port
    ));

    // Запуск обработки входящих пакетов (блокирующий вызов)
    peer.run().await;
}
