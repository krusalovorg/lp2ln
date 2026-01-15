use dashmap::DashMap;
use std::sync::Arc;
use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use crate::logger;

#[derive(Clone, Debug)]
pub struct InfoPeer {
    pub wait_connection: Arc<RwLock<bool>>,
    pub public_addr: Arc<RwLock<String>>,
    pub local_addr: String,
    pub is_signal_server: Arc<RwLock<bool>>,
    pub peer_key: Arc<RwLock<Option<String>>>,
}

#[derive(Debug, Clone)]
pub struct PeerOpenNetInfo {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct Peer {
    reader: Arc<RwLock<tokio::io::ReadHalf<TcpStream>>>, // Добавляем reader
    writer: Arc<RwLock<tokio::io::WriteHalf<TcpStream>>>, // Добавляем writer
    pub info: InfoPeer,                                  // Peer information (ip:port)
    tx: mpsc::Sender<String>,                            // Добавляем Sender для отправки сообщений

    open_tunnels: Arc<DashMap<String, PeerOpenNetInfo>>,
}

impl Peer {
    pub fn new(socket: TcpStream, info: Option<InfoPeer>) -> Arc<Self> {
        let mut info = info;

        if info.is_none() {
            info = Some(InfoPeer {
                wait_connection: Arc::new(RwLock::new(false)),
                public_addr: Arc::new(RwLock::new("".to_string())),
                local_addr: socket.peer_addr().unwrap().to_string(),
                peer_key: Arc::new(RwLock::new(None)),
                is_signal_server: Arc::new(RwLock::new(false)),
            });
        }

        let open_tunnels = Arc::new(DashMap::new());

        let (reader, writer) = split(socket);
        let reader = Arc::new(RwLock::new(reader));
        let writer = Arc::new(RwLock::new(writer));
        let (tx, _) = mpsc::channel(1024);

        Arc::new(Self {
            reader,
            writer,
            info: info.unwrap(),
            tx,
            open_tunnels,
        })
    }

    pub async fn send_data(&self, message: &str) {
        let message_len = message.len() as u32;
        let len_bytes = message_len.to_be_bytes();

        let mut writer = self.writer.write().await;

        // Отправляем длину сообщения (4 байта)
        if let Err(e) = writer.write_all(&len_bytes).await {
            logger::debug(&format!(
                "Failed to send message length to peer {}: {}",
                self.info.local_addr, e
            ));
            return;
        }

        // Отправляем само сообщение
        if let Err(e) = writer.write_all(message.as_bytes()).await {
            logger::debug(&format!(
                "Failed to send message to peer {}: {}",
                self.info.local_addr, e
            ));
        } else {
            logger::debug(&format!(
                "[SendData] Message sent to peer {}: {}",
                self.info.local_addr, message
            ));
        }
    }

    pub async fn receive_message(&self) -> Result<String, String> {
        let mut reader = self.reader.write().await;

        // Читаем длину сообщения (4 байта)
        let mut len_bytes = [0u8; 4];
        match reader.read_exact(&mut len_bytes).await {
            Ok(_) => {}
            Err(e) => {
                if e.kind() == std::io::ErrorKind::ConnectionReset {
                    logger::debug(&format!("Peer {} disconnected", self.info.local_addr));
                    return Err("Peer disconnected".to_string());
                }
                logger::debug(&format!(
                    "Error reading message length from peer {}: {}",
                    self.info.local_addr, e
                ));
                return Err(e.to_string());
            }
        }

        let message_len = u32::from_be_bytes(len_bytes) as usize;

        // Читаем само сообщение
        let mut message_bytes = vec![0u8; message_len];
        match reader.read_exact(&mut message_bytes).await {
            Ok(_) => {}
            Err(e) => {
                logger::debug(&format!(
                    "Error reading message from peer {}: {}",
                    self.info.local_addr, e
                ));
                return Err(e.to_string());
            }
        }

        match String::from_utf8(message_bytes) {
            Ok(message) => Ok(message),
            Err(e) => {
                logger::debug(&format!(
                    "Error converting message to string from peer {}: {}",
                    self.info.local_addr, e
                ));
                Err(e.to_string())
            }
        }
    }

    pub async fn is_signal_server(&self) -> bool {
        self.info.is_signal_server.read().await.clone()
    }

    pub async fn set_is_signal_server(&self, is_signal_server: bool) {
        let mut guard = self.info.is_signal_server.write().await;
        *guard = is_signal_server;
    }

    pub async fn add_open_tunnel(&self, peer_id: &str, ip: String, port: u16) {
        self.open_tunnels.insert(peer_id.to_string(), PeerOpenNetInfo { ip, port });
    }

    pub async fn get_open_tunnel(&self, peer_id: &str) -> Option<PeerOpenNetInfo> {
        self.open_tunnels.get(peer_id).map(|v| v.clone())
    }

    pub async fn get_key(&self) -> Option<String> {
        return self.info.peer_key.read().await.clone();
    }

    pub async fn set_wait_connection(&self, wait_connection_new: bool) {
        let mut wait_connection = self.info.wait_connection.write().await;
        *wait_connection = wait_connection_new;
    }

    pub async fn set_public_addr(&self, public_addr: String) {
        let mut public_addr_now = self.info.public_addr.write().await;
        *public_addr_now = public_addr;
    }

    pub async fn set_peer_key(&self, peer_key: String) {
        let mut current_peer_key = self.info.peer_key.write().await;
        *current_peer_key = Some(peer_key);
    }

    pub async fn send(&self, packet: String) -> Result<(), String> {
        self.send_data(&packet).await;
        Ok(())
    }

    pub async fn receive(&self) -> Result<String, String> {
        self.receive_message().await
    }
}
