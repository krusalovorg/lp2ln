use crate::crypto::crypto::generate_uuid;
use crate::crypto::signature::sign_packet;
use crate::db::P2PDatabase;
use crate::packets::{PeerInfo, Protocol, TransportData, TransportPacket};
use anyhow::Result;
use std::sync::Arc;
use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};

#[derive(Debug)]
struct Peer {
    socket: Arc<RwLock<TcpStream>>,
    info: String,
}

type PeersSender = mpsc::Sender<Peer>;
type PeersReceiver = mpsc::Receiver<Peer>;

#[derive(Debug)]
pub struct SignalClient {
    writer: Option<Arc<RwLock<tokio::io::WriteHalf<TcpStream>>>>,
    reader: Option<Arc<RwLock<tokio::io::ReadHalf<TcpStream>>>>,
    db: Arc<P2PDatabase>,
    message_tx: mpsc::Sender<TransportPacket>,
    message_rx: Option<mpsc::Receiver<TransportPacket>>,
    pub signal_server_ip: String,
    pub signal_server_port: u16,
    pub public_key: String,
}

impl SignalClient {
    pub fn new(db: &P2PDatabase) -> Self {
        let (message_tx, message_rx) = mpsc::channel(1024);
        SignalClient {
            writer: None,
            reader: None,
            db: Arc::new(db.clone()),
            message_tx,
            message_rx: Some(message_rx),
            signal_server_ip: "".to_string(),
            signal_server_port: 0,
            public_key: "".to_string(),
        }
    }

    pub fn get_message_receiver(&mut self) -> Option<mpsc::Receiver<TransportPacket>> {
        self.message_rx.take()
    }

    pub async fn connect(
        &mut self,
        signal_server_ip: &str,
        signal_server_port: i64,
        public_ip: &str,
        public_port: u16,
        public_key: &str,
    ) -> Result<(), String> {
        println!(
            "[SignalClient] Connecting to signal server {}:{}",
            signal_server_ip, signal_server_port
        );

        self.signal_server_ip = signal_server_ip.to_string();
        self.signal_server_port = signal_server_port as u16;
        self.public_key = public_key.to_string();
        match TcpStream::connect(format!("{}:{}", signal_server_ip, signal_server_port)).await {
            Ok(socket) => {
                let (reader, writer) = split(socket);
                self.writer = Some(Arc::new(RwLock::new(writer)));
                self.reader = Some(Arc::new(RwLock::new(reader)));

                // Запускаем обработчик входящих сообщений
                let reader = self.reader.as_ref().unwrap().clone();
                let db = self.db.clone();
                let message_tx = self.message_tx.clone();
                tokio::spawn(async move {
                    let mut buffer = [0; 1024];
                    loop {
                        let mut reader_guard = reader.write().await;
                        
                        // Читаем длину сообщения (4 байта)
                        let mut len_bytes = [0u8; 4];
                        match reader_guard.read_exact(&mut len_bytes).await {
                            Ok(_) => {
                                let message_len = u32::from_be_bytes(len_bytes) as usize;
                                
                                // Читаем само сообщение
                                let mut message_bytes = vec![0u8; message_len];
                                match reader_guard.read_exact(&mut message_bytes).await {
                                    Ok(_) => {
                                        let message = String::from_utf8_lossy(&message_bytes);
                                        println!("[SignalClient] Received message: {}", message);
                                        if let Ok(packet) = serde_json::from_str::<TransportPacket>(&message) {
                                            println!("[SignalClient] Parsed packet: {:?}", packet);
                                            
                                            // Отправляем пакет в канал для обработки
                                            if let Err(e) = message_tx.send(packet).await {
                                                println!("[SignalClient] Failed to send packet to handler: {}", e);
                                                break;
                                            }
                                        } else {
                                            println!("[SignalClient] Failed to parse packet: {}", message);
                                        }
                                    }
                                    Err(e) => {
                                        println!("[SignalClient] Error reading message: {}", e);
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::ConnectionReset {
                                    println!("[SignalClient] Connection closed by server");
                                    break;
                                }
                                println!("[SignalClient] Error reading message length: {}", e);
                                break;
                            }
                        }
                    }
                });

                let fragments = self.db.get_storage_fragments().unwrap();
                let mut stored_files = Vec::new();
                for fragment in fragments {
                    stored_files.push(fragment.file_hash.clone());
                }

                let connect_packet = TransportPacket {
                    act: "info".to_string(),
                    to: None,
                    data: Some(TransportData::PeerInfo(PeerInfo {
                        public_key: self.db.get_or_create_peer_id().unwrap(),
                        total_space: self.db.get_total_space().unwrap_or(0),
                        free_space: self.db.get_storage_free_space().await.unwrap_or(0),
                        stored_files: stored_files,
                        is_signal_server: true,
                    })),
                    protocol: Protocol::SIGNAL,
                    peer_key: self.db.get_or_create_peer_id().unwrap(),
                    uuid: generate_uuid(),
                    nodes: vec![],
                    signature: None,
                };

                self.send_packet(connect_packet).await?;

                Ok(())
            }
            Err(e) => {
                println!("[SignalClient] Failed to connect to signal server: {}", e);
                Err(e.to_string())
            }
        }
    }

    pub async fn send_packet(&self, packet: TransportPacket) -> Result<(), String> {
        let mut packet = packet;
        let _ = sign_packet(&mut packet, &self.db.get_private_signing_key().unwrap());
        
        let string_packet = serde_json::to_string(&packet).unwrap();
        let message_len = string_packet.len() as u32;
        let len_bytes = message_len.to_be_bytes();

        if let Some(writer) = &self.writer {
            // println!(
            //     "[SignalClient] Sending packet to signal server: {}",
            //     string_packet
            // );

            let mut writer_guard = writer.write().await;
            
            // Отправляем длину сообщения
            match writer_guard.write_all(&len_bytes).await {
                Ok(_) => {
                    // Отправляем само сообщение
                    match writer_guard.write_all(string_packet.as_bytes()).await {
                        Ok(_) => {
                            println!("[SignalClient] Successfully sent packet");
                            Ok(())
                        }
                        Err(e) => {
                            println!("[SignalClient] Failed to send packet: {}", e);
                            Err(e.to_string())
                        }
                    }
                }
                Err(e) => {
                    println!("[SignalClient] Failed to send packet length: {}", e);
                    Err(e.to_string())
                }
            }
        } else {
            println!("[SignalClient] Writer is not connected");
            Err("[SignalClient] Writer is not connected".to_string())
        }
    }
}
