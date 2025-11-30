use crate::connection::{Connection, Message};
use crate::db::P2PDatabase;
use crate::http::http_proxy::HttpProxy;
use crate::manager::types::{ConnectionTurnStatus, ConnectionType};
use crate::manager::packet_handler::PacketHandler;
use crate::packets::{SearchPathNode, TransportData, TransportPacket};
use crate::crypto::signature::sign_packet;
use crate::tunnel::Tunnel;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

use super::types::PeerOpenNetInfo;

#[derive(Clone)]
pub struct ConnectionManager {
    pub connections: Arc<DashMap<String, Connection>>,
    pub tunnels: Arc<DashMap<String, Arc<Mutex<Tunnel>>>>,
    pub connections_stun: Arc<DashMap<String, PeerOpenNetInfo>>,

    pub incoming_packet_rx:
        Arc<Mutex<mpsc::Receiver<(ConnectionType, TransportPacket, Option<Arc<Connection>>)>>>,
    pub incoming_packet_tx:
        mpsc::Sender<(ConnectionType, TransportPacket, Option<Arc<Connection>>)>,

    pub connections_turn: Arc<DashMap<String, ConnectionTurnStatus>>,
    pub db: Arc<P2PDatabase>,
    pub http_proxy: Arc<HttpProxy>,
    pub proxy_http_tx: mpsc::Sender<TransportPacket>,

    pub proxy_http_tx_reciever: Arc<Mutex<mpsc::Sender<TransportPacket>>>,
    pub path_blobs: String,
    pub packet_handlers: Arc<DashMap<String, crate::manager::packet_handler::PacketHandlerWrapper>>,
}

impl ConnectionManager {
    pub async fn new(db: &P2PDatabase, db_path: Option<&str>) -> Self {
        let (incoming_packet_tx, incoming_packet_rx) = mpsc::channel(4096);
        let (proxy_http_tx, mut proxy_http_rx) = mpsc::channel(4096);
        let (proxy_http_tx_reciever, mut proxy_http_rx_reciever) = mpsc::channel(4096);

        let connections_turn: Arc<DashMap<String, ConnectionTurnStatus>> = Arc::new(DashMap::new());

        let connections_stun = Arc::new(DashMap::new());

        let db_path_str = db_path.unwrap_or("./storage");
        let path_blobs = format!("{}/blobs", db_path_str);

        let db_arc = Arc::new(db.clone());
        let proxy_http_tx_clone = proxy_http_tx.clone();
        let proxy = Arc::new(HttpProxy::new(
            db_arc.clone(),
            proxy_http_tx_clone,
            path_blobs.clone(),
        ));

        let proxy_clone = Arc::clone(&proxy);
        let proxy_clone_for_spawn = proxy_clone.clone();

        let mut proxy_http_rx_reciever = proxy_http_rx_reciever;

        tokio::spawn(async move {
            proxy_clone_for_spawn.start().await;
        });

        let manager = ConnectionManager {
            connections: Arc::new(DashMap::new()),
            tunnels: Arc::new(DashMap::new()),
            connections_stun,

            incoming_packet_rx: Arc::new(Mutex::new(incoming_packet_rx)),
            incoming_packet_tx,

            connections_turn,

            db: db_arc,
            http_proxy: proxy,
            proxy_http_tx,

            proxy_http_tx_reciever: Arc::new(Mutex::new(proxy_http_tx_reciever)),
            path_blobs,
            packet_handlers: Arc::new(DashMap::new()),
        };

        let manager_clone = manager.clone();
        let manager_clone_for_http = manager_clone.clone();
        tokio::spawn(async move {
            while let Some(packet) = proxy_http_rx.recv().await {
                println!(
                    "[HTTP Proxy] Getted request from http proxy: {:?}",
                    packet.to
                );
                manager_clone_for_http.auto_send_packet(packet).await;
            }
        });

        let proxy_clone_rx = proxy_clone.clone();
        tokio::spawn(async move {
            while let Some(packet) = proxy_http_rx_reciever.recv().await {
                println!(
                    "[HTTP Proxy] Getted request from http proxy: {:?}",
                    packet.to
                );
                let proxy = proxy_clone_rx.clone();
                tokio::spawn(async move {
                    let packet_clone = packet.clone();
                    match &packet_clone.data {
                        Some(TransportData::ProxyMessage(msg)) => {
                            println!(
                                "[HTTP Proxy] Getted request from http proxy: {:?}",
                                msg.from_peer_id
                            );
                            proxy
                                .set_response(msg.request_id.clone(), packet_clone)
                                .await;
                        }
                        Some(TransportData::FragmentSearchResponse(_)) => {
                            // println!(
                            //     "[HTTP Proxy] Getted FragmentSearchResponse from http proxy: {:?}",
                            //     packet_clone
                            // );
                            proxy
                                .set_response(packet_clone.uuid.clone(), packet_clone)
                                .await;
                        }
                        _ => {}
                    }
                });
            }
        });

        manager
    }

    pub async fn send_signaling_message(
        &self,
        server_address: &str,
        data: TransportPacket,
    ) -> Result<(), String> {
        if let Some(conn) = self.connections.get(server_address) {
            if let Err(e) = conn.tx.send(Message::SendData(data)).await {
                return Err(format!(
                    "Failed to send message to {}: {}",
                    server_address, e
                ));
            }
            Ok(())
        } else {
            Err(format!(
                "Signaling connection to {} not found",
                server_address
            ))
        }
    }

    pub async fn auto_send_peer_info(&self) -> Result<(), String> {
        for connection in self.connections.iter() {
            connection.send_peer_info_request_self().await;
        }
        Ok(())
    }

    pub async fn auto_send_packet(&self, mut packet: TransportPacket) -> Result<(), String> {
        if packet.signature.is_none() && packet.peer_key == self.db.get_or_create_peer_id().unwrap() {
            let signing_key = self.db.get_private_signing_key().map_err(|e| format!("Failed to get signing key: {}", e))?;
            sign_packet(&mut packet, &signing_key)?;
        }


        packet.nodes.push(SearchPathNode {
            uuid: self.db.get_or_create_peer_id().unwrap(),
            public_ip: "0.0.0.0".to_string(),
            public_port: -1,
        });

        let mut sended_by_uuid = false;

        if let Some(to) = &packet.to {
            if let Some(status) = self.connections_turn.get(to) {
                println!("Status: stun: {:?}, connected: {:?}", status.stun_connection, status.connected);
                if status.connected && status.stun_connection {
                    if let Some(tunnel) = self.tunnels.get(to) {
                        match serde_json::to_string(&packet) {
                            Ok(message) => {
                                println!("[DEBUG] Sending packet to tunnel {}", to);
                                let tunnel = tunnel.lock().await;
                                tunnel.send_packet(&message).await;
                                println!("[DEBUG] Sended packet to tunnel {}", to);
                                sended_by_uuid = true;
                            }
                            Err(e) => {
                                println!("[ERROR] Failed to serialize packet: {}", e);
                                sended_by_uuid = false;
                            },
                        }
                    }
                }
            }

            if !sended_by_uuid {
                if let Some(connection) = self.connections.get(to) {
                    if let Err(e) = connection.send_packet(packet.clone()).await {
                        println!("[ERROR] Failed to send packet to connection {}: {}", to, e);
                    } else {
                        println!(
                            "[AUTO SEND] Sended packet to connection {}: {:?}",
                            to, packet.to
                        );
                        sended_by_uuid = true;
                    }
                }
            }
        }

        if !sended_by_uuid {
            for entry in self.connections.iter() {
                if let Err(e) = entry.send_packet(packet.clone()).await {
                    println!(
                        "[ERROR] Failed to send packet to connection {}: {}",
                        entry.key(),
                        e
                    );
                } else {
                    println!(
                        "[BROADCAST] Sended packet to connection {}: {:?}",
                        entry.key(),
                        packet.to
                    );
                }
            }
        }
        Ok(())
    }

    pub async fn add_connection(&self, id: String, connection: Arc<Connection>) {
        let tx = self.incoming_packet_tx.clone();

        self.connections_turn.insert(
            id.clone(),
            ConnectionTurnStatus {
                connected: true,
                stun_connection: false,
                is_signal: true,
            },
        );

        let id_clone = id.clone();
        let connections_turn_clone = self.connections_turn.clone();

        tokio::spawn({
            let tx_clone = tx.clone();
            let connection_clone = connection.clone();
            async move {
                while let Ok(response) = connection_clone.get_response().await {
                    let _ = tx_clone
                        .send((
                            ConnectionType::Signal(id_clone.clone()),
                            response,
                            Some(connection_clone.clone()),
                        ))
                        .await;
                }
            }
        });

        self.connections.insert(
            id,
            Arc::try_unwrap(connection).unwrap_or_else(|arc| (*arc).clone()),
        );
    }

    pub async fn get_tunnel(&self, id: String) -> Option<Arc<Mutex<Tunnel>>> {
        self.tunnels.get(&id).map(|t| t.clone())
    }

    pub async fn have_connection_with_peer(&self, id: String) -> bool {
        self.connections_turn
            .get(&id)
            .map(|status| status.connected && status.stun_connection)
            .unwrap_or(false)
    }

    pub async fn add_tunnel(&self, id: String, tunnel: Tunnel) {
        let tx = self.incoming_packet_tx.clone();
        let id_for_spawn = id.clone();

        let tunnel_clone = Arc::new(tokio::sync::Mutex::new(tunnel));
        let tunnel_clone_for_spawn = tunnel_clone.clone();

        tokio::spawn(async move {
            let (local_tx, mut local_rx) = mpsc::channel::<Vec<u8>>(1024);

            tokio::spawn(async move {
                while let Some(data) = local_rx.recv().await {
                    if data.len() == 3 {
                        print!("\r\x1B[K[TUNNEL] Tunnel is alive: {}\r", id_for_spawn);
                        continue;
                    }

                    if let Ok(packet) = serde_json::from_slice(&data)
                        .map_err(|e| format!("Failed to parse TransportPacket: {}", e))
                    {
                        let _ = tx
                            .send((ConnectionType::Signal(id_for_spawn.clone()), packet, None))
                            .await;
                    } else {
                        println!(
                            "[ERROR] Failed to parse incoming data into TransportPacket: {:?}",
                            data
                        );
                    }
                }
            });

            loop {
                let mut buf = vec![0u8; 1024];
                let tunnel = tunnel_clone_for_spawn.lock().await;
                if let Some(socket) = &tunnel.socket {
                    match socket.recv_from(&mut buf).await {
                        Ok((n, _)) => {
                            let data = buf[..n].to_vec();
                            let _ = local_tx.send(data).await;
                        }
                        Err(e) => {
                            println!("[ERROR] Failed to receive data: {:?}", e);
                            break;
                        }
                    }
                }
            }
        });

        self.tunnels.insert(id.clone(), tunnel_clone);
    }

    /// Регистрация пользовательского обработчика пакетов
    /// 
    /// # Arguments
    /// * `name` - уникальное имя обработчика
    /// * `handler` - обработчик пакетов
    pub fn register_packet_handler(&self, name: String, handler: Arc<dyn PacketHandler>) {
        self.packet_handlers.insert(name, crate::manager::packet_handler::PacketHandlerWrapper::new(handler));
    }

    /// Удаление обработчика пакетов
    pub fn unregister_packet_handler(&self, name: &str) {
        self.packet_handlers.remove(name);
    }
}
