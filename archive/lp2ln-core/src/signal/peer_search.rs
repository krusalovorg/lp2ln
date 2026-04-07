use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

use crate::crypto::crypto::generate_uuid;
use crate::crypto::signature::sign_packet;
use crate::db::P2PDatabase;
use crate::packets::{
    PeerSearchRequest, PeerSearchResponse, Protocol, SearchPathNode, TransportData, TransportPacket,
};
use crate::signal::client::SignalClient;

use super::Peer;

#[derive(Debug)]
struct SearchCache {
    found_peer_id: String,
    public_ip: String,
    public_port: i64,
    expires_at: Instant,
}

#[derive(Debug)]
pub struct PeerSearchManager {
    peers: Arc<RwLock<Vec<Arc<Peer>>>>,
    public_key: String,
    public_ip: String,
    public_port: i64,
    connected_servers: Arc<RwLock<Vec<Arc<SignalClient>>>>,
    active_searches: Arc<RwLock<HashMap<String, mpsc::Sender<PeerSearchResponse>>>>,
    search_cache: Arc<RwLock<HashMap<String, SearchCache>>>,
    db: Arc<P2PDatabase>,
}

impl PeerSearchManager {
    pub fn new(
        public_key: String,
        public_ip: String,
        public_port: i64,
        peers: Arc<RwLock<Vec<Arc<Peer>>>>,
        connected_servers: Arc<RwLock<Vec<Arc<SignalClient>>>>,
        db: Arc<P2PDatabase>,
    ) -> Arc<Self> {
        Arc::new(Self {
            db,
            peers,
            public_key,
            public_ip,
            public_port,
            connected_servers,
            active_searches: Arc::new(RwLock::new(HashMap::new())),
            search_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn handle_search_request(&self, request: PeerSearchRequest) -> Result<(), String> {
        let peer_id = request.peer_id.clone(); // id пира инициатора поиска
        let search_id = request.search_id.clone(); // id поиска

        println!(
            "[PeerSearch] Starting search for peer {} (request from {})",
            search_id, peer_id
        );

        // Проверяем кэш
        if let Some(cache) = self.search_cache.read().await.get(&search_id) {
            if cache.expires_at > Instant::now() {
                println!("[PeerSearch] Found peer {} in cache", search_id);
                let mut path = request.path.clone();
                path.push(SearchPathNode {
                    uuid: self.public_key.clone(),
                    public_ip: self.public_ip.clone(),
                    public_port: self.public_port,
                });
                let path_clone = path.clone();
                
                let response = PeerSearchResponse {
                    search_id: search_id.clone(),               // id поиска
                    peer_id: peer_id.clone(),                   // id пира инициатора поиска
                    found_peer_id: cache.found_peer_id.clone(), // id пира найденного
                    public_ip: self.public_ip.clone(),   // публичный адрес ноды пира
                    public_port: self.public_port.clone(),
                    hops: 0,                                    // количество прыжков
                    path,                                       // путь поиска
                };

                // Сначала проверяем локальных пиров
                let peers = self.peers.read().await;
                for peer in peers.iter() {
                    let peer_uuid = peer.info.peer_key.read().await;
                    if peer_uuid.as_ref() == Some(&peer_id) {
                        println!("[PeerSearch] Found initiator peer {} locally, sending response directly", peer_id);
                        let mut packet = TransportPacket {
                            act: "search_response".to_string(),
                            to: Some(peer_id.clone()),
                            data: Some(TransportData::PeerSearchResponse(response)),
                            protocol: Protocol::SIGNAL,
                            peer_key: self.public_key.clone(),
                            uuid: generate_uuid(),
                            nodes: path_clone.clone(),
                            signature: None,
                        };
                        let _ = sign_packet(&mut packet, &self.db.get_private_signing_key().unwrap());
                        peer.send_data(&serde_json::to_string(&packet).unwrap())
                            .await;
                        println!("[PeerSearch] Sent search response to peer");
                        return Ok(());
                    }
                }
                println!(
                    "[PeerSearch] Initiator peer {} not found locally, forwarding response",
                    peer_id
                );
            }
        }

        let peers = self.peers.read().await;
        println!("[PeerSearch] Checking {} local peers", peers.len());
        for peer in peers.iter() {
            let peer_uuid = peer.info.peer_key.read().await;
            if peer_uuid.as_ref() == Some(&search_id) {
                println!("[PeerSearch] Found peer {} locally", search_id);
                let mut path = request.path.clone();
                path.push(SearchPathNode {
                    uuid: self.public_key.clone(),
                    public_ip: self.public_ip.clone(),
                    public_port: self.public_port.clone(),
                });
                let path_clone = path.clone();
                
                let response = PeerSearchResponse {
                    search_id: search_id.clone(),             // id поиска
                    peer_id: peer_id.clone(),                 // id пира инициатора поиска
                    found_peer_id: search_id.clone(),         // id пира найденного
                    public_ip: self.public_ip.clone(), // публичный адрес ноды пира
                    public_port: self.public_port.clone(),
                    hops: 0,                                  // количество прыжков
                    path,                                     // путь поиска
                };

                // Кэшируем результат
                let search_id_clone = search_id.clone();
                let found_peer_id = search_id_clone.clone();
                self.search_cache.write().await.insert(
                    search_id_clone.clone(),
                    SearchCache {
                        found_peer_id,
                        public_ip: self.public_ip.clone(),
                        public_port: self.public_port.clone(),
                        expires_at: Instant::now() + Duration::from_secs(300), // 5 минут
                    },
                );

                // Сначала проверяем локальных пиров
                for initiator_peer in peers.iter() {
                    let initiator_uuid = initiator_peer.info.peer_key.read().await;
                    if initiator_uuid.as_ref() == Some(&peer_id) {
                        println!("[PeerSearch] Found initiator peer {} locally, sending response directly", peer_id);
                        let mut packet = TransportPacket {
                            act: "search_response".to_string(),
                            to: Some(peer_id.clone()),
                            data: Some(TransportData::PeerSearchResponse(response)),
                            protocol: Protocol::SIGNAL,
                            peer_key: self.public_key.clone(),
                            uuid: generate_uuid(),
                            nodes: path_clone,
                            signature: None,
                        };
                        let _ = sign_packet(&mut packet, &self.db.get_private_signing_key().unwrap());
                        initiator_peer.send_data(&serde_json::to_string(&packet).unwrap())
                            .await;
                        println!("[PeerSearch] Sent search response to peer");
                        return Ok(());
                    }
                }
                println!(
                    "[PeerSearch] Initiator peer {} not found locally, forwarding response",
                    peer_id
                );
            }
        }

        // Если не нашли локально и есть еще ходы
        if request.max_hops > 0 {
            println!(
                "[PeerSearch] Peer not found locally, forwarding search request (hops left: {})",
                request.max_hops - 1
            );
            
            // Добавляем себя в путь поиска
            let mut path = request.path.clone();
            path.push(SearchPathNode {
                uuid: self.public_key.clone(),
                public_ip: self.public_ip.clone(),
                public_port: self.public_port.clone(),
            });
            let path_clone = path.clone();
            
            let new_request = PeerSearchRequest {
                search_id: search_id.clone(),
                peer_id: request.peer_id,
                max_hops: request.max_hops - 1,
                path, // Передаем обновленный путь
            };

            let mut packet = TransportPacket {
                act: "search_peer".to_string(),
                to: None,
                data: Some(TransportData::PeerSearchRequest(new_request)),
                protocol: Protocol::SIGNAL,
                peer_key: peer_id,
                uuid: generate_uuid(),
                nodes: path_clone,
                signature: None,
            };
            let _ = sign_packet(&mut packet, &self.db.get_private_signing_key().unwrap());
            let servers = self.connected_servers.read().await;
            for server in servers.iter() {
                if let Err(e) = server.send_packet(packet.clone()).await {
                    println!(
                        "[PeerSearch] Failed to forward search request to server: {}",
                        e
                    );
                } else {
                    println!("[PeerSearch] Successfully forwarded search request to server");
                }
            }
        } else {
            println!("[PeerSearch] Search failed - max hops reached");
        }

        Ok(())
    }

    pub async fn handle_search_response(&self, response: PeerSearchResponse) -> Result<(), String> {
        println!(
            "[PeerSearch] Received search response for peer {} (from {})",
            response.search_id, response.peer_id
        );

        // Находим свой индекс в пути поиска
        let my_index = response.path.iter().position(|node| node.uuid == self.public_key);
        
        if let Some(index) = my_index {
            // Если мы последний узел в пути, значит мы инициатор поиска
            if index == response.path.len() - 1 {
                println!("[PeerSearch] We are the initiator, processing response");
                // Сначала проверяем локальных пиров
                let peers = self.peers.read().await;
                for peer in peers.iter() {
                    if let Some(peer_key) = peer.info.peer_key.read().await.clone() {
                        if peer_key == response.peer_id {
                            println!("[PeerSearch] Found initiator peer {} locally, sending response directly", response.peer_id);
                            let path_clone = response.path.clone();
                            let mut packet = TransportPacket {
                                act: "search_response".to_string(),
                                to: Some(response.peer_id.clone()),
                                data: Some(TransportData::PeerSearchResponse(response.clone())),
                                protocol: Protocol::SIGNAL,
                                peer_key: self.public_key.clone(),
                                uuid: generate_uuid(),
                                nodes: path_clone,
                                signature: None,
                            };
                            let _ = sign_packet(&mut packet, &self.db.get_private_signing_key().unwrap());
                            peer.send_data(&serde_json::to_string(&packet).unwrap())
                                .await;
                            println!("[PeerSearch] Sent search response to initiator peer");
                            return Ok(());
                        }
                    }
                }
                println!("[PeerSearch] Initiator peer {} not found locally", response.peer_id);
            } else {
                // Мы промежуточный узел, сначала проверяем локальных пиров
                let my_index = response.path.iter().position(|node| node.uuid == self.public_key).unwrap();
                let next_node = &response.path[my_index - 1];
                println!("[PeerSearch] Looking for next node {} in path", next_node.uuid);
                
                // Проверяем локальных пиров
                let peers = self.peers.read().await;
                for peer in peers.iter() {
                    if let Some(peer_key) = peer.info.peer_key.read().await.clone() {
                        if peer_key == next_node.uuid {
                            println!("[PeerSearch] Found next node {} locally, sending response directly", next_node.uuid);
                            let path_clone = response.path.clone();
                            let mut packet = TransportPacket {
                                act: "search_response".to_string(),
                                to: Some(next_node.uuid.clone()),
                                data: Some(TransportData::PeerSearchResponse(response.clone())),
                                protocol: Protocol::SIGNAL,
                                peer_key: self.public_key.clone(),
                                uuid: generate_uuid(),
                                nodes: path_clone,
                                signature: None,
                            };
                            let _ = sign_packet(&mut packet, &self.db.get_private_signing_key().unwrap());
                            peer.send_data(&serde_json::to_string(&packet).unwrap())
                                .await;
                            println!("[PeerSearch] Sent search response to next node");
                            return Ok(());
                        }
                    }
                }
                
                // Если не нашли локально, отправляем через сигнальный сервер
                println!("[PeerSearch] Next node {} not found locally, forwarding through signal server", next_node.uuid);
                let path_clone = response.path.clone();
                let mut packet = TransportPacket {
                    act: "search_response".to_string(),
                    to: Some(next_node.uuid.clone()),
                    data: Some(TransportData::PeerSearchResponse(response.clone())),
                    protocol: Protocol::SIGNAL,
                    peer_key: self.public_key.clone(),
                    uuid: generate_uuid(),
                    nodes: path_clone,
                    signature: None,
                };
                let _ = sign_packet(&mut packet, &self.db.get_private_signing_key().unwrap());
                let servers = self.connected_servers.read().await;
                let mut forwarded = false;
                for server in servers.iter() {
                    if let Err(e) = server.send_packet(packet.clone()).await {
                        println!("[PeerSearch] Failed to forward response to server: {}", e);
                    } else {
                        forwarded = true;
                        println!("[PeerSearch] Successfully forwarded response to server");
                        break;
                    }
                }

                if !forwarded {
                    println!("[PeerSearch] Failed to forward response to any server");
                }
            }
        } else {
            println!("[PeerSearch] We are not in the search path, ignoring response");
        }

        Ok(())
    }
}


