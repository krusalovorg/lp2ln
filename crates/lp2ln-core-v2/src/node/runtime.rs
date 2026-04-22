use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use rand::Rng;
use tokio::sync::mpsc;

use crate::crypto::NodeKeypair;
use crate::db::P2PDatabase;
use crate::node::addressing::{detect_lan_advertise_ip, ordered_bootstrap_targets};
use crate::node::incoming_sessions::spawn_incoming_session_handler;
use crate::node::nat_traversal::NatTraversalState;
use crate::node::options::{NodeOptions, NodeRole};
use crate::node::topology_maintenance::{dial_bootstrap_address, spawn_topology_maintenance_loop};
use crate::packet::Packet;
use crate::packet_processor::{DefaultPacketProcessor, PacketProcessor};
use crate::peer_score::{PeerScoreStore, PeerScoreWeights};
use crate::protocol::control::{NatCandidate, NatCandidateKind, NetworkControlPayload};
use crate::protocol::handshake;
use crate::router::{Router, ROUTER_INCOMING_QUEUE_CAP};
use crate::sessions::manager::SessionManager;
use crate::sessions::session::IncomingPacket;
use crate::sessions::{LinkKind, Session, SessionMetrics};
use crate::topology::PeerCatalog;
use crate::transport::{Transport, TransportContext};
use crate::types::{PeerId, SessionId};
use crate::logger;
use crate::peer_score::PeerConnectionPolicy;

pub struct NodeRuntime {
    _db: Option<Arc<P2PDatabase>>,
    _options: NodeOptions,
    peer_connection_policy_live: Arc<RwLock<PeerConnectionPolicy>>,
    keypair: NodeKeypair,
    transports: Vec<Arc<dyn Transport>>,
    packet_processor: Arc<dyn PacketProcessor>,
    session_manager: Arc<SessionManager>,
    peer_catalog: Arc<PeerCatalog>,
    nat_state: Arc<NatTraversalState>,
    dial_book: Arc<DashMap<PeerId, Vec<(String, SocketAddr)>>>,
    descriptor_version: Arc<AtomicU64>,
    router: Option<Arc<Router>>,
    incoming_sessions_tx: Option<mpsc::Sender<Arc<dyn Session>>>,
}

impl NodeRuntime {
    pub fn new(
        db: Option<Arc<P2PDatabase>>,
        options: NodeOptions,
        packet_processor: Option<Arc<dyn PacketProcessor>>,
    ) -> Self {
        if let Some(ref opts) = options.logger_options {
            logger::init(opts);
        }
        let catalog_cap = options.catalog_max_peers.unwrap_or(4096).max(128);
        let peer_catalog = Arc::new(PeerCatalog::with_max_peers(catalog_cap));
        let keypair = options
            .keypair
            .or_else(|| db.as_ref().and_then(|db| db.get_or_create_node_keypair().ok()))
            .unwrap_or_else(NodeKeypair::generate);
        let nat_state = NatTraversalState::new();
        let packet_processor = packet_processor.unwrap_or_else(|| {
            Arc::new(DefaultPacketProcessor::new(
                keypair.peer_id().to_string(),
                options.allow_unsigned_packets,
                peer_catalog.clone(),
                options.peer_discovery_random_fraction,
                nat_state.clone(),
                keypair.clone(),
            )) as Arc<dyn PacketProcessor>
        });
        let peer_scores = Arc::new(PeerScoreStore::new());
        let session_manager = Arc::new(SessionManager::new(
            peer_scores,
            options.peer_score_weights.clone(),
        ));
        let peer_policy_init = options.peer_connection_policy.normalized();
        Self {
            _db: db,
            _options: NodeOptions {
                listens: options.listens,
                advertise_addrs: options.advertise_addrs,
                default_nodes: options.default_nodes,
                keypair: None,
                allow_unsigned_packets: options.allow_unsigned_packets,
                logger_options: options.logger_options,
                peer_connection_policy: options.peer_connection_policy,
                peer_score_weights: options.peer_score_weights,
                bootstrap_peer_hints: options.bootstrap_peer_hints,
                bootstrap_nodes: options.bootstrap_nodes,
                database_dir: options.database_dir.clone(),
                log_peer_score_snapshot: options.log_peer_score_snapshot,
                node_role: options.node_role,
                catalog_max_peers: options.catalog_max_peers,
                peer_discovery_random_fraction: options.peer_discovery_random_fraction,
                transport_obfuscation: options.transport_obfuscation,
                topology_tuning: options.topology_tuning,
                flow_trace: options.flow_trace,
                debug_server: options.debug_server,
            },
            peer_connection_policy_live: Arc::new(RwLock::new(peer_policy_init)),
            keypair,
            transports: vec![],
            packet_processor,
            session_manager,
            peer_catalog,
            nat_state,
            dial_book: Arc::new(DashMap::new()),
            descriptor_version: Arc::new(AtomicU64::new(1)),
            router: None,
            incoming_sessions_tx: None,
        }
    }

    pub fn add_transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transports.push(transport);
        self
    }

    pub fn peer_score_store(&self) -> Arc<PeerScoreStore> {
        self.session_manager.peer_score_store()
    }

    pub fn peer_catalog(&self) -> Arc<PeerCatalog> {
        self.peer_catalog.clone()
    }

    pub fn register_known_peer_addr(
        &self,
        peer_id: PeerId,
        transport: impl Into<String>,
        addr: SocketAddr,
    ) {
        let transport = transport.into();
        let mut entry = self.dial_book.entry(peer_id).or_default();
        if !entry
            .iter()
            .any(|(t, a)| t == &transport && a == &addr)
        {
            entry.push((transport, addr));
        }
    }

    pub async fn dial(&self, transport_name: &str, addr: SocketAddr) -> Result<Arc<dyn Session>> {
        let transport = self
            .transports
            .iter()
            .find(|t| t.name() == transport_name)
            .ok_or_else(|| anyhow::anyhow!("Transport '{}' is not registered in runtime", transport_name))?;

        transport.dial(addr).await
    }

    pub async fn connect(&self, transport_name: &str, addr: SocketAddr) -> Result<SessionId> {
        let router = self
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Node is not started, call start() first"))?;

        let session = self.dial(transport_name, addr).await?;

        let session_id = SessionId::from(session.id().to_string());
        router.register_session_only(session_id.clone(), session.clone());
        session.spawn_reader(router.incoming_sender());

        let mut obf_protocols: Vec<String> = self
            ._options
            .transport_obfuscation
            .keys()
            .cloned()
            .collect();
        obf_protocols.sort();
        let handshake_payload = handshake::encode_hello(obf_protocols);
        let handshake = Packet {
            signature: None,
            data: handshake_payload,
            nodes: vec![],
            sender: self.keypair.peer_id().to_string(),
            receiver: String::new(),
            max_hops: 8,
            request_id: None,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };
        router.send_to_session(session_id.clone(), handshake).await?;

        Ok(session_id)
    }

    pub async fn send_with_options(
        &self,
        route_peer_id: PeerId,
        data: Vec<u8>,
        receiver: Option<String>,
        max_hops: Option<u8>,
        nodes: Option<Vec<String>>,
    ) -> Result<u64> {
        let router = self
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Node is not started, call start() first"))?;

        let sender = self.keypair.peer_id();
        let receiver_str = receiver
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| route_peer_id.as_str().to_string());

        let packet = Packet {
            signature: None,
            data,
            nodes: nodes.unwrap_or_default(),
            sender: sender.to_string(),
            receiver: receiver_str,
            max_hops: max_hops.unwrap_or(8),
            request_id: None,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };

        router.send_to_peer(route_peer_id, packet, None).await
    }

    pub async fn send(&self, peer_id: PeerId, data: Vec<u8>) -> Result<u64> {
        self.send_with_options(peer_id, data, None, None, None).await
    }

    async fn build_local_nat_candidates(&self) -> Vec<NatCandidate> {
        let mut candidates = Vec::new();
        for listen in self._options.listens.iter() {
            let proto = listen.key().to_ascii_lowercase();
            let addr = *listen.value();
            candidates.push(NatCandidate {
                protocol: proto.clone(),
                addr: addr.to_string(),
                kind: NatCandidateKind::Host,
                priority: 200,
            });
            if proto == "udp" {
                if let Some(transport) = self
                    .transports
                    .iter()
                    .find(|t| t.name().eq_ignore_ascii_case("udp"))
                {
                    if let Ok(public_addr) = transport.get_public_address(addr.port()).await {
                        candidates.push(NatCandidate {
                            protocol: "udp".to_string(),
                            addr: format!("{}:{}", public_addr.ip, public_addr.port),
                            kind: NatCandidateKind::Srflx,
                            priority: 300,
                        });
                    }
                }
            }
        }
        candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
        candidates.dedup_by(|a, b| a.protocol == b.protocol && a.addr == b.addr && a.kind == b.kind);
        candidates
    }

    pub async fn start_nat_traversal(&self, route_peer_id: PeerId) -> Result<String> {
        let router = self
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Node is not started, call start() first"))?;
        let local_candidates = self.build_local_nat_candidates().await;
        if local_candidates.is_empty() {
            return Err(anyhow::anyhow!("No local candidates for NAT traversal"));
        }
        let session_id = format!("{:016x}", rand::rng().random::<u64>());
        let offer = self.nat_state.create_offer(
            session_id.clone(),
            route_peer_id.as_str().to_string(),
            local_candidates,
        );
        let payload = NetworkControlPayload::NatOffer { offer }
            .encode()
            .map_err(anyhow::Error::msg)?;
        let packet = Packet {
            signature: None,
            data: payload,
            nodes: vec![],
            sender: self.keypair.peer_id().to_string(),
            receiver: route_peer_id.as_str().to_string(),
            max_hops: 2,
            request_id: None,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };
        let _ = router.send_to_peer(route_peer_id, packet, None).await?;
        Ok(session_id)
    }

    async fn recv_reply_matching(
        &self,
        sub: &mut tokio::sync::broadcast::Receiver<IncomingPacket>,
        route_peer_id: &PeerId,
        request_id: u64,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        use tokio::sync::broadcast::error::RecvError;

        let our_id = self.keypair.peer_id().to_string();
        let peer_str = route_peer_id.as_str().to_string();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(anyhow::anyhow!(
                    "recv_reply_matching: timeout waiting for request_id {}",
                    request_id
                ));
            }
            let incoming = tokio::time::timeout(remaining, sub.recv())
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "recv_reply_matching: timeout waiting for request_id {}",
                        request_id
                    )
                })?;
            let incoming = match incoming {
                Ok(p) => p,
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => {
                    return Err(anyhow::anyhow!(
                        "recv_reply_matching: incoming channel closed"
                    ));
                }
            };
            let packet = incoming.packet;
            if packet.request_id != Some(request_id) {
                continue;
            }
            let via = incoming
                .from_node
                .as_deref()
                .unwrap_or_else(|| packet.sender.as_str());
            if via != peer_str {
                continue;
            }
            if !packet.receiver.is_empty() && packet.receiver != our_id {
                continue;
            }
            return Ok(packet.data);
        }
    }

    pub async fn send_with_options_and_wait_reply(
        &self,
        route_peer_id: PeerId,
        data: Vec<u8>,
        receiver: Option<String>,
        max_hops: Option<u8>,
        nodes: Option<Vec<String>>,
        timeout: Duration,
    ) -> Result<(u64, Vec<u8>)> {
        let router = self
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Node is not started, call start() first"))?;
        let mut sub = router.subscribe();
        let request_id = self
            .send_with_options(
                route_peer_id.clone(),
                data,
                receiver,
                max_hops,
                nodes,
            )
            .await?;
        let reply = self
            .recv_reply_matching(&mut sub, &route_peer_id, request_id, timeout)
            .await?;
        Ok((request_id, reply))
    }

    pub async fn send_and_wait_reply(
        &self,
        peer_id: PeerId,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let router = self
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Node is not started, call start() first"))?;
        let mut sub = router.subscribe();
        let request_id = self
            .send_with_options(peer_id.clone(), data, None, None, None)
            .await?;
        self.recv_reply_matching(&mut sub, &peer_id, request_id, timeout)
            .await
    }

    pub async fn send_to_session(&self, session_id: SessionId, data: Vec<u8>) -> Result<u64> {
        let router = self
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Node is not started, call start() first"))?;

        let sender = self.keypair.peer_id();
        let packet = Packet {
            signature: None,
            data,
            nodes: vec![],
            sender: sender.to_string(),
            receiver: sender.to_string(),
            max_hops: 8,
            request_id: None,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };
        router.send_to_session(session_id, packet).await
    }

    pub async fn disconnect_peer(&self, peer_id: &str) -> Result<()> {
        let pid = PeerId::from(peer_id);
        self.session_manager.close_all_sessions_for_peer(&pid).await
    }

    pub async fn disconnect_session(&self, session_id: &str) -> Result<()> {
        let sid = SessionId::from(session_id);
        self.session_manager.close_session(&sid).await
    }

    pub fn router(&self) -> Option<Arc<Router>> {
        self.router.clone()
    }

    pub fn peer_id(&self) -> &str {
        self.keypair.peer_id()
    }

    pub fn get_metrics_for_protocol(&self, kind: LinkKind) -> Vec<SessionMetrics> {
        self.session_manager.get_metrics_for_protocol(kind)
    }

    pub fn get_metrics_by_protocol(&self) -> Vec<(LinkKind, Vec<SessionMetrics>)> {
        self.session_manager.get_metrics_by_protocol()
    }

    pub fn debug_sessions(&self) -> Vec<crate::sessions::manager::SessionDebugEntry> {
        self.session_manager.debug_sessions()
    }

    pub fn peer_connection_policy(&self) -> PeerConnectionPolicy {
        self.peer_connection_policy_live.read().unwrap().clone()
    }

    pub fn effective_peer_connection_policy(&self) -> PeerConnectionPolicy {
        let base = self.peer_connection_policy_live.read().unwrap().clone();
        NodeOptions::effective_peer_connection_policy_for(base, self._options.node_role)
    }

    pub fn set_peer_connection_policy(&self, policy: PeerConnectionPolicy) -> PeerConnectionPolicy {
        let n = policy.normalized();
        *self.peer_connection_policy_live.write().unwrap() = n.clone();
        n
    }

    pub fn node_role(&self) -> NodeRole {
        self._options.node_role
    }

    pub fn active_peer_count(&self) -> usize {
        self.session_manager.distinct_peer_count()
    }

    pub fn connected_peers(&self) -> Vec<PeerId> {
        if let Some(router) = self.router.as_ref() {
            return router.connected_peers();
        }
        vec![]
    }

    pub fn nat_metrics(&self) -> (u64, u64, u64) {
        self.nat_state.metrics()
    }

    pub fn peer_score_weights(&self) -> &PeerScoreWeights {
        &self._options.peer_score_weights
    }

    pub async fn start(&mut self) -> Result<()> {
        let (incoming_sessions_tx, incoming_sessions_rx) =
            mpsc::channel(ROUTER_INCOMING_QUEUE_CAP);
        let signing_key = Some(Arc::new(self.keypair.signing_key().clone()));
        let router = {
            let (router, incoming_packets_rx) = Router::new(
                self.session_manager.clone(),
                self.packet_processor.clone(),
                signing_key,
                self.keypair.peer_id(),
            );
            let router = Arc::new(router);
            tokio::spawn(router.clone().run(incoming_packets_rx));
            router
        };
        self.router = Some(router.clone());
        let flow_trace_enabled_from_env = std::env::var("LP2LN_TRACE_FLOW")
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                matches!(v.as_str(), "1" | "true" | "yes" | "on")
            })
            .unwrap_or(false);
        let flow_trace_enabled = flow_trace_enabled_from_env || self._options.flow_trace.enabled;
        let flow_trace_json_packets = self._options.flow_trace.json_packets;
        let flow_trace_payload_preview_bytes = self._options.flow_trace.payload_preview_bytes.min(256);
        let node_role_for_trace = self._options.node_role;
        let our_peer_for_trace = self.keypair.peer_id().to_string();
        if flow_trace_enabled {
            let mut trace_rx = router.subscribe();
            crate::info!(
                "[NodeRuntime] flow-trace enabled on {:?}; reporting every 10s",
                node_role_for_trace
            );
            tokio::spawn(async move {
                use std::collections::HashMap;
                use tokio::sync::broadcast::error::RecvError;
                use tokio::time::{self, MissedTickBehavior};

                let mut interval = time::interval(Duration::from_secs(10));
                interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
                let mut counters: HashMap<(String, String, String, u8, u8, bool, String), u64> =
                    HashMap::new();

                loop {
                    tokio::select! {
                        evt = trace_rx.recv() => {
                            match evt {
                                Ok(incoming) => {
                                    let packet = incoming.packet;
                                    let via = incoming
                                        .from_node
                                        .unwrap_or_else(|| packet.sender.clone());
                                    let hops_len = packet.nodes.len().min(u8::MAX as usize) as u8;
                                    let is_forward = !packet.receiver.is_empty() && packet.receiver != our_peer_for_trace;
                                    let payload_kind = if packet.data.is_empty() {
                                        "local:handshake".to_string()
                                    } else if crate::protocol::handshake::decode_hello(&packet.data).is_some() {
                                        "local:handshake_hello".to_string()
                                    } else if packet.data.as_slice() == b"hs_ack" {
                                        "local:handshake_ack".to_string()
                                    } else if packet.data.as_slice() == b"ping" {
                                        "local:ping".to_string()
                                    } else if packet.data.as_slice() == b"pong" {
                                        "local:pong".to_string()
                                    } else if let Ok(ctrl) = NetworkControlPayload::decode(&packet.data) {
                                        let tag = match ctrl {
                                            NetworkControlPayload::AnnounceNodeDescriptor { .. } => "control:AnnounceNodeDescriptor",
                                            NetworkControlPayload::RequestPeers { .. } => "control:RequestPeers",
                                            NetworkControlPayload::PeersResponse { .. } => "control:PeersResponse",
                                            NetworkControlPayload::AnnounceEvidence { .. } => "control:AnnounceEvidence",
                                            NetworkControlPayload::PingPeerQuality { .. } => "control:PingPeerQuality",
                                            NetworkControlPayload::PongPeerQuality { .. } => "control:PongPeerQuality",
                                            NetworkControlPayload::RequestDescriptors { .. } => "control:RequestDescriptors",
                                            NetworkControlPayload::RequestCapabilities { .. } => "control:RequestCapabilities",
                                            NetworkControlPayload::FindRelays { .. } => "control:FindRelays",
                                            NetworkControlPayload::FindProviders { .. } => "control:FindProviders",
                                            NetworkControlPayload::RequestAdjacency { .. } => "control:RequestAdjacency",
                                            NetworkControlPayload::AdjacencyResponse { .. } => "control:AdjacencyResponse",
                                            NetworkControlPayload::NatOffer { .. } => "control:NatOffer",
                                            NetworkControlPayload::NatAnswer { .. } => "control:NatAnswer",
                                            NetworkControlPayload::NatPunchStart { .. } => "control:NatPunchStart",
                                            NetworkControlPayload::NatPunchResult { .. } => "control:NatPunchResult",
                                        };
                                        tag.to_string()
                                    } else {
                                        "data:opaque".to_string()
                                    };
                                    if flow_trace_json_packets {
                                        let preview = packet
                                            .data
                                            .iter()
                                            .take(flow_trace_payload_preview_bytes)
                                            .map(|b| format!("{:02x}", b))
                                            .collect::<Vec<_>>()
                                            .join("");
                                        let row = serde_json::json!({
                                            "sender": packet.sender.clone(),
                                            "receiver": packet.receiver.clone(),
                                            "via": via.clone(),
                                            "payload_kind": payload_kind.clone(),
                                            "payload_len": packet.data.len(),
                                            "payload_preview_hex": preview,
                                            "payload_preview_truncated": packet.data.len() > flow_trace_payload_preview_bytes,
                                            "path_len": hops_len,
                                            "hops_left": packet.max_hops,
                                            "is_forward": is_forward,
                                        });
                                        match serde_json::to_string_pretty(&row) {
                                            Ok(pretty) => {
                                                crate::info!("[FLOWTRACE]\n{}", pretty);
                                            }
                                            Err(_) => {
                                                crate::info!("[FLOWTRACE] packet {}", row);
                                            }
                                        }
                                    }
                                    let key = (
                                        packet.sender,
                                        packet.receiver,
                                        via,
                                        hops_len,
                                        packet.max_hops,
                                        is_forward,
                                        payload_kind,
                                    );
                                    *counters.entry(key).or_insert(0) += 1;
                                }
                                Err(RecvError::Lagged(skipped)) => {
                                    crate::warn!("[NodeRuntime] flow-trace lagged, skipped {} packets", skipped);
                                }
                                Err(RecvError::Closed) => break,
                            }
                        }
                        _ = interval.tick() => {
                            if counters.is_empty() {
                                continue;
                            }
                            let mut rows: Vec<_> = counters.into_iter().collect();
                            rows.sort_by(|a, b| b.1.cmp(&a.1));
                            let top = rows
                                .into_iter()
                                .take(12)
                                .map(|((sender, receiver, via, hops_len, hops_left, is_forward, payload_kind), cnt)| {
                                    let kind = if is_forward { "fwd" } else { "local" };
                                    format!(
                                        "{}:{} {} {}->{} via={} path_len={} hops_left={}",
                                        cnt,
                                        kind,
                                        payload_kind,
                                        sender,
                                        receiver,
                                        via,
                                        hops_len,
                                        hops_left
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join(" | ");
                            crate::info!("[FLOWTRACE] top {}", top);
                            counters = HashMap::new();
                        }
                    }
                }
            });
        }

        self.incoming_sessions_tx = Some(incoming_sessions_tx.clone());
        let ctx = TransportContext {
            incoming_sessions_tx: incoming_sessions_tx.clone(),
            incoming_packets_tx: router.incoming_sender(),
            listen_addr: None,
        };

        if self.transports.is_empty() {
            crate::error!("[NodeRuntime] No transports registered");
            return Err(anyhow::anyhow!("No transports registered"));
        }

        for transport in &self.transports {
            if !transport.is_listener() {
                continue;
            }
            let listen_addr = self._options.listens.get(transport.name()).map(|r| *r);
            let ctx_clone = TransportContext {
                incoming_sessions_tx: ctx.incoming_sessions_tx.clone(),
                incoming_packets_tx: ctx.incoming_packets_tx.clone(),
                listen_addr,
            };
            let transport_clone = transport.clone();
            let transport_name = transport.name();

            tokio::spawn(async move {
                if let Err(e) = transport_clone.start(ctx_clone).await {
                    crate::error!("[NodeRuntime] Failed to start transport {}: {}", transport_name, e);
                } else {
                    crate::info!(
                        "[NodeRuntime] Transport {} started on {}",
                        transport_name,
                        listen_addr.unwrap()
                    );
                }
            });
        }

        let session_manager = self.session_manager.clone();
        let incoming_packets_tx_for_sessions = router.incoming_sender();
        let router_for_incoming = router.clone();
        let our_peer_id_for_incoming = self.keypair.peer_id().to_string();
        let policy_live_incoming = self.peer_connection_policy_live.clone();
        let incoming_catalog = self.peer_catalog.clone();
        let incoming_peer_store = self.session_manager.peer_score_store();
        let incoming_weights = self._options.peer_score_weights.clone();
        let incoming_node_role = self._options.node_role;
        let incoming_topology_tuning = self._options.topology_tuning.clone();
        let incoming_discovery_random_fraction = self._options.peer_discovery_random_fraction;
        spawn_incoming_session_handler(
            incoming_sessions_rx,
            session_manager,
            router_for_incoming,
            our_peer_id_for_incoming,
            policy_live_incoming,
            incoming_catalog,
            incoming_peer_store,
            incoming_weights,
            incoming_node_role,
            incoming_topology_tuning,
            incoming_discovery_random_fraction,
            incoming_packets_tx_for_sessions,
        );

        let peer_scores_for_order = self.session_manager.peer_score_store();
        let bootstrap_targets = ordered_bootstrap_targets(&self._options, peer_scores_for_order.as_ref());
        let bootstrap_targets_maint = bootstrap_targets.clone();
        let advertise_fallback_ip =
            detect_lan_advertise_ip(&bootstrap_targets_maint, &self._options.default_nodes);
        let transports = self.transports.clone();
        let router_outgoing = router.clone();
        let incoming_packets_tx_outgoing = router.incoming_sender();
        let our_peer_id = self.keypair.peer_id().to_string();
        let mut obf_protocols: Vec<String> = self
            ._options
            .transport_obfuscation
            .keys()
            .cloned()
            .collect();
        obf_protocols.sort();
        let handshake_payload = handshake::encode_hello(obf_protocols);
        tokio::spawn(async move {
            for target in bootstrap_targets {
                dial_bootstrap_address(
                    &transports,
                    &router_outgoing,
                    &incoming_packets_tx_outgoing,
                    &our_peer_id,
                    &target,
                    &handshake_payload,
                )
                .await;
            }
        });

        if let Some(db) = self._db.as_ref() {
            if let Ok(cached) = db.load_peer_descriptors() {
                for desc in cached {
                    let _ = self.peer_catalog.upsert_descriptor(desc);
                }
            }
            if let Ok(scores) = db.load_peer_score_snapshot() {
                let store = self.session_manager.peer_score_store();
                for (pid, s) in scores {
                    store.insert(pid, s);
                }
            }
        }

        let policy_live_maint = self.peer_connection_policy_live.clone();
        let node_role = self._options.node_role;
        let weights = self._options.peer_score_weights.clone();
        let sm = self.session_manager.clone();
        let dial_book = self.dial_book.clone();
        let peer_store = self.session_manager.peer_score_store();
        let catalog = self.peer_catalog.clone();
        let db = self._db.clone();
        let listens = self._options.listens.clone();
        let advertise_addrs = self._options.advertise_addrs.clone();
        let transports_maint = self.transports.clone();
        let router_maint = router.clone();
        let incoming_maint = router.incoming_sender();
        let our_peer_maint = self.keypair.peer_id().to_string();
        let descriptor_ver = self.descriptor_version.clone();
        let signing_key = self.keypair.signing_key().clone();
        let log_peer_scores = self._options.log_peer_score_snapshot;
        let topology_tuning = self._options.topology_tuning.clone();
        let mut maint_obf_protocols: Vec<String> = self
            ._options
            .transport_obfuscation
            .keys()
            .cloned()
            .collect();
        maint_obf_protocols.sort();
        let maintenance_handshake_payload = handshake::encode_hello(maint_obf_protocols);

        spawn_topology_maintenance_loop(
            policy_live_maint,
            node_role,
            weights,
            sm,
            dial_book,
            peer_store,
            catalog,
            db,
            listens,
            advertise_addrs,
            advertise_fallback_ip,
            transports_maint,
            router_maint,
            incoming_maint,
            our_peer_maint,
            descriptor_ver,
            signing_key,
            log_peer_scores,
            topology_tuning,
            maintenance_handshake_payload,
            bootstrap_targets_maint,
            self.nat_state.clone(),
        );

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        for transport in &self.transports {
            transport.stop().await?;
            crate::info!("[NodeRuntime] Stopped transport: {}", transport.name());
        }
        Ok(())
    }
}
