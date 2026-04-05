use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use tokio::sync::mpsc;

use crate::crypto::NodeKeypair;
use crate::db::P2PDatabase;
use crate::node::addressing::{
    advertised_addr_for_protocol, detect_lan_advertise_ip, ordered_bootstrap_targets,
};
use crate::node::connection_strategy::{
    bootstrap_dial_quota, dial_reserve_slots, peers_to_drop_when_overloaded, rank_dial_candidates,
    send_discovery_redirect_and_close, should_reseed_bootstrap, should_skip_for_bootstrap_quota,
    BOOTSTRAP_INCOMING_HEADROOM, INCOMING_ROTATION_INTERVAL_MS,
};
use crate::node::options::{BootstrapNode, NodeOptions, NodeRole};
use crate::packet::Packet;
use crate::packet_processor::{DefaultPacketProcessor, PacketProcessor};
use crate::peer_score::{total_score, PeerScore, PeerScoreStore, PeerScoreWeights};
use crate::protocol::control::NetworkControlPayload;
use crate::router::{Router, ROUTER_INCOMING_QUEUE_CAP};
use crate::sessions::manager::SessionManager;
use crate::sessions::session::IncomingPacket;
use crate::sessions::{LinkKind, Session, SessionMetrics};
use crate::topology::{
    now_ms, parse_observed_addr_line, sign_descriptor, CapacityBudget, NodeCapabilities,
    NodeDescriptor, NodeDynamicStatus, PeerCatalog,
};
use crate::transport::{Transport, TransportContext};
use crate::types::{PeerId, SessionId};
use crate::logger;
use crate::metrics::MetricsAggregator;
use crate::peer_score::PeerConnectionPolicy;

const DIAL_RETRY_COOLDOWN_MS: u64 = 30_000;
const PRUNE_REDIAL_COOLDOWN_MS: u64 = 45_000;
const MAINTENANCE_INTERVAL_SECS: u64 = 5;
const MAINTENANCE_START_JITTER_MS: u64 = 3_000;
const REGULAR_AUTO_TARGET_MIN: usize = 4;
const REGULAR_AUTO_TARGET_MAX: usize = 8;
const REGULAR_MAX_HEADROOM: usize = 2;
const REGULAR_BOOTSTRAP_MIN_KEEP: usize = 1;
const REGULAR_BOOTSTRAP_REJOIN_INTERVAL_MS: u64 = 20_000;
const REGULAR_SELF_HEAL_FLOOR: usize = 3;
const REGULAR_EXPLORATION_INTERVAL_MS: u64 = 20_000;
const DIAL_HUB_SOFT_CAP_EXTRA: usize = 2;
const REGULAR_DIAL_ATTEMPT_BUDGET_MAX: usize = 4;
const BOOTSTRAP_DIAL_ATTEMPT_BUDGET_MAX: usize = 8;
const DIAL_ENDPOINT_ATTEMPTS_PER_PEER_MAX: usize = 1;

pub struct NodeRuntime {
    _db: Option<Arc<P2PDatabase>>,
    _options: NodeOptions,
    keypair: NodeKeypair,
    transports: Vec<Arc<dyn Transport>>,
    packet_processor: Arc<dyn PacketProcessor>,
    session_manager: Arc<SessionManager>,
    peer_catalog: Arc<PeerCatalog>,
    dial_book: Arc<DashMap<PeerId, Vec<(String, SocketAddr)>>>,
    descriptor_version: Arc<AtomicU64>,
    router: Option<Arc<Router>>,
    incoming_sessions_tx: Option<mpsc::Sender<Arc<dyn Session>>>,
}

async fn dial_bootstrap_address(
    transports: &[Arc<dyn Transport>],
    router: &Arc<Router>,
    incoming_packets_tx: &mpsc::Sender<IncomingPacket>,
    our_peer_id: &str,
    target: &BootstrapNode,
) {
    for transport in transports {
        if !transport.is_listener() {
            continue;
        }
        if !target.protocols.is_empty()
            && !target
                .protocols
                .iter()
                .any(|p| p.eq_ignore_ascii_case(transport.name()))
        {
            continue;
        }
        match transport.dial(target.addr).await {
            Ok(session) => {
                crate::info!(
                    "[NodeRuntime] Connected to default node {} via {}",
                    target.addr,
                    transport.name()
                );
                let session_id = SessionId::from(session.id().to_string());
                router.register_session_only(session_id.clone(), session.clone());
                session.spawn_reader(incoming_packets_tx.clone());
                let handshake = Packet {
                    signature: None,
                    data: vec![],
                    nodes: vec![],
                    sender: our_peer_id.to_string(),
                    receiver: String::new(),
                    max_hops: 8,
                    chunk_stream_id: None,
                    chunk_index: None,
                    total_chunks: None,
                };
                if let Err(e) = router.send_to_session(session_id, handshake).await {
                    crate::error!("[NodeRuntime] Failed to send handshake to {}: {}", target.addr, e);
                }
                break;
            }
            Err(e) => {
                crate::error!(
                    "[NodeRuntime] Failed to dial {} via {}: {}",
                    target.addr,
                    transport.name(),
                    e
                );
            }
        }
    }
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
        let packet_processor = packet_processor.unwrap_or_else(|| {
            Arc::new(DefaultPacketProcessor::new(
                keypair.peer_id().to_string(),
                options.allow_unsigned_packets,
                peer_catalog.clone(),
                options.peer_discovery_random_fraction,
            )) as Arc<dyn PacketProcessor>
        });
        let peer_scores = Arc::new(PeerScoreStore::new());
        let session_manager = Arc::new(SessionManager::new(
            peer_scores,
            options.peer_score_weights.clone(),
        ));
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
            },
            keypair,
            transports: vec![],
            packet_processor,
            session_manager,
            peer_catalog,
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

        let handshake = Packet {
            signature: None,
            data: vec![],
            nodes: vec![],
            sender: self.keypair.peer_id().to_string(),
            receiver: String::new(),
            max_hops: 8,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };
        router.send_to_session(session_id.clone(), handshake).await?;

        Ok(session_id)
    }

    pub async fn send(&self, peer_id: PeerId, data: Vec<u8>) -> Result<()> {
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
            receiver: peer_id.as_str().to_string(),
            max_hops: 8,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };

        router.send_to_peer(peer_id, packet, None).await
    }

    pub async fn send_to_session(&self, session_id: SessionId, data: Vec<u8>) -> Result<()> {
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
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };
        router.send_to_session(session_id, packet).await
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

    pub fn peer_connection_policy(&self) -> &PeerConnectionPolicy {
        &self._options.peer_connection_policy
    }

    pub fn effective_peer_connection_policy(&self) -> PeerConnectionPolicy {
        self._options.effective_peer_connection_policy()
    }

    pub fn node_role(&self) -> NodeRole {
        self._options.node_role
    }

    pub fn active_peer_count(&self) -> usize {
        self.session_manager.distinct_peer_count()
    }

    pub fn peer_score_weights(&self) -> &PeerScoreWeights {
        &self._options.peer_score_weights
    }

    pub async fn start(&mut self) -> Result<()> {
        let (incoming_sessions_tx, mut incoming_sessions_rx) =
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
        let flow_trace_enabled = std::env::var("LP2LN_TRACE_FLOW")
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                matches!(v.as_str(), "1" | "true" | "yes" | "on")
            })
            .unwrap_or(false);
        let node_role_for_trace = self._options.node_role;
        let our_peer_for_trace = self.keypair.peer_id().to_string();
        if flow_trace_enabled && !matches!(node_role_for_trace, NodeRole::Regular) {
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
                                        };
                                        tag.to_string()
                                    } else {
                                        "data:opaque".to_string()
                                    };
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
        let incoming_policy = self._options.effective_peer_connection_policy().normalized();
        let incoming_catalog = self.peer_catalog.clone();
        let incoming_peer_store = self.session_manager.peer_score_store();
        let incoming_weights = self._options.peer_score_weights.clone();
        let incoming_node_role = self._options.node_role;
        let incoming_discovery_random_fraction = self._options.peer_discovery_random_fraction;
        tokio::spawn(async move {
            let mut last_rotation_ms = 0u64;
            while let Some(session) = incoming_sessions_rx.recv().await {
                crate::session!(
                    "[NodeRuntime] New session: {} (kind: {:?})",
                    session.id(),
                    session.kind()
                );

                let session_id = SessionId::from(session.id().to_string());
                if let Some(peer_id) = session.peer_id() {
                    let pid = PeerId::from(peer_id.to_string());
                    let already_connected = session_manager.is_connected_to_peer(&pid);
                    // Keep at most one session per peer to reduce duplicate links/churn.
                    if already_connected {
                        crate::debug!(
                            "[NodeRuntime] Reject duplicate incoming session from {}",
                            pid
                        );
                        send_discovery_redirect_and_close(
                            &router_for_incoming,
                            session.clone(),
                            &session_id,
                            &pid,
                            &our_peer_id_for_incoming,
                            incoming_catalog.as_ref(),
                            incoming_discovery_random_fraction,
                        )
                        .await;
                        continue;
                    }

                    let connected_now = session_manager.distinct_peer_count();
                    let hard_limit = if matches!(incoming_node_role, NodeRole::BootstrapJoin) {
                        incoming_policy
                            .max_active_peers
                            .saturating_add(BOOTSTRAP_INCOMING_HEADROOM)
                    } else {
                        incoming_policy.max_active_peers
                    };
                    if connected_now >= hard_limit {
                        crate::debug!(
                            "[NodeRuntime] Redirect incoming session from {}: hard peer limit reached ({})",
                            pid,
                            hard_limit
                        );
                        send_discovery_redirect_and_close(
                            &router_for_incoming,
                            session.clone(),
                            &session_id,
                            &pid,
                            &our_peer_id_for_incoming,
                            incoming_catalog.as_ref(),
                            incoming_discovery_random_fraction,
                        )
                        .await;
                        continue;
                    }

                    if connected_now >= incoming_policy.max_active_peers {
                        if matches!(incoming_node_role, NodeRole::BootstrapJoin) {
                            crate::debug!(
                                "[NodeRuntime] Redirect incoming session from {}: bootstrap soft limit reached ({})",
                                pid,
                                incoming_policy.max_active_peers
                            );
                            send_discovery_redirect_and_close(
                                &router_for_incoming,
                                session.clone(),
                                &session_id,
                                &pid,
                                &our_peer_id_for_incoming,
                                incoming_catalog.as_ref(),
                                incoming_discovery_random_fraction,
                            )
                            .await;
                            continue;
                        }
                        let now = now_ms();
                        if now.saturating_sub(last_rotation_ms) < INCOMING_ROTATION_INTERVAL_MS {
                            crate::debug!(
                                "[NodeRuntime] Redirect incoming session from {}: rotation cooldown",
                                pid
                            );
                            send_discovery_redirect_and_close(
                                &router_for_incoming,
                                session.clone(),
                                &session_id,
                                &pid,
                                &our_peer_id_for_incoming,
                                incoming_catalog.as_ref(),
                                incoming_discovery_random_fraction,
                            )
                            .await;
                            continue;
                        }
                        let connected = session_manager.get_all_peers();
                        let mut to_drop = peers_to_drop_when_overloaded(
                            connected,
                            1,
                            incoming_catalog.as_ref(),
                            incoming_peer_store.as_ref(),
                            &incoming_weights,
                            incoming_node_role,
                        );
                        if let Some(victim) = to_drop.pop() {
                            incoming_catalog.observe_failure(&victim);
                            let _ = session_manager.close_all_sessions_for_peer(&victim).await;
                            last_rotation_ms = now;
                            crate::debug!(
                                "[NodeRuntime] Rotated peer {} to admit newcomer {}",
                                victim,
                                pid
                            );
                        } else {
                            crate::debug!(
                                "[NodeRuntime] Redirect incoming session from {}: no rotation candidate",
                                pid
                            );
                            send_discovery_redirect_and_close(
                                &router_for_incoming,
                                session.clone(),
                                &session_id,
                                &pid,
                                &our_peer_id_for_incoming,
                                incoming_catalog.as_ref(),
                                incoming_discovery_random_fraction,
                            )
                            .await;
                            continue;
                        }
                    }
                    session_manager.register(pid, session_id.clone(), session.clone());
                } else {
                    session_manager.register_session(session_id.clone(), session.clone());
                }

                session
                    .clone()
                    .spawn_reader(incoming_packets_tx_for_sessions.clone());

                if session.peer_id().is_some() {
                    let peer_id_str = session.peer_id().unwrap().to_string();
                    let ack = Packet {
                        signature: None,
                        data: b"hs_ack".to_vec(),
                        nodes: vec![],
                        sender: our_peer_id_for_incoming.clone(),
                        receiver: peer_id_str,
                        max_hops: 1,
                        chunk_stream_id: None,
                        chunk_index: None,
                        total_chunks: None,
                    };
                    if let Err(e) = router_for_incoming.send_to_session(session_id, ack).await {
                        let msg = e.to_string();
                        if msg.contains("not found") {
                            crate::debug!(
                                "[NodeRuntime] handshake ack skipped (session already closed): {}",
                                msg
                            );
                        } else {
                            crate::error!(
                                "[NodeRuntime] Failed to send handshake ack to incoming session: {}",
                                e
                            );
                        }
                    }
                }
            }
        });

        let peer_scores_for_order = self.session_manager.peer_score_store();
        let bootstrap_targets = ordered_bootstrap_targets(&self._options, peer_scores_for_order.as_ref());
        let bootstrap_targets_maint = bootstrap_targets.clone();
        let advertise_fallback_ip =
            detect_lan_advertise_ip(&bootstrap_targets_maint, &self._options.default_nodes);
        let transports = self.transports.clone();
        let router_outgoing = router.clone();
        let incoming_packets_tx_outgoing = router.incoming_sender();
        let our_peer_id = self.keypair.peer_id().to_string();
        tokio::spawn(async move {
            for target in bootstrap_targets {
                dial_bootstrap_address(
                    &transports,
                    &router_outgoing,
                    &incoming_packets_tx_outgoing,
                    &our_peer_id,
                    &target,
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

        let policy = self._options.effective_peer_connection_policy().normalized();
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
        let descriptor_ttl_secs = 120u64;
        let descriptor_interval = Duration::from_secs(30);
        let mut last_publish = now_ms().saturating_sub(descriptor_interval.as_millis() as u64);
        let signing_key = self.keypair.signing_key().clone();
        let log_peer_scores = self._options.log_peer_score_snapshot;

        tokio::spawn(async move {
            let initial_jitter =
                (our_peer_maint.bytes().fold(0u64, |acc, b| acc.wrapping_add(b as u64))
                    % MAINTENANCE_START_JITTER_MS)
                    + 1;
            tokio::time::sleep(Duration::from_millis(initial_jitter)).await;
            let mut interval = tokio::time::interval(Duration::from_secs(MAINTENANCE_INTERVAL_SECS));
            let mut dial_cooldown_until: HashMap<PeerId, u64> = HashMap::new();
            let mut last_bootstrap_reseed_ms = 0u64;
            let mut last_exploration_ms = 0u64;
            loop {
                interval.tick().await;
                catalog.decay(Duration::from_secs(180));
                catalog.cleanup_expired();
                for (pid, score) in catalog.recalc_scores(&weights) {
                    peer_store.insert(pid, score);
                }
                if let Some(ref db) = db {
                    let snap = peer_store.snapshot();
                    if let Err(e) = db.save_peer_score_snapshot(&snap) {
                        crate::warn!(
                            "[NodeRuntime] persist peer_scores failed: {}",
                            e
                        );
                    }
                }
                if log_peer_scores && crate::logger::is_debug_enabled() {
                    let mut rows: Vec<(PeerId, PeerScore)> = peer_store.snapshot();
                    rows.sort_by(|a, b| {
                        let ta = total_score(&a.1, &weights);
                        let tb = total_score(&b.1, &weights);
                        tb.partial_cmp(&ta).unwrap_or(std::cmp::Ordering::Equal)
                    });
                    let summary = rows
                        .iter()
                        .take(16)
                        .map(|(p, s)| {
                            format!(
                                "{}:{:.2}(lat={}ms,ok={:.2})",
                                p.as_str(),
                                total_score(s, &weights),
                                s.latency_ms,
                                s.success_rate
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    if !summary.is_empty() {
                        crate::debug!("[NodeRuntime] peer-scores: {}", summary);
                    }
                }
                let our_listen_addrs: HashSet<SocketAddr> =
                    listens.iter().map(|r| *r.value()).collect();
                for desc in catalog.descriptors() {
                    if desc.peer_id == our_peer_maint {
                        continue;
                    }
                    for addr_s in &desc.observed_addrs {
                        let Some((proto, addr)) = parse_observed_addr_line(addr_s) else {
                            continue;
                        };
                        if addr.ip().is_unspecified() {
                            continue;
                        }
                        if our_listen_addrs.contains(&addr) {
                            continue;
                        }
                        if proto != "tcp" {
                            continue;
                        }
                        let mut entry = dial_book
                            .entry(PeerId::from(desc.peer_id.as_str()))
                            .or_default();
                        let exists = entry
                            .iter()
                            .any(|(t, a)| t == "tcp" && a == &addr);
                        if !exists {
                            entry.push(("tcp".to_string(), addr));
                        }
                    }
                }
                let metrics = MetricsAggregator::aggregate(sm.as_ref(), policy.max_active_peers.max(8));
                let mut n = metrics.node.active_peers as usize;
                let budget = CapacityBudget {
                    active_sessions: metrics.node.active_connections as usize,
                    max_sessions: policy.max_active_peers.max(8),
                    hard_ceiling_connections: policy.max_active_peers.max(16) * 4,
                    cpu_load: metrics.node.cpu_load_estimate,
                    memory_pressure: metrics.node.memory_pressure_estimate,
                    ..CapacityBudget::default()
                };
                let adaptive = budget.recommend_policy(&policy);
                let now = now_ms();
                let known_peers = catalog.known_peer_ids().len().max(1);
                let auto_target_regular = ((known_peers as f32).sqrt().round() as usize)
                    .clamp(REGULAR_AUTO_TARGET_MIN, REGULAR_AUTO_TARGET_MAX);
                if n > adaptive.max_active_peers {
                    let drop_n = n.saturating_sub(adaptive.max_active_peers);
                    let connected = router_maint.connected_peers();
                    let to_drop = peers_to_drop_when_overloaded(
                        connected,
                        drop_n,
                        catalog.as_ref(),
                        peer_store.as_ref(),
                        &weights,
                        node_role,
                    );
                    for pid in to_drop {
                        catalog.observe_failure(&pid);
                        dial_cooldown_until
                            .insert(pid.clone(), now.saturating_add(PRUNE_REDIAL_COOLDOWN_MS));
                        let _ = sm.close_all_sessions_for_peer(&pid).await;
                    }
                    n = sm.distinct_peer_count();
                }
                let mut desired = adaptive
                    .target_active_peers
                    .max(adaptive.min_active_peers)
                    .min(adaptive.max_active_peers);
                if matches!(node_role, NodeRole::Regular) {
                    desired = desired.min(auto_target_regular);
                }
                let reserve_slots = dial_reserve_slots(node_role);
                let dial_target = desired
                    .saturating_sub(reserve_slots)
                    .max(adaptive.min_active_peers);
                let connected_bootstrap_now = router_maint
                    .connected_peers()
                    .into_iter()
                    .filter(|p| catalog.peer_is_bootstrap_entry(p))
                    .count();
                let low_connectivity_reseed = should_reseed_bootstrap(
                    n,
                    adaptive.min_active_peers,
                    connected_bootstrap_now,
                    now,
                    last_bootstrap_reseed_ms,
                );
                let missing_bootstrap_bridge = matches!(node_role, NodeRole::Regular)
                    && connected_bootstrap_now == 0
                    && n >= adaptive.min_active_peers
                    && now.saturating_sub(last_bootstrap_reseed_ms)
                        >= REGULAR_BOOTSTRAP_REJOIN_INTERVAL_MS;
                if !bootstrap_targets_maint.is_empty() && (low_connectivity_reseed || missing_bootstrap_bridge)
                {
                    crate::debug!(
                        "[NodeRuntime] bootstrap reseed: active={} min={} boot-connected={} targets={} reason={}",
                        n,
                        adaptive.min_active_peers,
                        connected_bootstrap_now,
                        bootstrap_targets_maint.len(),
                        if low_connectivity_reseed {
                            "low-connectivity"
                        } else {
                            "bridge-rejoin"
                        }
                    );
                    let max_reseed_targets = if low_connectivity_reseed {
                        bootstrap_targets_maint.len()
                    } else {
                        1
                    };
                    for target in bootstrap_targets_maint.iter().take(max_reseed_targets) {
                        dial_bootstrap_address(
                            &transports_maint,
                            &router_maint,
                            &incoming_maint,
                            &our_peer_maint,
                            target,
                        )
                        .await;
                    }
                    last_bootstrap_reseed_ms = now;
                    n = sm.distinct_peer_count();
                }
                let mut max_allowed = adaptive.max_active_peers;
                if matches!(node_role, NodeRole::Regular) {
                    max_allowed = max_allowed.min(desired.saturating_add(REGULAR_MAX_HEADROOM));
                }
                if n > max_allowed {
                    let drop_n = n.saturating_sub(max_allowed);
                    let connected = router_maint.connected_peers();
                    let to_drop = peers_to_drop_when_overloaded(
                        connected,
                        drop_n,
                        catalog.as_ref(),
                        peer_store.as_ref(),
                        &weights,
                        node_role,
                    );
                    for pid in to_drop {
                        catalog.observe_failure(&pid);
                        dial_cooldown_until
                            .insert(pid.clone(), now.saturating_add(PRUNE_REDIAL_COOLDOWN_MS));
                        let _ = sm.close_all_sessions_for_peer(&pid).await;
                    }
                    n = sm.distinct_peer_count();
                }
                if matches!(node_role, NodeRole::Regular) && n > desired.saturating_add(2) {
                    let drop_n = n.saturating_sub(desired);
                    let connected = router_maint.connected_peers();
                    let to_drop = peers_to_drop_when_overloaded(
                        connected,
                        drop_n,
                        catalog.as_ref(),
                        peer_store.as_ref(),
                        &weights,
                        node_role,
                    );
                    if !to_drop.is_empty() {
                        crate::info!(
                            "[NodeRuntime] pruning {} peer(s) to stay near desired={} (current={})",
                            to_drop.len(),
                            desired,
                            n
                        );
                    }
                    for pid in to_drop {
                        catalog.observe_failure(&pid);
                        dial_cooldown_until
                            .insert(pid.clone(), now.saturating_add(PRUNE_REDIAL_COOLDOWN_MS));
                        let _ = sm.close_all_sessions_for_peer(&pid).await;
                    }
                    n = sm.distinct_peer_count();
                }
                let should_explore = matches!(node_role, NodeRole::Regular)
                    && n >= dial_target
                    && n < adaptive.max_active_peers
                    && now.saturating_sub(last_exploration_ms) >= REGULAR_EXPLORATION_INTERVAL_MS;
                if n < dial_target || should_explore {
                    let req = NetworkControlPayload::RequestPeers { limit: 32 };
                    if let Ok(data) = req.encode() {
                        for p in router_maint.connected_peers() {
                            let packet = Packet {
                                signature: None,
                                data: data.clone(),
                                nodes: vec![],
                                sender: our_peer_maint.clone(),
                                receiver: p.as_str().to_string(),
                                max_hops: 2,
                                chunk_stream_id: None,
                                chunk_index: None,
                                total_chunks: None,
                            };
                            let _ = router_maint.send_to_peer(p, packet, None).await;
                        }
                    }
                    let mut candidates: Vec<PeerId> = dial_book.iter().map(|r| r.key().clone()).collect();
                    let desc_by_peer: HashMap<PeerId, NodeDescriptor> = catalog
                        .descriptors()
                        .into_iter()
                        .map(|d| (PeerId::from(d.peer_id.as_str()), d))
                        .collect();
                    let mut connected_bootstrap = router_maint
                        .connected_peers()
                        .into_iter()
                        .filter(|p| catalog.peer_is_bootstrap_entry(p))
                        .count();
                    let bootstrap_quota = bootstrap_dial_quota(node_role);
                    rank_dial_candidates(
                        &mut candidates,
                        peer_store.as_ref(),
                        &weights,
                        &desc_by_peer,
                        &our_peer_maint,
                        node_role,
                        dial_target,
                        connected_bootstrap,
                        bootstrap_quota,
                    );
                    let dial_limit = if should_explore && n >= dial_target {
                        n.saturating_add(1)
                    } else {
                        dial_target
                    };
                    let dial_deficit = dial_limit.saturating_sub(n).max(1);
                    let mut dial_attempts_left = if matches!(node_role, NodeRole::Regular) {
                        dial_deficit.min(REGULAR_DIAL_ATTEMPT_BUDGET_MAX)
                    } else {
                        dial_deficit.min(BOOTSTRAP_DIAL_ATTEMPT_BUDGET_MAX)
                    };
                    let mut dialed_any = false;
                    for pid in candidates {
                        if n >= dial_limit {
                            break;
                        }
                        if dial_attempts_left == 0 {
                            break;
                        }
                        if pid.as_str() == our_peer_maint.as_str() {
                            continue;
                        }
                        if sm.is_connected_to_peer(&pid) {
                            continue;
                        }
                        if let Some(until) = dial_cooldown_until.get(&pid).copied() {
                            if now < until {
                                continue;
                            }
                        }
                        if let Some(desc) = desc_by_peer.get(&pid) {
                            if should_skip_for_bootstrap_quota(
                                desc,
                                node_role,
                                connected_bootstrap,
                                bootstrap_quota,
                                n,
                                adaptive.min_active_peers,
                            ) {
                                // Keep bootstrap links bounded when we already have minimum connectivity.
                                continue;
                            }
                            if !desc.capabilities.bootstrap_entry {
                                // Avoid global hubs while still allowing aggressive self-heal in low-connectivity mode.
                                if n >= REGULAR_SELF_HEAL_FLOOR
                                    && !desc.dynamic_status.accepts_new_sessions
                                {
                                    continue;
                                }
                                let cap = desc.capabilities.base_session_limit.max(1) as usize;
                                if n >= REGULAR_SELF_HEAL_FLOOR
                                    && desc.dynamic_status.active_connections as usize >= cap
                                {
                                    continue;
                                }
                                let soft_cap = dial_target.saturating_add(DIAL_HUB_SOFT_CAP_EXTRA);
                                if desc.dynamic_status.active_connections as usize > soft_cap {
                                    continue;
                                }
                            }
                        }
                        let Some(entry) = dial_book.get(&pid) else {
                            continue;
                        };
                        let mut tried_endpoints: HashSet<(String, SocketAddr)> = HashSet::new();
                        let mut endpoint_attempts = 0usize;
                        for (transport_name, addr) in entry.value().iter() {
                            if endpoint_attempts >= DIAL_ENDPOINT_ATTEMPTS_PER_PEER_MAX {
                                break;
                            }
                            if !tried_endpoints.insert((transport_name.clone(), *addr)) {
                                continue;
                            }
                            if let Some(t) = transports_maint
                                .iter()
                                .find(|t| t.name() == transport_name.as_str())
                            {
                                if !t.is_listener() {
                                    continue;
                                }
                                endpoint_attempts = endpoint_attempts.saturating_add(1);
                                dial_attempts_left = dial_attempts_left.saturating_sub(1);
                                match t.dial(*addr).await {
                                    Ok(session) => {
                                        let session_id = SessionId::from(session.id().to_string());
                                        router_maint.register_session(
                                            pid.clone(),
                                            session_id.clone(),
                                            session.clone(),
                                        );
                                        session.spawn_reader(incoming_maint.clone());
                                        let handshake = Packet {
                                            signature: None,
                                            data: vec![],
                                            nodes: vec![],
                                            sender: our_peer_maint.clone(),
                                            receiver: String::new(),
                                            max_hops: 8,
                                            chunk_stream_id: None,
                                            chunk_index: None,
                                            total_chunks: None,
                                        };
                                        let _ = router_maint
                                            .send_to_session(session_id, handshake)
                                            .await;
                                        catalog.observe_success(&pid, 80);
                                        if desc_by_peer
                                            .get(&pid)
                                            .is_some_and(|d| d.capabilities.bootstrap_entry)
                                        {
                                            connected_bootstrap = connected_bootstrap.saturating_add(1);
                                        }
                                        dial_cooldown_until.remove(&pid);
                                        dialed_any = true;
                                        n = sm.distinct_peer_count();
                                        break;
                                    }
                                    Err(_) => {
                                        catalog.observe_failure(&pid);
                                        dial_cooldown_until.insert(
                                            pid.clone(),
                                            now.saturating_add(DIAL_RETRY_COOLDOWN_MS),
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if should_explore && dialed_any {
                        last_exploration_ms = now;
                    }
                }
                if matches!(node_role, NodeRole::Regular) {
                    let min_keep = adaptive.min_active_peers;
                    let desired_keep = desired;
                    let connected = router_maint.connected_peers();
                    let non_boot = connected
                        .iter()
                        .filter(|p| !catalog.peer_is_bootstrap_entry(p))
                        .count();
                    if non_boot >= desired_keep {
                        let mut boot_peers: Vec<_> = connected
                            .into_iter()
                            .filter(|p| catalog.peer_is_bootstrap_entry(&p))
                            .collect();
                        let connected_bootstrap = boot_peers.len();
                        if connected_bootstrap > REGULAR_BOOTSTRAP_MIN_KEEP {
                            boot_peers.sort_by(|a, b| {
                                let ta = total_score(&peer_store.get(a), &weights);
                                let tb = total_score(&peer_store.get(b), &weights);
                                ta.partial_cmp(&tb)
                                    .unwrap_or(std::cmp::Ordering::Equal)
                            });
                            let max_bootstrap_drop =
                                connected_bootstrap.saturating_sub(REGULAR_BOOTSTRAP_MIN_KEEP);
                            let drop_n = n.saturating_sub(desired_keep).min(max_bootstrap_drop);
                            if drop_n > 0 {
                                crate::info!(
                                    "[NodeRuntime] shedding {} bootstrap_entry peer(s); {} non-bootstrap neighbor(s) (min_keep={}, desired={}, bootstrap_keep={})",
                                    drop_n,
                                    non_boot,
                                    min_keep,
                                    desired_keep,
                                    REGULAR_BOOTSTRAP_MIN_KEEP
                                );
                            }
                            for pid in boot_peers.into_iter().take(drop_n) {
                                catalog.observe_failure(&pid);
                                let _ = sm.close_all_sessions_for_peer(&pid).await;
                            }
                        }
                    }
                }
                n = sm.distinct_peer_count();
                let now = now_ms();
                if now.saturating_sub(last_publish) >= descriptor_interval.as_millis() as u64 {
                    let version = descriptor_ver.fetch_add(1, Ordering::Relaxed) + 1;
                    let mut proto_list: Vec<(String, SocketAddr)> = listens
                        .iter()
                        .map(|r| {
                            let proto = r.key().clone();
                            let advertised = advertised_addr_for_protocol(
                                &proto,
                                *r.value(),
                                &advertise_addrs,
                                advertise_fallback_ip,
                            );
                            (proto, advertised)
                        })
                        .collect();
                    proto_list.sort_by(|a, b| a.0.cmp(&b.0));
                    let observed_addrs: Vec<String> = proto_list
                        .into_iter()
                        .map(|(p, a)| format!("{}:{}", p.to_lowercase(), a))
                        .collect();
                    let mut caps = NodeCapabilities::default();
                    if matches!(node_role, NodeRole::BootstrapJoin) {
                        caps.bootstrap_entry = true;
                    }
                    let descriptor = NodeDescriptor::new_unsigned(
                        our_peer_maint.clone(),
                        caps,
                        {
                            let mut s = NodeDynamicStatus::from(&metrics.node);
                            s.accepts_new_sessions = n < adaptive.max_active_peers;
                            s
                        },
                        observed_addrs,
                        descriptor_ttl_secs,
                        version,
                    );
                    let mut descriptor = descriptor;
                    if sign_descriptor(&mut descriptor, &signing_key).is_ok() {
                        let _ = catalog.upsert_descriptor(descriptor.clone());
                        if let Some(db) = db.as_ref() {
                            let _ = db.upsert_peer_descriptor(&descriptor);
                        }
                        let msg = NetworkControlPayload::AnnounceNodeDescriptor { descriptor };
                        if let Ok(data) = msg.encode() {
                            for p in router_maint.connected_peers() {
                                let packet = Packet {
                                    signature: None,
                                    data: data.clone(),
                                    nodes: vec![],
                                    sender: our_peer_maint.clone(),
                                    receiver: p.as_str().to_string(),
                                    max_hops: 2,
                                    chunk_stream_id: None,
                                    chunk_index: None,
                                    total_chunks: None,
                                };
                                let _ = router_maint.send_to_peer(p, packet, None).await;
                            }
                        }
                    }
                    last_publish = now;
                }
            }
        });

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
