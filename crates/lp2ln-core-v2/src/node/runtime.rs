use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use futures::FutureExt;
use rand::Rng;
use tokio::sync::mpsc;

use crate::crypto::NodeKeypair;
use crate::db::P2PDatabase;
use crate::logger;
use crate::nat::NatTraversalState;
use crate::node::addressing::{detect_lan_advertise_ip, ordered_bootstrap_targets};
use crate::node::direct_upgrade::{
    CoreDirectDialer, DirectUpgradeContext, DirectUpgradeRouterSink, TrafficDemandTracker,
    nat_trigger_from_parts, run_direct_upgrade_loop,
};
use crate::node::flow_trace::FlowTraceService;
use crate::node::incoming_sessions::run_incoming_session_handler;
use crate::node::options::{NodeOptions, NodeRole};
use crate::node::supervisor::NodeSupervisor;
use crate::node::topology_maintenance::{
    BootstrapDialDedupe, dial_bootstrap_address, run_topology_maintenance_loop,
};
use crate::packet::Packet;
use crate::packet_processor::{DefaultPacketProcessor, PacketProcessor};
use crate::peer_score::PeerConnectionPolicy;
use crate::peer_score::{PeerScoreStore, PeerScoreWeights};
use crate::protocol::control::{NatCandidate, NatCandidateKind, NetworkControlPayload};
use crate::protocol::handshake;
use crate::router::{ROUTER_INCOMING_QUEUE_CAP, Router};
use crate::sessions::manager::SessionManager;
use crate::sessions::session::IncomingPacket;
use crate::sessions::{LinkKind, Session, SessionMetrics};
use crate::topology::PeerCatalog;
use crate::transport::{Transport, TransportContext};
use crate::types::{PeerId, SessionId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeLifecycleState {
    Created,
    Running,
    Stopping,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeLifecycleError {
    AlreadyStarted,
    RestartNotSupported,
}

impl std::fmt::Display for NodeLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyStarted => write!(f, "node is already running"),
            Self::RestartNotSupported => {
                write!(f, "node restart is not supported; build a new NodeRuntime")
            }
        }
    }
}

impl std::error::Error for NodeLifecycleError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    Normal,
    Degraded,
}

#[derive(Debug, Clone)]
pub struct RuntimeHealthSnapshot {
    pub mode: RuntimeMode,
    pub router_restarts: u64,
    pub transport_restarts: u64,
    pub incoming_restarts: u64,
    pub topology_restarts: u64,
    pub last_error: Option<String>,
}

#[derive(Default)]
struct RuntimeHealthState {
    router_restarts: AtomicU64,
    transport_restarts: AtomicU64,
    incoming_restarts: AtomicU64,
    topology_restarts: AtomicU64,
    degraded: AtomicBool,
    last_error: RwLock<Option<String>>,
}

impl RuntimeHealthState {
    fn record_error(&self, subsystem: &str, err: impl Into<String>) {
        let msg = format!("[{}] {}", subsystem, err.into());
        if let Ok(mut w) = self.last_error.write() {
            *w = Some(msg.clone());
        }
        self.degraded.store(true, Ordering::Relaxed);
        crate::warn!("[NodeRuntime] subsystem degraded: {}", msg);
    }

    fn mark_healthy(&self) {
        self.degraded.store(false, Ordering::Relaxed);
        if let Ok(mut w) = self.last_error.write() {
            *w = None;
        }
    }

    fn snapshot(&self) -> RuntimeHealthSnapshot {
        let mode = if self.degraded.load(Ordering::Relaxed) {
            RuntimeMode::Degraded
        } else {
            RuntimeMode::Normal
        };
        let last_error = self.last_error.read().ok().and_then(|v| v.clone());
        RuntimeHealthSnapshot {
            mode,
            router_restarts: self.router_restarts.load(Ordering::Relaxed),
            transport_restarts: self.transport_restarts.load(Ordering::Relaxed),
            incoming_restarts: self.incoming_restarts.load(Ordering::Relaxed),
            topology_restarts: self.topology_restarts.load(Ordering::Relaxed),
            last_error,
        }
    }
}

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
    bootstrap_dial_dedupe: Arc<Mutex<HashSet<(String, SocketAddr)>>>,
    bootstrap_dial_ok_ms: Arc<Mutex<HashMap<SocketAddr, u64>>>,
    descriptor_version: Arc<AtomicU64>,
    router: Option<Arc<Router>>,
    incoming_sessions_tx: Mutex<Option<mpsc::Sender<Arc<dyn Session>>>>,
    lifecycle: Mutex<NodeLifecycleState>,
    supervisor: Mutex<Option<NodeSupervisor>>,
    // Child token of the supervisor root token; cancelled first during
    // shutdown to stop producer services (accept/dial/maintenance) before
    // sessions are drained and the router ingress is closed.
    producer_cancel: Mutex<Option<tokio_util::sync::CancellationToken>>,
    health: Arc<RuntimeHealthState>,
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
            .or_else(|| {
                db.as_ref()
                    .and_then(|db| db.get_or_create_node_keypair().ok())
            })
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
                ipc_tcp: options.ipc_tcp,
                direct_upgrade: options.direct_upgrade,
            },
            peer_connection_policy_live: Arc::new(RwLock::new(peer_policy_init)),
            keypair,
            transports: vec![],
            packet_processor,
            session_manager,
            peer_catalog,
            nat_state,
            dial_book: Arc::new(DashMap::new()),
            bootstrap_dial_dedupe: Arc::new(Mutex::new(HashSet::new())),
            bootstrap_dial_ok_ms: Arc::new(Mutex::new(HashMap::new())),
            descriptor_version: Arc::new(AtomicU64::new(1)),
            router: None,
            incoming_sessions_tx: Mutex::new(None),
            lifecycle: Mutex::new(NodeLifecycleState::Created),
            supervisor: Mutex::new(None),
            producer_cancel: Mutex::new(None),
            health: Arc::new(RuntimeHealthState::default()),
        }
    }

    #[doc(hidden)]
    pub fn lifecycle_state(&self) -> NodeLifecycleState {
        self.lifecycle
            .lock()
            .map(|state| *state)
            .unwrap_or(NodeLifecycleState::Stopped)
    }

    #[doc(hidden)]
    pub fn lifecycle_active_tasks(&self) -> usize {
        self.supervisor
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(NodeSupervisor::active_task_count))
            .unwrap_or(0)
    }

    #[doc(hidden)]
    pub fn test_close_router_ingress(&self) {
        if let Some(router) = self.router.as_ref() {
            router.close_incoming();
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
        if !entry.iter().any(|(t, a)| t == &transport && a == &addr) {
            entry.push((transport, addr));
        }
    }

    pub async fn dial(&self, transport_name: &str, addr: SocketAddr) -> Result<Arc<dyn Session>> {
        let transport = self
            .transports
            .iter()
            .find(|t| t.name() == transport_name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Transport '{}' is not registered in runtime",
                    transport_name
                )
            })?;

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
        router
            .send_to_session(session_id.clone(), handshake)
            .await?;

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
        self.send_with_options(peer_id, data, None, None, None)
            .await
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
        candidates
            .dedup_by(|a, b| a.protocol == b.protocol && a.addr == b.addr && a.kind == b.kind);
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
            .send_with_options(route_peer_id.clone(), data, receiver, max_hops, nodes)
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

    fn read_policy_lock(&self) -> PeerConnectionPolicy {
        match self.peer_connection_policy_live.read() {
            Ok(g) => g.clone(),
            Err(poison) => {
                self.health
                    .record_error("policy_lock", "peer policy lock poisoned on read");
                poison.into_inner().clone()
            }
        }
    }

    fn write_policy_lock(&self, policy: PeerConnectionPolicy) {
        match self.peer_connection_policy_live.write() {
            Ok(mut g) => *g = policy,
            Err(poison) => {
                self.health
                    .record_error("policy_lock", "peer policy lock poisoned on write");
                let mut g = poison.into_inner();
                *g = policy;
            }
        }
    }

    pub fn peer_connection_policy(&self) -> PeerConnectionPolicy {
        self.read_policy_lock()
    }

    pub fn effective_peer_connection_policy(&self) -> PeerConnectionPolicy {
        let base = self.read_policy_lock();
        NodeOptions::effective_peer_connection_policy_for(base, self._options.node_role)
    }

    pub fn set_peer_connection_policy(&self, policy: PeerConnectionPolicy) -> PeerConnectionPolicy {
        let n = policy.normalized();
        self.write_policy_lock(n.clone());
        n
    }

    pub fn health_snapshot(&self) -> RuntimeHealthSnapshot {
        self.health.snapshot()
    }

    pub fn is_degraded(&self) -> bool {
        self.health.snapshot().mode == RuntimeMode::Degraded
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
        {
            let mut lifecycle = self
                .lifecycle
                .lock()
                .map_err(|_| anyhow::anyhow!("node lifecycle lock poisoned"))?;
            match *lifecycle {
                NodeLifecycleState::Created => {}
                NodeLifecycleState::Running | NodeLifecycleState::Stopping => {
                    return Err(NodeLifecycleError::AlreadyStarted.into());
                }
                NodeLifecycleState::Stopped => {
                    return Err(NodeLifecycleError::RestartNotSupported.into());
                }
            }
            *lifecycle = NodeLifecycleState::Running;
        }

        if self.transports.is_empty() {
            if let Ok(mut lifecycle) = self.lifecycle.lock() {
                *lifecycle = NodeLifecycleState::Created;
            }
            crate::error!("[NodeRuntime] No transports registered");
            return Err(anyhow::anyhow!("No transports registered"));
        }

        let supervisor = NodeSupervisor::new();
        let cancel = supervisor.cancellation();
        // Producer services (accept/dial/maintenance) get a child token so
        // stop() can halt them first, before sessions are drained and the
        // router ingress is closed. Cancelling the root token still cancels
        // producers as a fallback.
        let producer_cancel = cancel.child_token();
        if let Ok(mut guard) = self.producer_cancel.lock() {
            *guard = Some(producer_cancel.clone());
        }

        let (incoming_sessions_tx, incoming_sessions_rx) = mpsc::channel(ROUTER_INCOMING_QUEUE_CAP);
        let signing_key = Some(Arc::new(self.keypair.signing_key().clone()));
        let du_cfg = self._options.direct_upgrade.clone();
        let upgrade_sink = if du_cfg.enabled {
            let (tx, rx) = mpsc::channel(du_cfg.event_queue_cap.max(64));
            Some((DirectUpgradeRouterSink { enabled: true, tx }, rx, du_cfg))
        } else {
            None
        };
        let (router_raw, mut incoming_packets_rx) = Router::new(
            self.session_manager.clone(),
            self.packet_processor.clone(),
            signing_key,
            self.keypair.peer_id(),
            upgrade_sink.as_ref().map(|(sink, _rx, _cfg)| sink.clone()),
        );
        let router = Arc::new(router_raw);
        {
            let router_loop = router.clone();
            let health = self.health.clone();
            let cancel_router = cancel.clone();
            supervisor.spawn("router", async move {
                let mut backoff = Duration::from_millis(500);
                loop {
                    if cancel_router.is_cancelled() {
                        break;
                    }
                    let result = AssertUnwindSafe(
                        router_loop
                            .clone()
                            .run(&mut incoming_packets_rx, cancel_router.clone()),
                    )
                    .catch_unwind()
                    .await;
                    match result {
                        Ok(Ok(_)) => {
                            health.mark_healthy();
                            if router_loop.is_ingress_closed() {
                                // Clean exit during shutdown: ingress is closed,
                                // restarting the loop would spin on an empty queue.
                                break;
                            }
                            backoff = Duration::from_millis(500);
                        }
                        Ok(Err(err)) => {
                            health.router_restarts.fetch_add(1, Ordering::Relaxed);
                            health.record_error("router", err.to_string());
                        }
                        Err(_) => {
                            health.router_restarts.fetch_add(1, Ordering::Relaxed);
                            health.record_error("router", "panic in router loop");
                        }
                    }
                    tokio::select! {
                        _ = cancel_router.cancelled() => break,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(15));
                }
            });
        }
        self.router = Some(router.clone());
        if let Some((_sink, rx, du_cfg)) = upgrade_sink {
            let mut obf_protocols: Vec<String> = self
                ._options
                .transport_obfuscation
                .keys()
                .cloned()
                .collect();
            obf_protocols.sort();
            let listens: HashMap<String, SocketAddr> = self
                ._options
                .listens
                .iter()
                .map(|r| (r.key().clone(), *r.value()))
                .collect();
            let advertise = self._options.advertise_addrs.clone();
            let dialer = Arc::new(CoreDirectDialer {
                router: router.clone(),
                transports: self.transports.clone(),
                keypair: self.keypair.clone(),
                obfuscation_protocols: obf_protocols,
            });
            let nat = if du_cfg.try_nat_traversal {
                Some(nat_trigger_from_parts(
                    router.clone(),
                    self.keypair.clone(),
                    self.transports.clone(),
                    listens.clone(),
                    self.nat_state.clone(),
                ))
            } else {
                None
            };
            let tracker = Arc::new(TrafficDemandTracker::new(du_cfg.max_tracker_peers));
            let cancel_du = producer_cancel.clone();
            let router_du = router.clone();
            let session_manager_du = self.session_manager.clone();
            let peer_catalog_du = self.peer_catalog.clone();
            let dial_book_du = self.dial_book.clone();
            let our_peer_id_du = self.keypair.peer_id().to_string();
            supervisor.spawn("direct_upgrade", async move {
                run_direct_upgrade_loop(
                    rx,
                    DirectUpgradeContext {
                        config: du_cfg,
                        our_peer_id: our_peer_id_du,
                        router: router_du,
                        session_manager: session_manager_du,
                        peer_catalog: peer_catalog_du,
                        dial_book: dial_book_du,
                        listens,
                        advertise,
                        dialer,
                        nat,
                        tracker,
                    },
                    cancel_du,
                )
                .await;
            });
        }
        if FlowTraceService::is_enabled(&self._options.flow_trace) {
            let cancel_trace = cancel.clone();
            let node_role = self._options.node_role;
            let our_peer_id_trace = self.keypair.peer_id().to_string();
            let flow_trace = self._options.flow_trace.clone();
            let router_trace = router.clone();
            supervisor.spawn("flow_trace", async move {
                FlowTraceService::run(
                    &router_trace,
                    node_role,
                    our_peer_id_trace,
                    &flow_trace,
                    cancel_trace,
                )
                .await;
            });
        }

        if let Ok(mut guard) = self.incoming_sessions_tx.lock() {
            *guard = Some(incoming_sessions_tx.clone());
        }
        let ctx = TransportContext {
            incoming_sessions_tx: incoming_sessions_tx.clone(),
            incoming_packets_tx: router.incoming_sender(),
            listen_addr: None,
        };

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
            let health = self.health.clone();
            let cancel_transport = producer_cancel.clone();
            let service_name: &'static str = match transport_name {
                "tcp" => "transport:tcp",
                "udp" => "transport:udp",
                _ => "transport:other",
            };

            supervisor.spawn(service_name, async move {
                let mut backoff = Duration::from_millis(500);
                loop {
                    if cancel_transport.is_cancelled() {
                        break;
                    }
                    let start_result = tokio::select! {
                        _ = cancel_transport.cancelled() => break,
                        result = transport_clone.start(ctx_clone.clone()) => result,
                    };
                    match start_result {
                        Ok(bound) => {
                            let started_addr = bound.or(listen_addr);
                            if let Some(addr) = started_addr {
                                crate::info!(
                                    "[NodeRuntime] Transport {} started on {}",
                                    transport_name,
                                    addr
                                );
                            } else {
                                crate::info!("[NodeRuntime] Transport {} started", transport_name);
                            }
                            health.mark_healthy();
                            break;
                        }
                        Err(e) => {
                            health.transport_restarts.fetch_add(1, Ordering::Relaxed);
                            health.record_error(
                                "transport",
                                format!("{} failed to start: {}", transport_name, e),
                            );
                            if let Some(addr) = listen_addr {
                                crate::warn!(
                                    "[NodeRuntime] restarting transport {} on {} after {:?}",
                                    transport_name,
                                    addr,
                                    backoff
                                );
                            } else {
                                crate::warn!(
                                    "[NodeRuntime] restarting transport {} after {:?}",
                                    transport_name,
                                    backoff
                                );
                            }
                            tokio::select! {
                                _ = cancel_transport.cancelled() => break,
                                _ = tokio::time::sleep(backoff) => {}
                            }
                            backoff = (backoff * 2).min(Duration::from_secs(15));
                        }
                    }
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
        let health_incoming = self.health.clone();
        let cancel_incoming = producer_cancel.clone();
        supervisor.spawn("incoming", async move {
            let mut incoming_sessions_rx = incoming_sessions_rx;
            let mut backoff = Duration::from_millis(500);
            loop {
                if cancel_incoming.is_cancelled() {
                    break;
                }
                let result = tokio::select! {
                    _ = cancel_incoming.cancelled() => break,
                    result = AssertUnwindSafe(run_incoming_session_handler(
                        cancel_incoming.clone(),
                        &mut incoming_sessions_rx,
                        session_manager.clone(),
                        router_for_incoming.clone(),
                        our_peer_id_for_incoming.clone(),
                        policy_live_incoming.clone(),
                        incoming_catalog.clone(),
                        incoming_peer_store.clone(),
                        incoming_weights.clone(),
                        incoming_node_role,
                        incoming_topology_tuning.clone(),
                        incoming_discovery_random_fraction,
                        incoming_packets_tx_for_sessions.clone(),
                    ))
                    .catch_unwind() => result,
                };
                match result {
                    Ok(Ok(_)) => {
                        backoff = Duration::from_millis(500);
                        health_incoming.mark_healthy();
                    }
                    Ok(Err(err)) => {
                        health_incoming
                            .incoming_restarts
                            .fetch_add(1, Ordering::Relaxed);
                        health_incoming.record_error("incoming_loop", err.to_string());
                    }
                    Err(_) => {
                        health_incoming
                            .incoming_restarts
                            .fetch_add(1, Ordering::Relaxed);
                        health_incoming.record_error("incoming_loop", "panic in incoming loop");
                    }
                }
                tokio::select! {
                    _ = cancel_incoming.cancelled() => break,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(15));
            }
        });

        let peer_scores_for_order = self.session_manager.peer_score_store();
        let bootstrap_targets =
            ordered_bootstrap_targets(&self._options, peer_scores_for_order.as_ref());
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
        let bootstrap_dedupe_startup = self.bootstrap_dial_dedupe.clone();
        let bootstrap_ok_startup = self.bootstrap_dial_ok_ms.clone();
        let cancel_bootstrap = producer_cancel.clone();
        supervisor.spawn("bootstrap", async move {
            for target in bootstrap_targets {
                if cancel_bootstrap.is_cancelled() {
                    break;
                }
                let dedupe_ctx = BootstrapDialDedupe {
                    active_peers: 0,
                    set: bootstrap_dedupe_startup.clone(),
                };
                let ts = crate::topology::now_ms();
                tokio::select! {
                    _ = cancel_bootstrap.cancelled() => break,
                    _ = dial_bootstrap_address(
                        &transports,
                        &router_outgoing,
                        &incoming_packets_tx_outgoing,
                        &our_peer_id,
                        &target,
                        &handshake_payload,
                        Some(&dedupe_ctx),
                        Some((&bootstrap_ok_startup, ts)),
                    ) => {}
                }
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
        let nat_state_maint = self.nat_state.clone();
        let bootstrap_dial_dedupe_maint = self.bootstrap_dial_dedupe.clone();
        let bootstrap_dial_ok_maint = self.bootstrap_dial_ok_ms.clone();

        let health_maint = self.health.clone();
        let cancel_topology = producer_cancel.clone();
        supervisor.spawn("topology", async move {
            let mut backoff = Duration::from_millis(500);
            loop {
                if cancel_topology.is_cancelled() {
                    break;
                }
                let result = tokio::select! {
                    _ = cancel_topology.cancelled() => break,
                    result = AssertUnwindSafe(run_topology_maintenance_loop(
                        cancel_topology.clone(),
                        policy_live_maint.clone(),
                        node_role,
                        weights.clone(),
                        sm.clone(),
                        dial_book.clone(),
                        peer_store.clone(),
                        catalog.clone(),
                        db.clone(),
                        listens.clone(),
                        advertise_addrs.clone(),
                        advertise_fallback_ip,
                        transports_maint.clone(),
                        router_maint.clone(),
                        incoming_maint.clone(),
                        our_peer_maint.clone(),
                        descriptor_ver.clone(),
                        signing_key.clone(),
                        log_peer_scores,
                        topology_tuning.clone(),
                        maintenance_handshake_payload.clone(),
                        bootstrap_targets_maint.clone(),
                        nat_state_maint.clone(),
                        bootstrap_dial_dedupe_maint.clone(),
                        bootstrap_dial_ok_maint.clone(),
                    ))
                    .catch_unwind() => result,
                };
                match result {
                    Ok(Ok(_)) => {
                        backoff = Duration::from_millis(500);
                        health_maint.mark_healthy();
                    }
                    Ok(Err(err)) => {
                        health_maint
                            .topology_restarts
                            .fetch_add(1, Ordering::Relaxed);
                        health_maint.record_error("topology_loop", err.to_string());
                    }
                    Err(_) => {
                        health_maint
                            .topology_restarts
                            .fetch_add(1, Ordering::Relaxed);
                        health_maint.record_error("topology_loop", "panic in topology loop");
                    }
                }
                tokio::select! {
                    _ = cancel_topology.cancelled() => break,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(15));
            }
        });

        if let Ok(mut guard) = self.supervisor.lock() {
            *guard = Some(supervisor);
        }

        Ok(())
    }

    /// Phased shutdown:
    /// 1. lifecycle guard (idempotent / concurrent-safe);
    /// 2. cancel producer services (bootstrap, topology dial, direct
    ///    upgrade, transport restart loops, incoming handler) and drop our
    ///    clone of the incoming-sessions sender;
    /// 3. stop transports — sends the shutdown signal and joins the accept
    ///    task, so no new connections appear past this point;
    /// 4. close every registered session by registry ID (covers unbound
    ///    handshake/redirect sessions without a PeerId);
    /// 5. close router ingress — the router loop drains buffered packets
    ///    and exits cleanly;
    /// 6. bounded drain of in-flight per-packet processing tasks;
    /// 7. cancel remaining services (router loop, flow trace) and join all
    ///    supervised handles; hung tasks are aborted after the timeout and
    ///    their handles awaited.
    pub async fn stop(&self) -> Result<()> {
        {
            let mut lifecycle = self
                .lifecycle
                .lock()
                .map_err(|_| anyhow::anyhow!("node lifecycle lock poisoned"))?;
            match *lifecycle {
                NodeLifecycleState::Created | NodeLifecycleState::Stopped => return Ok(()),
                NodeLifecycleState::Stopping => return Ok(()),
                NodeLifecycleState::Running => *lifecycle = NodeLifecycleState::Stopping,
            }
        }

        // Phase 2: stop producers. The general (root) cancellation is NOT
        // triggered here: the router must stay alive to drain its queue.
        let producer_cancel = self
            .producer_cancel
            .lock()
            .ok()
            .and_then(|mut guard| guard.take());
        if let Some(token) = producer_cancel {
            token.cancel();
        }
        if let Ok(mut guard) = self.incoming_sessions_tx.lock() {
            guard.take();
        }

        // Phase 3: no new incoming connections.
        for transport in &self.transports {
            transport.stop().await?;
            crate::info!("[NodeRuntime] Stopped transport: {}", transport.name());
        }

        // Phase 4: close active sessions by full registry, not by peer map,
        // so sessions without a bound PeerId are closed too.
        for session_id in self.session_manager.all_session_ids() {
            let _ = self.session_manager.close_session(&session_id).await;
        }

        // Phases 5–6: close ingress, then bounded drain of packet tasks.
        if let Some(router) = self.router.as_ref() {
            router.close_incoming();
            router.shutdown_packet_tasks(Duration::from_secs(3)).await;
        }

        // Phase 7: cancel remaining services and join everything.
        let supervisor = self
            .supervisor
            .lock()
            .ok()
            .and_then(|mut guard| guard.take());
        if let Some(supervisor) = supervisor {
            supervisor.shutdown().await;
        }

        if let Ok(mut lifecycle) = self.lifecycle.lock() {
            *lifecycle = NodeLifecycleState::Stopped;
        }

        Ok(())
    }
}
