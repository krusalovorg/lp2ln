use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;

use crate::crypto::NodeKeypair;
use crate::crypto::peer_cache::PeerCryptoCache;
use crate::db::P2PDatabase;
use crate::event_core::prelude::{CoreBus, HandlerRegistration};
use crate::logger;
use crate::nat::NatTraversalState;
use crate::node::options::NodeOptions;
use crate::node::runtime::health::{RuntimeHealthState, SharedHealth};
use crate::node::runtime::lifecycle::NodeLifecycleState;
use crate::node::supervisor::NodeSupervisor;
use crate::node::topology_maintenance::SessionRedialQueue;
use crate::packet_processor::{DefaultPacketProcessor, PacketProcessor};
use crate::peer_score::{PeerConnectionPolicy, PeerScoreStore};
use crate::router::Router;
use crate::sessions::Session;
use crate::sessions::manager::SessionManager;
use crate::topology::PeerCatalog;
use crate::transport::Transport;

pub struct NodeRuntime {
    pub(crate) db: Option<Arc<P2PDatabase>>,
    pub(crate) options: NodeOptions,
    pub(crate) peer_connection_policy_live: Arc<RwLock<PeerConnectionPolicy>>,
    pub(crate) keypair: NodeKeypair,
    pub(crate) transports: Vec<Arc<dyn Transport>>,
    pub(crate) packet_processor: Arc<dyn PacketProcessor>,
    pub(crate) session_manager: Arc<SessionManager>,
    pub(crate) peer_catalog: Arc<PeerCatalog>,
    pub(crate) nat_state: Arc<NatTraversalState>,
    pub(crate) dial_book: Arc<DashMap<crate::types::PeerId, Vec<(String, SocketAddr)>>>,
    pub(crate) bootstrap_dial_dedupe: Arc<Mutex<HashSet<(String, SocketAddr)>>>,
    pub(crate) bootstrap_dial_ok_ms: Arc<Mutex<HashMap<SocketAddr, u64>>>,
    pub(crate) descriptor_version: Arc<AtomicU64>,
    pub(crate) peer_crypto_cache: Arc<PeerCryptoCache>,
    pub(crate) router: Option<Arc<Router>>,
    pub(crate) incoming_sessions_tx: Mutex<Option<mpsc::Sender<Arc<dyn Session>>>>,
    pub(crate) lifecycle: Mutex<NodeLifecycleState>,
    pub(crate) supervisor: Mutex<Option<NodeSupervisor>>,
    pub(crate) producer_cancel: Mutex<Option<CancellationToken>>,
    pub(crate) health: SharedHealth,
    pub(crate) core_bus: CoreBus,
    pub(crate) lifecycle_generation: AtomicU64,
    pub(crate) event_handler_regs: Vec<HandlerRegistration>,
    pub(crate) session_redial_queue: Arc<SessionRedialQueue>,
    pub(crate) degradation_stop_tx: Mutex<Option<mpsc::Sender<()>>>,
    pub(crate) stop_notifier: Arc<Notify>,
    pub(crate) stop_on_degradation_armed: AtomicBool,
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
        let peer_crypto_cache = PeerCryptoCache::new();
        let packet_processor = packet_processor.unwrap_or_else(|| {
            Arc::new(DefaultPacketProcessor::new(
                keypair.peer_id().to_string(),
                options.allow_unsigned_packets,
                peer_catalog.clone(),
                options.peer_discovery_random_fraction,
                nat_state.clone(),
                keypair.clone(),
                peer_crypto_cache.clone(),
            )) as Arc<dyn PacketProcessor>
        });
        let peer_scores = Arc::new(PeerScoreStore::new());
        let core_bus = CoreBus::new(options.event_bus_broadcast_cap);
        let session_manager = Arc::new(
            SessionManager::new(peer_scores, options.peer_score_weights.clone())
                .with_join_timeout(Duration::from_secs(options.session_join_timeout_secs))
                .with_event_bus(core_bus.clone()),
        );
        let peer_policy_init = options.peer_connection_policy.normalized();
        let health = Arc::new(RuntimeHealthState::default());
        Self {
            db,
            options: NodeOptions {
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
                quic: options.quic,
                topology_tuning: options.topology_tuning,
                flow_trace: options.flow_trace,
                debug_server: options.debug_server,
                ipc_tcp: options.ipc_tcp,
                direct_upgrade: options.direct_upgrade,
                session_join_timeout_secs: options.session_join_timeout_secs,
                supervisor_shutdown_timeout_secs: options.supervisor_shutdown_timeout_secs,
                router_incoming_queue_cap: options.router_incoming_queue_cap,
                router_broadcast_cap: options.router_broadcast_cap,
                router_process_concurrency: options.router_process_concurrency,
                signature_format: options.signature_format,
                enable_topology_maintenance: options.enable_topology_maintenance,
                event_bus_broadcast_cap: options.event_bus_broadcast_cap,
                stop_on_permanent_degradation: options.stop_on_permanent_degradation,
                topology_react_to_session_events: options.topology_react_to_session_events,
                dial_policy: options.dial_policy,
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
            peer_crypto_cache,
            router: None,
            incoming_sessions_tx: Mutex::new(None),
            lifecycle: Mutex::new(NodeLifecycleState::Created),
            supervisor: Mutex::new(None),
            producer_cancel: Mutex::new(None),
            health,
            core_bus,
            lifecycle_generation: AtomicU64::new(0),
            event_handler_regs: Vec::new(),
            session_redial_queue: Arc::new(SessionRedialQueue::new()),
            degradation_stop_tx: Mutex::new(None),
            stop_notifier: Arc::new(Notify::new()),
            stop_on_degradation_armed: AtomicBool::new(false),
        }
    }

    pub fn core_bus(&self) -> CoreBus {
        self.core_bus.clone()
    }

    pub fn add_transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transports.push(transport);
        self
    }

    pub async fn start(&mut self) -> Result<()> {
        super::startup::run_startup(self).await
    }

    pub async fn stop(&self) -> Result<()> {
        super::shutdown::run_shutdown(self).await
    }

    pub(crate) fn request_degradation_stop(&self) {
        if !self.options.stop_on_permanent_degradation {
            return;
        }
        if self
            .stop_on_degradation_armed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        self.stop_notifier.notify_waiters();
        if let Ok(guard) = self.degradation_stop_tx.lock() {
            if let Some(tx) = guard.as_ref() {
                let _ = tx.try_send(());
            }
        }
        if let Ok(guard) = self.producer_cancel.lock() {
            if let Some(token) = guard.as_ref() {
                token.cancel();
            }
        }
    }
}
