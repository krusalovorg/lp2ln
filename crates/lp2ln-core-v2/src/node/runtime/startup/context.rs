use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::Result;
use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::crypto::NodeKeypair;
use crate::db::P2PDatabase;
use crate::event_core::prelude::{CoreBus, HandlerRegistration};
use crate::nat::NatTraversalState;
use crate::node::options::NodeOptions;
use crate::node::runtime::health::SharedHealth;
use crate::node::runtime::lifecycle::NodeLifecycleState;
use crate::node::supervisor::NodeSupervisor;
use crate::node::topology_maintenance::SessionRedialQueue;
use crate::packet_processor::PacketProcessor;
use crate::peer_score::PeerConnectionPolicy;
use crate::router::Router;
use crate::sessions::Session;
use crate::sessions::manager::SessionManager;
use crate::topology::PeerCatalog;
use crate::transport::Transport;

/// Shared state passed to each runtime service spawner during `start()`.
#[allow(dead_code)]
pub(crate) struct StartupContext<'a> {
    pub supervisor: &'a mut NodeSupervisor,
    pub cancel: CancellationToken,
    pub producer_cancel: CancellationToken,
    pub options: &'a NodeOptions,
    pub db: &'a Option<Arc<P2PDatabase>>,
    pub keypair: &'a NodeKeypair,
    pub transports: &'a [Arc<dyn Transport>],
    pub packet_processor: Arc<dyn PacketProcessor>,
    pub session_manager: Arc<SessionManager>,
    pub peer_catalog: Arc<PeerCatalog>,
    pub nat_state: Arc<NatTraversalState>,
    pub dial_book: Arc<DashMap<crate::types::PeerId, Vec<(String, SocketAddr)>>>,
    pub bootstrap_dial_dedupe: Arc<Mutex<HashSet<(String, SocketAddr)>>>,
    pub bootstrap_dial_ok_ms: Arc<Mutex<HashMap<SocketAddr, u64>>>,
    pub descriptor_version: Arc<AtomicU64>,
    pub peer_connection_policy_live: Arc<RwLock<PeerConnectionPolicy>>,
    pub health: SharedHealth,
    pub core_bus: CoreBus,
    pub lifecycle_generation: u64,
    pub router: Option<Arc<Router>>,
    pub incoming_packets_rx:
        Option<tokio::sync::mpsc::Receiver<crate::sessions::session::IncomingPacket>>,
    pub direct_upgrade_rx:
        Option<tokio::sync::mpsc::Receiver<crate::node::direct_upgrade::DirectUpgradeEvent>>,
    pub incoming_sessions_tx: Option<mpsc::Sender<Arc<dyn Session>>>,
    pub incoming_sessions_rx: Option<mpsc::Receiver<Arc<dyn Session>>>,
    pub session_redial_queue: Arc<SessionRedialQueue>,
    pub event_handler_regs: &'a mut Vec<HandlerRegistration>,
    pub lifecycle: &'a Mutex<NodeLifecycleState>,
    pub bootstrap_targets: Option<Vec<crate::node::options::BootstrapNode>>,
}

pub(crate) trait RuntimeService: Send + Sync {
    fn name(&self) -> &'static str;
    fn enabled(&self, ctx: &StartupContext<'_>) -> bool {
        let _ = ctx;
        true
    }
    fn spawn(&self, ctx: &mut StartupContext<'_>) -> Result<()>;
}
