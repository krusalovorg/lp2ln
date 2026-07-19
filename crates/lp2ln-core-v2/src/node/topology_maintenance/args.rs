use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};

use dashmap::DashMap;

use crate::db::P2PDatabase;
use crate::node::nat_traversal::NatTraversalState;
use crate::node::options::{BootstrapNode, DialPolicy, NodeRole, TopologyTuning};
use crate::peer_score::{PeerConnectionPolicy, PeerScoreStore, PeerScoreWeights};
use crate::router::Router;
use crate::sessions::manager::SessionManager;
use crate::sessions::session::IncomingPacket;
use crate::topology::{PeerCatalog, PeerDirectory};
use crate::transport::Transport;
use crate::types::PeerId;

use super::session_reactions::SessionRedialQueue;

pub(crate) struct TopologyMaintenanceArgs {
    pub(crate) policy_live: Arc<RwLock<PeerConnectionPolicy>>,
    pub(crate) node_role: NodeRole,
    pub(crate) weights: PeerScoreWeights,
    pub(crate) sm: Arc<SessionManager>,
    pub(crate) peer_dir: Arc<PeerDirectory>,
    pub(crate) dial_book: Arc<DashMap<PeerId, Vec<(String, SocketAddr)>>>,
    pub(crate) peer_store: Arc<PeerScoreStore>,
    pub(crate) catalog: Arc<PeerCatalog>,
    pub(crate) db: Option<Arc<P2PDatabase>>,
    pub(crate) listens: DashMap<String, SocketAddr>,
    pub(crate) advertise_addrs: HashMap<String, SocketAddr>,
    pub(crate) advertise_fallback_ip: Option<IpAddr>,
    pub(crate) transports: Vec<Arc<dyn Transport>>,
    pub(crate) router: Arc<Router>,
    pub(crate) incoming: tokio::sync::mpsc::Sender<IncomingPacket>,
    pub(crate) our_peer_id: String,
    pub(crate) descriptor_ver: Arc<AtomicU64>,
    pub(crate) signing_key: k256::ecdsa::SigningKey,
    pub(crate) log_peer_scores: bool,
    pub(crate) topology_tuning: TopologyTuning,
    pub(crate) handshake_payload: Vec<u8>,
    pub(crate) bootstrap_targets: Vec<BootstrapNode>,
    pub(crate) nat_state: Arc<NatTraversalState>,
    pub(crate) bootstrap_dial_dedupe: Arc<Mutex<HashSet<(String, SocketAddr)>>>,
    pub(crate) bootstrap_dial_ok_ms: Arc<Mutex<HashMap<SocketAddr, u64>>>,
    pub(crate) session_redial_queue: Option<Arc<SessionRedialQueue>>,
    pub(crate) react_to_session_events: bool,
    pub(crate) dial_policy: DialPolicy,
}
