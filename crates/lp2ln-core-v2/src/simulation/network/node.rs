use std::sync::Arc;
use std::sync::Once;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::crypto::NodeKeypair;
use crate::crypto::peer_cache::PeerCryptoCache;
use crate::crypto::signature::SignatureFormat;
use crate::logger::{LoggerOptions, init};
use crate::nat::NatTraversalState;
use crate::packet_processor::DefaultPacketProcessor;
use crate::peer_score::{PeerScoreStore, PeerScoreWeights};
use crate::router::Router;
use crate::sessions::manager::SessionManager;
use crate::simulation::topology::SimNodeId;
use crate::topology::PeerCatalog;

use super::routing::SimRoutingTable;

const SIM_INCOMING_CAP: usize = 16_384;
const SIM_BROADCAST_CAP: usize = 512;
const SIM_WORKER_CONCURRENCY: usize = 4;

static SIM_LOGGER: Once = Once::new();

fn init_sim_logger() {
    SIM_LOGGER.call_once(|| {
        init(&LoggerOptions {
            log_dir: None,
            file_enabled: false,
            show_debug: false,
            show_info: false,
            show_warning: false,
            show_error: false,
        });
    });
}

pub fn sim_peer_id(node_id: SimNodeId) -> String {
    format!("sim-{node_id:04}")
}

pub struct SimNode {
    pub node_id: SimNodeId,
    pub peer_id: String,
    pub router: Arc<Router>,
    run_handle: JoinHandle<()>,
}

impl SimNode {
    pub fn spawn(
        node_id: SimNodeId,
        cancel: CancellationToken,
        routing: Arc<SimRoutingTable>,
    ) -> Self {
        init_sim_logger();
        let keypair = NodeKeypair::generate();
        let peer_id = keypair.peer_id().to_string();
        let signing_key = Arc::new(keypair.signing_key().clone());
        let peer_catalog = Arc::new(PeerCatalog::with_max_peers(256));
        let nat_state = NatTraversalState::new();
        let peer_cache = PeerCryptoCache::new();
        let processor = Arc::new(
            DefaultPacketProcessor::new(
                peer_id.clone(),
                true,
                peer_catalog,
                0.0,
                nat_state,
                keypair,
                peer_cache.clone(),
            )
            .with_forward_hop_resolver(routing.resolver(node_id)),
        );
        let session_manager = Arc::new(SessionManager::new(
            Arc::new(PeerScoreStore::new()),
            PeerScoreWeights::default(),
        ));
        let (router, mut incoming_rx) = Router::new_with_caps(
            session_manager,
            processor,
            Some(signing_key),
            peer_id.clone(),
            None,
            peer_cache,
            SIM_INCOMING_CAP,
            SIM_BROADCAST_CAP,
            SIM_WORKER_CONCURRENCY,
            SignatureFormat::V2Hash,
        );
        let router = Arc::new(router);
        let run_router = router.clone();
        let run_cancel = cancel.clone();
        let run_handle = tokio::spawn(async move {
            let _ = run_router.run(&mut incoming_rx, run_cancel).await;
        });

        Self {
            node_id,
            peer_id,
            router,
            run_handle,
        }
    }

    pub fn incoming_sender(&self) -> mpsc::Sender<crate::sessions::session::IncomingPacket> {
        self.router.incoming_sender()
    }

    pub async fn join_run(self) {
        let _ = self.run_handle.await;
        self.router
            .shutdown_packet_tasks(std::time::Duration::from_secs(2))
            .await;
    }
}

impl std::fmt::Debug for SimNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimNode")
            .field("node_id", &self.node_id)
            .field("peer_id", &self.peer_id)
            .finish()
    }
}
