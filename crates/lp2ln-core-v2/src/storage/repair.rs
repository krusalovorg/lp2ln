// M5 — RepairWorker: restores replication factor when replicas go missing.
//
// Periodically checks tracked blocks, finds peers via DHT, and pushes blocks
// to under-replicated ones. Leases are created optimistically (no negotiation
// — that belongs to the storage market in roadmap 06).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::dht::records::unix_now;
use crate::dht::service::DhtService;
use crate::storage::block_transfer::BlockTransferService;
use crate::storage::lease::{LeaseStore, ReplicaLease};
use crate::storage::{BlockStore, ContentId};

pub const DEFAULT_REPLICATION_FACTOR: usize = 2;
pub const LEASE_TTL_SECS: u64 = 24 * 3600;

pub struct RepairWorker {
    store: BlockStore,
    lease_store: Arc<LeaseStore>,
    block_transfer: Arc<BlockTransferService>,
    dht: Arc<DhtService>,
    replication_factor: usize,
    /// Blocks we are responsible for keeping replicated.
    tracked: Arc<RwLock<Vec<ContentId>>>,
}

impl RepairWorker {
    pub fn new(
        store: BlockStore,
        lease_store: Arc<LeaseStore>,
        block_transfer: Arc<BlockTransferService>,
        dht: Arc<DhtService>,
        replication_factor: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            lease_store,
            block_transfer,
            dht,
            replication_factor,
            tracked: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Add a block to the repair tracking set.
    pub async fn track(&self, content_id: ContentId) {
        let mut t = self.tracked.write().await;
        if !t.contains(&content_id) {
            t.push(content_id);
        }
    }

    /// Ensure `content_id` has at least `replication_factor` live leases.
    pub async fn repair_block(&self, content_id: ContentId) -> anyhow::Result<()> {
        let live = self.lease_store.live_count(&content_id)?;
        if live >= self.replication_factor {
            return Ok(());
        }
        let needed = self.replication_factor - live;

        let data = self
            .store
            .get(&content_id)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .ok_or_else(|| anyhow::anyhow!("block {} not local", hex::encode(content_id)))?;

        let local_id = self.dht.local_record.peer_id.clone();
        let peers = self.dht.find_node(content_id).await;
        let mut repaired = 0usize;

        for peer in peers.iter().filter(|p| p.peer_id != local_id) {
            if repaired >= needed {
                break;
            }
            if self
                .block_transfer
                .push_to(&peer.peer_id, content_id, data.clone())
                .await
                .is_ok()
            {
                let lease = ReplicaLease {
                    content_id,
                    holder_peer_id: peer.peer_id.clone(),
                    expires_at: unix_now() + LEASE_TTL_SECS,
                    granted_at: unix_now(),
                };
                self.lease_store.put(&lease).ok();
                repaired += 1;
            }
        }
        Ok(())
    }

    /// Spawn the background repair loop (runs every hour by default).
    pub fn spawn(self: Arc<Self>, cancel: CancellationToken) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = interval.tick() => {
                        let blocks = self.tracked.read().await.clone();
                        for cid in blocks {
                            self.repair_block(cid).await.ok();
                        }
                    }
                }
            }
        });
    }
}
