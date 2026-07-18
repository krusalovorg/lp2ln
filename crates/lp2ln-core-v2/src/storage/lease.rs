// M5 — ReplicaLease: who promised to hold a block, until when.
// LeaseStore: redb-backed, keyed by "content_id_hex:holder_peer_id".

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use redb::ReadableTable;

use crate::db::P2PDatabase;
use crate::dht::records::unix_now;
use crate::storage::ContentId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaLease {
    pub content_id: ContentId,
    pub holder_peer_id: String,
    pub expires_at: u64,
    pub granted_at: u64,
}

impl ReplicaLease {
    pub fn is_expired(&self) -> bool {
        unix_now() >= self.expires_at
    }
}

pub struct LeaseStore {
    db: Arc<P2PDatabase>,
}

impl LeaseStore {
    pub fn new(db: Arc<P2PDatabase>) -> Self {
        Self { db }
    }

    fn key(content_id: &ContentId, holder: &str) -> String {
        format!("{}:{}", hex::encode(content_id), holder)
    }

    pub fn put(&self, lease: &ReplicaLease) -> anyhow::Result<()> {
        let k = Self::key(&lease.content_id, &lease.holder_peer_id);
        let v = postcard::to_allocvec(lease)?;
        let lock = self.db.db.lock().expect("db");
        let txn = lock.begin_write()?;
        {
            let mut t = txn.open_table(crate::db::tables::LEASE_TABLE)?;
            t.insert(k.as_str(), v.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn remove(&self, content_id: &ContentId, holder: &str) -> anyhow::Result<()> {
        let k = Self::key(content_id, holder);
        let lock = self.db.db.lock().expect("db");
        let txn = lock.begin_write()?;
        {
            let mut t = txn.open_table(crate::db::tables::LEASE_TABLE)?;
            t.remove(k.as_str())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_leases(&self, content_id: &ContentId) -> anyhow::Result<Vec<ReplicaLease>> {
        let prefix = hex::encode(content_id);
        let lock = self.db.db.lock().expect("db");
        let txn = lock.begin_read()?;
        let t = txn.open_table(crate::db::tables::LEASE_TABLE)?;
        let mut result = Vec::new();
        for item in t.iter()? {
            let (k, v) = item?;
            if k.value().starts_with(&prefix) {
                if let Ok(lease) = postcard::from_bytes::<ReplicaLease>(v.value()) {
                    result.push(lease);
                }
            }
        }
        Ok(result)
    }

    pub fn live_count(&self, content_id: &ContentId) -> anyhow::Result<usize> {
        Ok(self
            .get_leases(content_id)?
            .into_iter()
            .filter(|l| !l.is_expired())
            .count())
    }
}
