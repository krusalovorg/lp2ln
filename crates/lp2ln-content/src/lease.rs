//! ReplicaLease: who promised to hold a block, until when.
//! LeaseStore: redb-backed, keyed by `content_id_hex:holder_peer_id`.

use std::sync::{Arc, Mutex};

use redb::{Database, ReadableTable};
use serde::{Deserialize, Serialize};

use crate::error::ContentError;
use crate::id::{ContentId, content_id_hex, unix_now};
use crate::tables::LEASE_TABLE;

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
    db: Arc<Mutex<Database>>,
}

impl LeaseStore {
    pub fn from_database(db: Arc<Mutex<Database>>) -> Self {
        Self { db }
    }

    /// Ensure the lease table exists on a shared / standalone database.
    pub fn ensure_table(db: &Database) -> Result<(), ContentError> {
        let txn = db.begin_write()?;
        {
            let _ = txn.open_table(LEASE_TABLE)?;
        }
        txn.commit()?;
        Ok(())
    }

    fn key(content_id: &ContentId, holder: &str) -> String {
        format!("{}:{}", content_id_hex(content_id), holder)
    }

    pub fn put(&self, lease: &ReplicaLease) -> Result<(), ContentError> {
        let k = Self::key(&lease.content_id, &lease.holder_peer_id);
        let v = postcard::to_allocvec(lease)?;
        let lock = self.db.lock().expect("db");
        let txn = lock.begin_write()?;
        {
            let mut t = txn.open_table(LEASE_TABLE)?;
            t.insert(k.as_str(), v.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn remove(&self, content_id: &ContentId, holder: &str) -> Result<(), ContentError> {
        let k = Self::key(content_id, holder);
        let lock = self.db.lock().expect("db");
        let txn = lock.begin_write()?;
        {
            let mut t = txn.open_table(LEASE_TABLE)?;
            t.remove(k.as_str())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_leases(&self, content_id: &ContentId) -> Result<Vec<ReplicaLease>, ContentError> {
        let prefix = content_id_hex(content_id);
        let lock = self.db.lock().expect("db");
        let txn = lock.begin_read()?;
        let t = txn.open_table(LEASE_TABLE)?;
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

    pub fn live_count(&self, content_id: &ContentId) -> Result<usize, ContentError> {
        Ok(self
            .get_leases(content_id)?
            .into_iter()
            .filter(|l| !l.is_expired())
            .count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::RedbBlockStore;
    use std::fs;

    #[test]
    fn lease_put_get_count() {
        let dir = std::env::temp_dir().join(format!(
            "lp2ln_content_lease_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let blocks = RedbBlockStore::open(dir.join("db")).unwrap();
        LeaseStore::ensure_table(&blocks.database().lock().expect("db")).unwrap();
        let ls = LeaseStore::from_database(blocks.database());
        let cid: ContentId = [7u8; 32];

        ls.put(&ReplicaLease {
            content_id: cid,
            holder_peer_id: "peer-abc".to_string(),
            expires_at: u64::MAX,
            granted_at: 0,
        })
        .unwrap();
        assert_eq!(ls.live_count(&cid).unwrap(), 1);

        ls.put(&ReplicaLease {
            content_id: cid,
            holder_peer_id: "peer-expired".to_string(),
            expires_at: 1,
            granted_at: 0,
        })
        .unwrap();
        assert_eq!(ls.live_count(&cid).unwrap(), 1);

        ls.remove(&cid, "peer-abc").unwrap();
        assert_eq!(ls.live_count(&cid).unwrap(), 0);
        let _ = fs::remove_dir_all(&dir);
    }
}
