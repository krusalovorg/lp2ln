//! # EXPERIMENTAL 
//!
//! Local content-addressed block store, encryption, manifests, leases, transfer, repair.
//!
//! **Not** a completed distributed storage system. Default `lp2lnd` does not start
//! content/repair lifecycle. Opt-in surfaces:
//! - `experimental.content` — debug `block_put` / `block_get`
//! - `experimental.repair` — reserved for RepairWorker (not started by daemon yet)
//!
//! ContentId = SHA-256 of the chunk envelope (nonce || ciphertext||tag)
//! after encrypt-then-hash (roadmap 04 / P0-03). See `encrypt` module docs.
//! BlockStore wraps the existing redb P2PDatabase via the BLOCK_TABLE.

pub mod block_transfer;
pub mod encrypt;
pub mod lease;
pub mod manifest;
pub mod repair;

use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::db::P2PDatabase;

pub type ContentId = [u8; 32];

pub fn hash_bytes(data: &[u8]) -> ContentId {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn content_id_hex(id: &ContentId) -> String {
    hex::encode(id)
}

pub fn content_id_from_hex(s: &str) -> Option<ContentId> {
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

#[derive(Clone)]
pub struct BlockStore {
    db: Arc<P2PDatabase>,
}

impl BlockStore {
    pub fn new(db: Arc<P2PDatabase>) -> Self {
        Self { db }
    }

    /// Store `data`, return its ContentId.
    pub fn put(&self, data: &[u8]) -> Result<ContentId, redb::Error> {
        let id = hash_bytes(data);
        let key = content_id_hex(&id);
        let lock = self.db.db.lock().expect("db lock");
        let txn = lock.begin_write()?;
        {
            let mut table = txn.open_table(crate::db::tables::BLOCK_TABLE)?;
            table.insert(key.as_str(), data)?;
        }
        txn.commit()?;
        Ok(id)
    }

    /// Retrieve block by ContentId.
    pub fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, redb::Error> {
        let key = content_id_hex(id);
        let lock = self.db.db.lock().expect("db lock");
        let txn = lock.begin_read()?;
        let table = txn.open_table(crate::db::tables::BLOCK_TABLE)?;
        Ok(table.get(key.as_str())?.map(|v| v.value().to_vec()))
    }

    /// Returns true iff the stored bytes still hash to the given ContentId.
    pub fn verify(&self, id: &ContentId) -> Result<bool, redb::Error> {
        match self.get(id)? {
            Some(data) => Ok(hash_bytes(&data) == *id),
            None => Ok(false),
        }
    }

    /// Remove a block.
    pub fn delete(&self, id: &ContentId) -> Result<(), redb::Error> {
        let key = content_id_hex(id);
        let lock = self.db.db.lock().expect("db lock");
        let txn = lock.begin_write()?;
        {
            let mut table = txn.open_table(crate::db::tables::BLOCK_TABLE)?;
            table.remove(key.as_str())?;
        }
        txn.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> Arc<P2PDatabase> {
        let dir = std::env::temp_dir().join(format!("lp2ln_block_test_{}", uuid::Uuid::new_v4()));
        Arc::new(P2PDatabase::new(dir.to_str().unwrap()).expect("db"))
    }

    #[test]
    fn put_get_verify_roundtrip() {
        let db = temp_db();
        let store = BlockStore::new(db);
        let data = b"hello content-addressed world";
        let id = store.put(data).expect("put");
        assert_eq!(store.get(&id).expect("get").unwrap(), data);
        assert!(store.verify(&id).expect("verify"));
    }

    #[test]
    fn delete_removes_block() {
        let db = temp_db();
        let store = BlockStore::new(db);
        let id = store.put(b"delete me").expect("put");
        store.delete(&id).expect("delete");
        assert!(store.get(&id).expect("get").is_none());
    }
}
