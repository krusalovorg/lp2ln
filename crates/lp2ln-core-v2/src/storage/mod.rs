//! # EXPERIMENTAL
//!
//! Local content-addressed block store, encryption, manifests, leases, transfer, repair.
//!
//! Pure primitives live in `lp2ln-content` (P4-01). This module re-exports them and
//! keeps network integration (`block_transfer`, `repair`).
//!
//! **Not** a completed distributed storage system. Default `lp2lnd` does not start
//! content/repair lifecycle. Opt-in surfaces:
//! - `experimental.content` — debug `block_put` / `block_get`
//! - `experimental.repair` — reserved for RepairWorker (not started by daemon yet)
//!
//! ContentId = SHA-256 of the chunk envelope (nonce || ciphertext||tag)
//! after encrypt-then-hash. See `encrypt` module docs.

pub mod block_transfer;
pub mod dht;
pub mod repair;

use std::sync::Arc;

use crate::db::P2PDatabase;

pub use lp2ln_content::encrypt;
pub use lp2ln_content::{lease, manifest};
pub use lp2ln_content::lease::{LeaseStore, ReplicaLease};
pub use lp2ln_content::manifest::{DirEntry, DirectoryManifest, FileManifest};
pub use lp2ln_content::{
    BlockStore as BlockStoreTrait, ContentError, ContentId, FsBlockStore, MemoryBlockStore,
    RedbBlockStore, content_id_from_hex, content_id_hex, hash_bytes,
};

pub use block_transfer::BlockTransferService;
pub use dht::{DhtService, DhtStore, ProviderRecord, ValueRecord};

pub type BlockStore = FsBlockStore;

/// Node block store: one file per block under `{db.path}/blocks/`.
/// redb never shrinks and serializes MiB-sized blobs through one lock,
/// so chunks don't belong in it. Legacy in-db blocks are migrated once.
pub fn block_store_from_db(db: Arc<P2PDatabase>) -> BlockStore {
    let root = std::path::Path::new(&db.path).join("blocks");
    let store = FsBlockStore::new(&root).expect("create node block store dir");
    migrate_legacy_blocks(&db, &store);
    store
}

/// One-time migration of blocks stored in redb's BLOCK_TABLE by older versions.
/// No-op (one cheap read txn) once the table is empty. Best-effort: on error the
/// legacy blocks stay in redb and we retry on the next open.
fn migrate_legacy_blocks(db: &P2PDatabase, store: &FsBlockStore) {
    use lp2ln_content::BLOCK_TABLE;
    use redb::ReadableTable;
    let run = || -> anyhow::Result<usize> {
        let lock = db.db.lock().expect("db lock");
        {
            let txn = lock.begin_read()?;
            let table = txn.open_table(BLOCK_TABLE)?;
            if table.iter()?.next().is_none() {
                return Ok(0);
            }
        }
        let txn = lock.begin_write()?;
        let mut keys = Vec::new();
        {
            let mut table = txn.open_table(BLOCK_TABLE)?;
            for item in table.iter()? {
                let (k, v) = item?;
                store.put(v.value())?;
                keys.push(k.value().to_string());
            }
            for k in &keys {
                table.remove(k.as_str())?;
            }
        }
        txn.commit()?;
        Ok(keys.len())
    };
    match run() {
        Ok(0) => {}
        Ok(n) => crate::info!("[storage] migrated {n} blocks from redb to {}/blocks", db.path),
        Err(e) => crate::warn!("[storage] legacy block migration failed: {e}"),
    }
}

pub fn lease_store_from_db(db: Arc<P2PDatabase>) -> LeaseStore {
    LeaseStore::from_database(db.db.clone())
}
