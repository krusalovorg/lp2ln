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
pub use dht::{DhtService, DhtStore, ProviderRecord};

pub type BlockStore = RedbBlockStore;

pub fn block_store_from_db(db: Arc<P2PDatabase>) -> BlockStore {
    RedbBlockStore::from_database(db.db.clone())
}

pub fn lease_store_from_db(db: Arc<P2PDatabase>) -> LeaseStore {
    LeaseStore::from_database(db.db.clone())
}
