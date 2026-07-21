//! # LP2LN content primitives (P4)
//!
//! Pure reusable types for content-addressed storage:
//! ContentId, chunk encryption, manifests, block store backends, leases.
//!
//! Does **not** contain Router, PeerId routing, or NodeRuntime.
//! Network integration (DHT, block transfer, repair) lives in `lp2ln-core-v2`.

pub mod compress;
pub mod encrypt;
pub mod error;
pub mod id;
pub mod lease;
pub mod manifest;
pub mod store;
pub mod tables;

pub use error::ContentError;
pub use id::{ContentId, content_id_from_hex, content_id_hex, hash_bytes, unix_now};
pub use lease::{LeaseStore, ReplicaLease};
pub use manifest::{CODEC_FRAMED_LZ4, CODEC_RAW, DirEntry, DirectoryManifest, FileManifest};
pub use store::{BlockStore, FsBlockStore, MemoryBlockStore, RedbBlockStore};
pub use tables::{BLOCK_TABLE, LEASE_TABLE};
