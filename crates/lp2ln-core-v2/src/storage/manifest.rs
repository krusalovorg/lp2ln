// M5 — FileManifest and DirectoryManifest
//
// FileManifest: ordered chunk list + per-file encryption key (the capability).
// DirectoryManifest: versioned snapshot of the magic folder — chain of prev IDs.
// Both are stored as regular blocks in BlockStore (content-addressed).

use serde::{Deserialize, Serialize};

use crate::dht::records::unix_now;
use crate::storage::{BlockStore, ContentId};

/// All metadata needed to download and decrypt a file.
/// Sharing this struct (or its ContentId + the struct bytes) is the capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    pub original_name: String,
    pub file_size: u64,
    pub chunk_ids: Vec<ContentId>,
    /// Per-file symmetric key — never published to DHT.
    pub file_key: [u8; 32],
    pub created_at: u64,
    pub modified_at: u64,
}

impl FileManifest {
    /// Store serialized manifest in BlockStore; returns its ContentId.
    pub fn store(&self, store: &BlockStore) -> anyhow::Result<ContentId> {
        let bytes = postcard::to_allocvec(self)?;
        store.put(&bytes).map_err(|e| anyhow::anyhow!("{e}"))
    }

    pub fn load(store: &BlockStore, id: &ContentId) -> anyhow::Result<Self> {
        let bytes = store
            .get(id)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .ok_or_else(|| anyhow::anyhow!("file manifest {} not found", hex::encode(id)))?;
        postcard::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("{e}"))
    }
}

/// One file entry inside a DirectoryManifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub path: String,           // relative path (plaintext in Alpha)
    pub manifest_id: ContentId, // points to FileManifest
    pub tombstone: bool,        // true = file was deleted
    pub modified_at: u64,
}

/// Versioned snapshot of a watched directory.
/// ContentId of the latest DirectoryManifest is the "namespace pointer" shared
/// with other devices as their restore entry point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryManifest {
    pub namespace_id: [u8; 32],
    pub version: u64,
    pub entries: Vec<DirEntry>,
    pub created_at: u64,
    pub prev_manifest_id: Option<ContentId>,
}

impl DirectoryManifest {
    pub fn new(namespace_id: [u8; 32]) -> Self {
        Self {
            namespace_id,
            version: 0,
            entries: Vec::new(),
            created_at: unix_now(),
            prev_manifest_id: None,
        }
    }

    pub fn store(&self, store: &BlockStore) -> anyhow::Result<ContentId> {
        let bytes = postcard::to_allocvec(self)?;
        store.put(&bytes).map_err(|e| anyhow::anyhow!("{e}"))
    }

    pub fn load(store: &BlockStore, id: &ContentId) -> anyhow::Result<Self> {
        let bytes = store
            .get(id)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .ok_or_else(|| anyhow::anyhow!("dir manifest {} not found", hex::encode(id)))?;
        postcard::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Upsert an entry (or overwrite with tombstone). Returns new version number.
    pub fn apply(&mut self, entry: DirEntry) -> u64 {
        if let Some(e) = self.entries.iter_mut().find(|e| e.path == entry.path) {
            *e = entry;
        } else {
            self.entries.push(entry);
        }
        self.version += 1;
        self.version
    }
}
