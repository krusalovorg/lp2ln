//! FileManifest and DirectoryManifest.
//!
//! FileManifest: ordered chunk list + per-file encryption key (the capability).
//! DirectoryManifest: versioned snapshot of the magic folder — chain of prev IDs.
//! Both are stored as regular blocks in a [`BlockStore`](crate::store::BlockStore).

use serde::{Deserialize, Serialize};

use crate::error::ContentError;
use crate::id::{ContentId, content_id_hex, unix_now};
use crate::store::BlockStore;

/// Plaintext chunks are stored as-is (pre-codec manifests).
pub const CODEC_RAW: u8 = 0;
/// Plaintext chunks are framed by [`crate::compress`] (1-byte flag + raw/lz4 payload).
pub const CODEC_FRAMED_LZ4: u8 = 1;

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
    /// Chunk plaintext framing: [`CODEC_RAW`] or [`CODEC_FRAMED_LZ4`].
    /// Last field on purpose — legacy manifests without it decode via fallback.
    pub codec: u8,
}

/// Pre-codec wire layout, kept only for decoding manifests written before the
/// `codec` field existed.
#[derive(Deserialize)]
struct LegacyFileManifest {
    original_name: String,
    file_size: u64,
    chunk_ids: Vec<ContentId>,
    file_key: [u8; 32],
    created_at: u64,
    modified_at: u64,
}

impl FileManifest {
    /// Store serialized manifest in BlockStore; returns its ContentId.
    pub fn store(&self, store: &impl BlockStore) -> Result<ContentId, ContentError> {
        let bytes = postcard::to_allocvec(self)?;
        store.put(&bytes)
    }

    /// Decode manifest bytes; legacy (pre-`codec`) manifests get `codec = CODEC_RAW`.
    /// Use this everywhere instead of raw `postcard::from_bytes`.
    pub fn decode(bytes: &[u8]) -> Result<Self, ContentError> {
        // New layout is a strict superset: legacy bytes fail with UnexpectedEnd
        // on the missing codec field, never decode as a wrong new manifest.
        if let Ok(m) = postcard::from_bytes::<FileManifest>(bytes) {
            return Ok(m);
        }
        let l: LegacyFileManifest = postcard::from_bytes(bytes)?;
        Ok(FileManifest {
            original_name: l.original_name,
            file_size: l.file_size,
            chunk_ids: l.chunk_ids,
            file_key: l.file_key,
            created_at: l.created_at,
            modified_at: l.modified_at,
            codec: CODEC_RAW,
        })
    }

    pub fn load(store: &impl BlockStore, id: &ContentId) -> Result<Self, ContentError> {
        let bytes = store.get(id)?.ok_or_else(|| {
            ContentError::NotFound(format!("file manifest {} not found", content_id_hex(id)))
        })?;
        Self::decode(&bytes)
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

    pub fn store(&self, store: &impl BlockStore) -> Result<ContentId, ContentError> {
        let bytes = postcard::to_allocvec(self)?;
        store.put(&bytes)
    }

    pub fn load(store: &impl BlockStore, id: &ContentId) -> Result<Self, ContentError> {
        let bytes = store.get(id)?.ok_or_else(|| {
            ContentError::NotFound(format!("dir manifest {} not found", content_id_hex(id)))
        })?;
        Ok(postcard::from_bytes(&bytes)?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::generate_key;
    use crate::store::MemoryBlockStore;

    #[test]
    fn file_manifest_store_load() {
        let store = MemoryBlockStore::new();
        let key = generate_key();
        let manifest = FileManifest {
            original_name: "hello.txt".to_string(),
            file_size: 42,
            chunk_ids: vec![[0u8; 32], [1u8; 32]],
            file_key: key,
            created_at: 1000,
            modified_at: 2000,
            codec: CODEC_FRAMED_LZ4,
        };
        let id = manifest.store(&store).unwrap();
        let loaded = FileManifest::load(&store, &id).unwrap();
        assert_eq!(loaded.original_name, "hello.txt");
        assert_eq!(loaded.file_key, key);
        assert_eq!(loaded.codec, CODEC_FRAMED_LZ4);
    }

    #[test]
    fn legacy_manifest_without_codec_decodes_as_raw() {
        // Serialize the pre-codec layout by hand and decode with the new struct.
        #[derive(Serialize)]
        struct Old {
            original_name: String,
            file_size: u64,
            chunk_ids: Vec<ContentId>,
            file_key: [u8; 32],
            created_at: u64,
            modified_at: u64,
        }
        let old = Old {
            original_name: "old.bin".into(),
            file_size: 7,
            chunk_ids: vec![[9u8; 32]],
            file_key: [3u8; 32],
            created_at: 1,
            modified_at: 2,
        };
        let bytes = postcard::to_allocvec(&old).unwrap();
        let m = FileManifest::decode(&bytes).unwrap();
        assert_eq!(m.original_name, "old.bin");
        assert_eq!(m.codec, CODEC_RAW);
    }

    #[test]
    fn dir_manifest_versioning() {
        let mut dm = DirectoryManifest::new([99u8; 32]);
        let v1 = dm.apply(DirEntry {
            path: "a.txt".to_string(),
            manifest_id: [1u8; 32],
            tombstone: false,
            modified_at: 10,
        });
        assert_eq!(v1, 1);
        dm.apply(DirEntry {
            path: "a.txt".to_string(),
            manifest_id: [0u8; 32],
            tombstone: true,
            modified_at: 30,
        });
        assert_eq!(dm.version, 2);
        assert!(dm.entries[0].tombstone);
    }
}
