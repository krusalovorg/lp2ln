use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use lp2ln_content::id::{ContentId, content_id_from_hex, content_id_hex};

pub const EXTENSION: &str = ".lp2ln";
const MAGIC: &str = "LP2LN";
const VERSION: u32 = 1;

/// Written to `<file>.lp2ln` when the original file is dehydrated.
///
/// Contains enough info to locate and decrypt the file from the local block store.
/// The `mac` binds all fields to `namespace_key`, preventing tampering or key mismatch.
#[derive(Debug, Serialize, Deserialize)]
pub struct Placeholder {
    pub magic: String,
    pub version: u32,
    pub namespace_id: String,  // hex [u8; 32]
    pub manifest_id: String,   // hex ContentId → FileManifest
    pub original_name: String, // relative path inside the folder root
    pub file_size: u64,
    pub modified_at: u64,
    pub mac: String, // hex SHA-256(namespace_key || above fields)
}

impl Placeholder {
    pub fn build(
        namespace_id: &[u8; 32],
        namespace_key: &[u8; 32],
        manifest_id: ContentId,
        original_name: &str,
        file_size: u64,
        modified_at: u64,
    ) -> Self {
        let ns_hex = hex::encode(namespace_id);
        let mid_hex = content_id_hex(&manifest_id);
        let mac_bytes = compute_mac(namespace_key, &ns_hex, &mid_hex, original_name, file_size, modified_at);
        Self {
            magic: MAGIC.to_string(),
            version: VERSION,
            namespace_id: ns_hex,
            manifest_id: mid_hex,
            original_name: original_name.to_string(),
            file_size,
            modified_at,
            mac: hex::encode(mac_bytes),
        }
    }

    pub fn verify_mac(&self, namespace_key: &[u8; 32]) -> bool {
        let expected = compute_mac(
            namespace_key,
            &self.namespace_id,
            &self.manifest_id,
            &self.original_name,
            self.file_size,
            self.modified_at,
        );
        hex::encode(expected) == self.mac
    }

    pub fn manifest_content_id(&self) -> Option<ContentId> {
        content_id_from_hex(&self.manifest_id)
    }

    /// Write placeholder to `path` atomically (temp→rename).
    pub fn write_to(&self, path: &Path) -> anyhow::Result<()> {
        let tmp = path.with_extension("lp2ln.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn read_from(path: &Path) -> anyhow::Result<Self> {
        let p: Self = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        anyhow::ensure!(p.magic == MAGIC, "not a .lp2ln file (wrong magic: {:?})", p.magic);
        anyhow::ensure!(p.version == VERSION, "unsupported placeholder version {}", p.version);
        Ok(p)
    }
}

fn compute_mac(
    key: &[u8; 32],
    ns_hex: &str,
    mid_hex: &str,
    original_name: &str,
    file_size: u64,
    modified_at: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(key);
    h.update(ns_hex.as_bytes());
    h.update(mid_hex.as_bytes());
    h.update(original_name.as_bytes());
    h.update(file_size.to_le_bytes());
    h.update(modified_at.to_le_bytes());
    h.finalize().into()
}
