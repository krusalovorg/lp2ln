use sha2::{Digest, Sha256};

/// SHA-256 digest of stored bytes (typically a chunk envelope).
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

/// Unix seconds since epoch (local clock).
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
