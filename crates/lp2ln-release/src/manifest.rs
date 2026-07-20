use serde::{Deserialize, Serialize};

use crate::key::{ReleaseError, ReleaseSigningKey, ReleaseVerifyKey};

/// LP2LN protocol ID reserved for update announcements.
pub const UPDATE_PROTOCOL_ID: u16 = 0xF001;

/// Fields that are signed. Serialised with postcard before signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub format_version: u8,
    pub channel: String,
    pub build_id: String,
    pub version: String,
    pub target_os: String,
    pub target_arch: String,
    /// SHA-256 of the raw binary.
    pub package_hash: [u8; 32],
    pub package_size: u64,
    pub min_protocol: u16,
    pub max_protocol: u16,
    pub required_features: Vec<String>,
    /// 0-100 rollout percentage.
    pub rollout_percent: u8,
    /// Max nodes applying the update concurrently.
    pub max_concurrent: u32,
    pub created_at: u64,
    pub expires_at: u64,
    pub release_key_id: String,
}

/// Wire type broadcast over LP2LN (protocol_id = UPDATE_PROTOCOL_ID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifest {
    pub manifest: ReleaseManifest,
    /// DER-encoded ECDSA signature over `postcard(manifest)`.
    pub signature: Vec<u8>,
}

impl SignedManifest {
    pub fn sign(manifest: ReleaseManifest, key: &ReleaseSigningKey) -> Result<Self, ReleaseError> {
        let body = postcard::to_allocvec(&manifest)?;
        let signature = key.sign(&body);
        Ok(Self { manifest, signature })
    }

    pub fn verify(&self, key: &ReleaseVerifyKey) -> Result<(), ReleaseError> {
        let body = postcard::to_allocvec(&self.manifest)?;
        key.verify(&body, &self.signature)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ReleaseError> {
        postcard::to_allocvec(self).map_err(ReleaseError::Codec)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ReleaseError> {
        postcard::from_bytes(bytes).map_err(ReleaseError::Codec)
    }
}
