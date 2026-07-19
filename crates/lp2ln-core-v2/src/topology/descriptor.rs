use std::net::SocketAddr;

use hex;
use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::metrics::NodeHealthSnapshot;

use super::now_ms;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapabilities {
    pub can_relay: bool,
    pub can_store_data: bool,
    pub can_validate: bool,
    pub supports_udp: bool,
    pub supports_tcp: bool,
    pub public_reachable: bool,
    pub available_disk_mb: u64,
    pub base_session_limit: u16,
    #[serde(default, skip_serializing_if = "is_false")]
    pub bootstrap_entry: bool,
}

#[inline]
fn is_false(b: &bool) -> bool {
    !*b
}

impl Default for NodeCapabilities {
    fn default() -> Self {
        Self {
            can_relay: true,
            can_store_data: true,
            can_validate: false,
            supports_udp: true,
            supports_tcp: true,
            public_reachable: false,
            available_disk_mb: 1024,
            base_session_limit: 32,
            bootstrap_entry: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDynamicStatus {
    pub cpu_load: f32,
    pub memory_pressure: f32,
    pub active_connections: u16,
    pub relay_jobs: u16,
    pub storage_jobs: u16,
    pub accepts_new_sessions: bool,
    pub accepts_new_relay_jobs: bool,
    pub accepts_new_storage_jobs: bool,
}

impl Default for NodeDynamicStatus {
    fn default() -> Self {
        Self {
            cpu_load: 0.0,
            memory_pressure: 0.0,
            active_connections: 0,
            relay_jobs: 0,
            storage_jobs: 0,
            accepts_new_sessions: true,
            accepts_new_relay_jobs: true,
            accepts_new_storage_jobs: true,
        }
    }
}

impl From<&NodeHealthSnapshot> for NodeDynamicStatus {
    fn from(value: &NodeHealthSnapshot) -> Self {
        Self {
            cpu_load: value.conn_load_estimate,
            memory_pressure: value.local_capacity_pressure,
            active_connections: value.active_connections,
            relay_jobs: 0,
            storage_jobs: 0,
            accepts_new_sessions: true,
            accepts_new_relay_jobs: true,
            accepts_new_storage_jobs: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDescriptor {
    pub peer_id: String,
    pub capabilities: NodeCapabilities,
    pub dynamic_status: NodeDynamicStatus,
    pub observed_addrs: Vec<String>,
    pub ttl_secs: u64,
    pub version: u64,
    pub timestamp_ms: u64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
struct NodeDescriptorUnsigned<'a> {
    peer_id: &'a str,
    capabilities: &'a NodeCapabilities,
    dynamic_status: &'a NodeDynamicStatus,
    observed_addrs: &'a [String],
    ttl_secs: u64,
    version: u64,
    timestamp_ms: u64,
}

impl NodeDescriptor {
    pub fn new_unsigned(
        peer_id: impl Into<String>,
        capabilities: NodeCapabilities,
        dynamic_status: NodeDynamicStatus,
        observed_addrs: Vec<String>,
        ttl_secs: u64,
        version: u64,
    ) -> Self {
        Self {
            peer_id: peer_id.into(),
            capabilities,
            dynamic_status,
            observed_addrs,
            ttl_secs,
            version,
            timestamp_ms: now_ms(),
            signature: String::new(),
        }
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.timestamp_ms
            .saturating_add(self.ttl_secs.saturating_mul(1000))
    }
}

pub fn parse_observed_addr_line(s: &str) -> Option<(String, SocketAddr)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let lower = s.to_lowercase();
    if let Some(rest) = lower.strip_prefix("tcp:") {
        return rest.trim().parse().ok().map(|a| ("tcp".to_string(), a));
    }
    if let Some(rest) = lower.strip_prefix("udp:") {
        return rest.trim().parse().ok().map(|a| ("udp".to_string(), a));
    }
    if let Some(rest) = lower.strip_prefix("quic:") {
        return rest.trim().parse().ok().map(|a| ("quic".to_string(), a));
    }
    s.parse().ok().map(|a| ("tcp".to_string(), a))
}

pub fn sign_descriptor(
    descriptor: &mut NodeDescriptor,
    signing_key: &SigningKey,
) -> Result<(), String> {
    descriptor.signature.clear();
    let unsigned = NodeDescriptorUnsigned {
        peer_id: &descriptor.peer_id,
        capabilities: &descriptor.capabilities,
        dynamic_status: &descriptor.dynamic_status,
        observed_addrs: &descriptor.observed_addrs,
        ttl_secs: descriptor.ttl_secs,
        version: descriptor.version,
        timestamp_ms: descriptor.timestamp_ms,
    };
    let data = serde_json::to_vec(&unsigned).map_err(|e| e.to_string())?;
    let sig: Signature = signing_key.sign(&data);
    descriptor.signature = hex::encode(sig.to_bytes());
    Ok(())
}

pub fn verify_descriptor(descriptor: &NodeDescriptor) -> Result<(), String> {
    if descriptor.signature.is_empty() {
        return Err("Missing descriptor signature".to_string());
    }
    let unsigned = NodeDescriptorUnsigned {
        peer_id: &descriptor.peer_id,
        capabilities: &descriptor.capabilities,
        dynamic_status: &descriptor.dynamic_status,
        observed_addrs: &descriptor.observed_addrs,
        ttl_secs: descriptor.ttl_secs,
        version: descriptor.version,
        timestamp_ms: descriptor.timestamp_ms,
    };
    let payload = serde_json::to_vec(&unsigned).map_err(|e| e.to_string())?;
    let sig_bytes = hex::decode(&descriptor.signature).map_err(|e| e.to_string())?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| e.to_string())?;
    let pub_bytes = hex::decode(&descriptor.peer_id).map_err(|e| e.to_string())?;
    let vk = VerifyingKey::from_sec1_bytes(&pub_bytes).map_err(|e| e.to_string())?;
    vk.verify(&payload, &sig).map_err(|e| e.to_string())
}
