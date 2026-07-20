use std::cmp::Ordering;
use std::collections::HashSet;
use std::time::Duration;

use dashmap::DashMap;
use hex;
use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::peer_score::{PeerConnectionPolicy, PeerScore, PeerScoreWeights, total_score};
use crate::types::PeerId;

use super::{NodeDescriptor, now_ms, verify_descriptor};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustClass {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerView {
    pub success_count: u64,
    pub failure_count: u64,
    pub rtt_ms_ema: f32,
    pub packet_loss_ema: f32,
    pub stability_score: f32,
    pub relay_relevance: f32,
    pub storage_relevance: f32,
    pub routing_relevance: f32,
    pub trust_class: TrustClass,
    pub local_total_score: f32,
    pub last_updated_ms: u64,
}

impl Default for PeerView {
    fn default() -> Self {
        Self {
            success_count: 0,
            failure_count: 0,
            rtt_ms_ema: 120.0,
            packet_loss_ema: 0.0,
            stability_score: 0.5,
            relay_relevance: 0.5,
            storage_relevance: 0.5,
            routing_relevance: 0.5,
            trust_class: TrustClass::Medium,
            local_total_score: 0.0,
            last_updated_ms: now_ms(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEvidence {
    pub reporter_peer_id: String,
    pub target_peer_id: String,
    pub fact: String,
    pub confidence: f32,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
struct PeerEvidenceUnsigned<'a> {
    reporter_peer_id: &'a str,
    target_peer_id: &'a str,
    fact: &'a str,
    confidence: f32,
    observed_at_ms: u64,
    expires_at_ms: u64,
}

pub fn sign_evidence(evidence: &mut PeerEvidence, signing_key: &SigningKey) -> Result<(), String> {
    evidence.signature.clear();
    let unsigned = PeerEvidenceUnsigned {
        reporter_peer_id: &evidence.reporter_peer_id,
        target_peer_id: &evidence.target_peer_id,
        fact: &evidence.fact,
        confidence: evidence.confidence,
        observed_at_ms: evidence.observed_at_ms,
        expires_at_ms: evidence.expires_at_ms,
    };
    let data = serde_json::to_vec(&unsigned).map_err(|e| e.to_string())?;
    let sig: Signature = signing_key.sign(&data);
    evidence.signature = hex::encode(sig.to_bytes());
    Ok(())
}

pub fn verify_evidence(evidence: &PeerEvidence) -> Result<(), String> {
    if evidence.signature.is_empty() {
        return Err("Missing evidence signature".to_string());
    }
    let unsigned = PeerEvidenceUnsigned {
        reporter_peer_id: &evidence.reporter_peer_id,
        target_peer_id: &evidence.target_peer_id,
        fact: &evidence.fact,
        confidence: evidence.confidence,
        observed_at_ms: evidence.observed_at_ms,
        expires_at_ms: evidence.expires_at_ms,
    };
    let payload = serde_json::to_vec(&unsigned).map_err(|e| e.to_string())?;
    let sig_bytes = hex::decode(&evidence.signature).map_err(|e| e.to_string())?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| e.to_string())?;
    let pub_bytes = hex::decode(&evidence.reporter_peer_id).map_err(|e| e.to_string())?;
    let vk = VerifyingKey::from_sec1_bytes(&pub_bytes).map_err(|e| e.to_string())?;
    vk.verify(&payload, &sig).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NeighborSet {
    pub core: Vec<PeerId>,
    pub utility: Vec<PeerId>,
    pub exploratory: Vec<PeerId>,
    pub standby: Vec<PeerId>,
}

impl NeighborSet {
    pub fn total_unique(&self) -> usize {
        let mut s = HashSet::new();
        for p in self
            .core
            .iter()
            .chain(self.utility.iter())
            .chain(self.exploratory.iter())
            .chain(self.standby.iter())
        {
            s.insert(p.as_str().to_string());
        }
        s.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownPeerRecord {
    pub peer_id: PeerId,
    pub descriptor: Option<NodeDescriptor>,
    pub evidence: Vec<PeerEvidence>,
    pub view: PeerView,
    #[serde(default)]
    pub quic_obfs_supported: bool,
}

impl KnownPeerRecord {
    fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            descriptor: None,
            evidence: Vec::new(),
            view: PeerView::default(),
            quic_obfs_supported: false,
        }
    }
}

#[derive(Debug)]
pub struct PeerCatalog {
    peers: DashMap<PeerId, KnownPeerRecord>,
    max_peers: usize,
    /// Anti-flood: descriptor upserts per peer_id per 1s window.
    upsert_rate: DashMap<PeerId, (u64, u32)>,
}

impl Default for PeerCatalog {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerCatalog {
    pub fn new() -> Self {
        Self::with_max_peers(4096)
    }

    pub fn with_max_peers(max_peers: usize) -> Self {
        Self {
            peers: DashMap::new(),
            max_peers: max_peers.max(128),
            upsert_rate: DashMap::new(),
        }
    }

    fn enforce_max_peers(&self) {
        let max = self.max_peers;
        let n = self.peers.len();
        if n <= max {
            return;
        }
        let mut rows: Vec<(PeerId, u64)> = self
            .peers
            .iter()
            .map(|e| (e.key().clone(), e.value().view.last_updated_ms))
            .collect();
        rows.sort_by_key(|(_, t)| *t);
        for (pid, _) in rows.into_iter().take(n - max) {
            self.peers.remove(&pid);
        }
    }

    pub fn known_peer_ids(&self) -> Vec<PeerId> {
        self.peers.iter().map(|e| e.key().clone()).collect()
    }

    pub fn descriptors(&self) -> Vec<NodeDescriptor> {
        self.peers
            .iter()
            .filter_map(|e| e.value().descriptor.clone())
            .collect()
    }

    pub fn peer_is_bootstrap_entry(&self, peer_id: &PeerId) -> bool {
        let Some(rec) = self.peers.get(peer_id) else {
            return false;
        };
        rec.descriptor
            .as_ref()
            .is_some_and(|d| d.capabilities.bootstrap_entry)
    }

    pub fn descriptor_of(&self, peer_id: &PeerId) -> Option<NodeDescriptor> {
        self.peers.get(peer_id).and_then(|r| r.descriptor.clone())
    }

    pub fn set_quic_obfs_supported(&self, peer_id: &PeerId, supported: bool) {
        if let Some(mut rec) = self.peers.get_mut(peer_id) {
            rec.quic_obfs_supported = supported;
        }
    }

    pub fn quic_obfs_supported(&self, peer_id: &PeerId) -> bool {
        self.peers
            .get(peer_id)
            .map(|r| r.quic_obfs_supported)
            .unwrap_or(false)
    }

    pub fn upsert_descriptor(&self, descriptor: NodeDescriptor) -> Result<bool, String> {
        verify_descriptor(&descriptor)?;
        if descriptor.expires_at_ms() <= now_ms() {
            return Ok(false);
        }
        let pid = PeerId::from(descriptor.peer_id.as_str());
        const MAX_UPSERTS_PER_PEER_PER_SEC: u32 = 8;
        let now = now_ms();
        {
            let mut slot = self.upsert_rate.entry(pid.clone()).or_insert((now, 0));
            if now.saturating_sub(slot.0) >= 1_000 {
                slot.0 = now;
                slot.1 = 0;
            }
            slot.1 = slot.1.saturating_add(1);
            if slot.1 > MAX_UPSERTS_PER_PEER_PER_SEC {
                return Ok(false);
            }
        }
        let mut rec = self
            .peers
            .entry(pid.clone())
            .or_insert_with(|| KnownPeerRecord::new(pid));
        if let Some(old) = rec.descriptor.as_ref() {
            if old.version > descriptor.version {
                return Ok(false);
            }
            if old.version == descriptor.version && old.timestamp_ms >= descriptor.timestamp_ms {
                return Ok(false);
            }
        }
        rec.descriptor = Some(descriptor);
        rec.view.last_updated_ms = now;
        drop(rec);
        self.enforce_max_peers();
        Ok(true)
    }

    pub fn add_evidence(&self, evidence: PeerEvidence) -> Result<bool, String> {
        verify_evidence(&evidence)?;
        let now = now_ms();
        if evidence.expires_at_ms <= now || evidence.observed_at_ms > now + 30_000 {
            return Ok(false);
        }
        let pid = PeerId::from(evidence.target_peer_id.as_str());
        let mut rec = self
            .peers
            .entry(pid.clone())
            .or_insert_with(|| KnownPeerRecord::new(pid));
        let already = rec.evidence.iter().any(|e| {
            e.reporter_peer_id == evidence.reporter_peer_id
                && e.fact == evidence.fact
                && e.observed_at_ms == evidence.observed_at_ms
        });
        if already {
            return Ok(false);
        }
        rec.evidence.push(evidence);
        rec.view.last_updated_ms = now;
        Ok(true)
    }

    pub fn observe_success(&self, peer_id: &PeerId, rtt_ms: u32) {
        let mut rec = self
            .peers
            .entry(peer_id.clone())
            .or_insert_with(|| KnownPeerRecord::new(peer_id.clone()));
        rec.view.success_count += 1;
        rec.view.rtt_ms_ema = 0.85 * rec.view.rtt_ms_ema + 0.15 * (rtt_ms as f32);
        rec.view.packet_loss_ema = (rec.view.packet_loss_ema * 0.9).max(0.0);
        rec.view.stability_score = (rec.view.stability_score + 0.02).min(1.0);
        rec.view.last_updated_ms = now_ms();
    }

    pub fn observe_failure(&self, peer_id: &PeerId) {
        let mut rec = self
            .peers
            .entry(peer_id.clone())
            .or_insert_with(|| KnownPeerRecord::new(peer_id.clone()));
        rec.view.failure_count += 1;
        rec.view.packet_loss_ema = (rec.view.packet_loss_ema + 0.08).min(1.0);
        rec.view.stability_score = (rec.view.stability_score * 0.94).max(0.0);
        rec.view.last_updated_ms = now_ms();
    }

    pub fn decay(&self, half_life: Duration) {
        let now = now_ms();
        let hl = half_life.as_secs_f32().max(1.0);
        for mut rec in self.peers.iter_mut() {
            let age_secs =
                ((now.saturating_sub(rec.view.last_updated_ms)) as f32 / 1000.0).max(0.0);
            let decay = 2.0_f32.powf(-age_secs / hl);
            rec.view.stability_score *= decay.max(0.5);
            rec.view.local_total_score *= decay.max(0.6);
        }
    }

    pub fn cleanup_expired(&self) {
        let now = now_ms();
        let keys: Vec<PeerId> = self.peers.iter().map(|e| e.key().clone()).collect();
        for pid in keys {
            let mut remove = false;
            if let Some(mut rec) = self.peers.get_mut(&pid) {
                rec.evidence.retain(|e| e.expires_at_ms > now);
                if let Some(desc) = rec.descriptor.as_ref() {
                    if desc.expires_at_ms() <= now {
                        rec.descriptor = None;
                    }
                }
                if rec.descriptor.is_none()
                    && rec.view.success_count == 0
                    && rec.view.failure_count == 0
                {
                    remove = true;
                }
            }
            if remove {
                self.peers.remove(&pid);
            }
        }
    }

    pub fn recalc_scores(&self, weights: &PeerScoreWeights) -> Vec<(PeerId, PeerScore)> {
        let mut out = Vec::new();
        for mut rec in self.peers.iter_mut() {
            let (relay, storage, routing, load_penalty, nat, up): (f32, f32, f32, f32, f32, f32) =
                if let Some(desc) = rec.descriptor.as_ref() {
                    let relay = if desc.capabilities.can_relay {
                        1.0
                    } else {
                        0.2
                    };
                    let storage = if desc.capabilities.can_store_data {
                        1.0
                    } else {
                        0.2
                    };
                    let routing = if desc.capabilities.public_reachable {
                        0.9
                    } else {
                        0.4
                    };
                    let load = ((desc.dynamic_status.cpu_load
                        + desc.dynamic_status.memory_pressure)
                        / 2.0)
                        .clamp(0.0, 1.0);
                    let nat = if desc.capabilities.public_reachable {
                        0.9
                    } else {
                        0.6
                    };
                    let up = 1.0 - load * 0.5;
                    (relay, storage, routing, load, nat, up)
                } else {
                    (0.5, 0.5, 0.5, 0.3, 0.5, 0.5)
                };
            let total = rec.view.success_count + rec.view.failure_count;
            let success_rate = if total > 0 {
                rec.view.success_count as f32 / total as f32
            } else {
                0.5
            };
            let loss = rec.view.packet_loss_ema.clamp(0.0, 1.0);
            let confidence = 1.0 - (loss * 0.6);
            let trust = match rec.view.trust_class {
                TrustClass::Low => 0.2,
                TrustClass::Medium => 0.5,
                TrustClass::High => 0.85,
            };
            let score = PeerScore {
                latency_ms: rec.view.rtt_ms_ema.max(0.0) as u32,
                success_rate: (success_rate * confidence).clamp(0.0, 1.0),
                uptime_score: (up * rec.view.stability_score).clamp(0.0, 1.0),
                bandwidth_score: storage.clamp(0.0, 1.0),
                relay_score: relay.clamp(0.0, 1.0),
                trust_score: trust,
                geo_score: routing,
                nat_compat_score: nat,
                load_penalty: load_penalty.clamp(0.0, 1.0),
            };
            rec.view.relay_relevance = relay;
            rec.view.storage_relevance = storage;
            rec.view.routing_relevance = routing;
            rec.view.local_total_score = total_score(&score, weights);
            out.push((rec.peer_id.clone(), score));
        }
        out
    }

    pub fn select_neighbor_set(
        &self,
        weights: &PeerScoreWeights,
        policy: &PeerConnectionPolicy,
    ) -> NeighborSet {
        let mut ranked: Vec<(PeerId, f32)> = self
            .peers
            .iter()
            .map(|e| (e.key().clone(), e.value().view.local_total_score))
            .collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
        let policy = policy.normalized();
        let exploratory_n = (policy.target_active_peers / 6).max(1);
        let core_n = (policy.target_active_peers / 2).max(1);
        let utility_n = policy
            .target_active_peers
            .saturating_sub(core_n + exploratory_n);
        let mut set = NeighborSet::default();
        for (i, (pid, _)) in ranked.iter().enumerate() {
            if i < core_n {
                set.core.push(pid.clone());
            } else if i < core_n + utility_n {
                set.utility.push(pid.clone());
            } else if i < core_n + utility_n + exploratory_n {
                set.exploratory.push(pid.clone());
            } else if set.standby.len() < policy.max_active_peers {
                set.standby.push(pid.clone());
            }
        }
        let _ = weights;
        set
    }
}
