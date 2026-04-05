
mod store;

use serde::{Deserialize, Serialize};

pub use store::PeerScoreStore;

use crate::types::PeerId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerScore {
    pub latency_ms: u32,
    pub success_rate: f32,
    pub uptime_score: f32,
    pub bandwidth_score: f32,
    pub relay_score: f32,
    pub trust_score: f32,
    pub geo_score: f32,
    pub nat_compat_score: f32,
    pub load_penalty: f32,
}

impl PeerScore {
    pub fn neutral() -> Self {
        Self {
            latency_ms: 80,
            success_rate: 0.5,
            uptime_score: 0.5,
            bandwidth_score: 0.5,
            relay_score: 0.5,
            trust_score: 0.5,
            geo_score: 0.5,
            nat_compat_score: 0.5,
            load_penalty: 0.0,
        }
    }
}

impl Default for PeerScore {
    fn default() -> Self {
        Self::neutral()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerScoreWeights {
    pub w_uptime: f32,
    pub w_success: f32,
    pub w_bandwidth: f32,
    pub w_relay: f32,
    pub w_nat: f32,
    pub w_trust: f32,
    pub w_geo: f32,
    pub w_load: f32,
    pub w_latency: f32,
    pub latency_norm_ms: f32,
}

impl Default for PeerScoreWeights {
    fn default() -> Self {
        Self {
            w_uptime: 1.0,
            w_success: 1.2,
            w_bandwidth: 0.8,
            w_relay: 0.6,
            w_nat: 0.7,
            w_trust: 0.0,
            w_geo: 0.0,
            w_load: 1.0,
            w_latency: 0.9,
            latency_norm_ms: 200.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSelectionContext {
    General,
    Relay,
    StorageReplication,
    Committee,
}

impl PeerScoreWeights {
    pub fn for_context(self, ctx: PeerSelectionContext) -> Self {
        match ctx {
            PeerSelectionContext::General => self,
            PeerSelectionContext::Relay => Self {
                w_relay: self.w_relay * 2.0,
                ..self
            },
            PeerSelectionContext::StorageReplication => Self {
                w_bandwidth: self.w_bandwidth * 1.6,
                w_trust: (self.w_trust + 0.4).max(self.w_trust),
                ..self
            },
            PeerSelectionContext::Committee => Self {
                w_uptime: self.w_uptime * 1.4,
                w_trust: (self.w_trust + 0.5).max(self.w_trust),
                ..self
            },
        }
    }
}

#[inline]
pub fn latency_penalty(latency_ms: u32, norm_ms: f32) -> f32 {
    if norm_ms <= 0.0 {
        return 0.0;
    }
    ((latency_ms as f32) / norm_ms).min(1.0)
}

pub fn total_score(score: &PeerScore, w: &PeerScoreWeights) -> f32 {
    let lp = latency_penalty(score.latency_ms, w.latency_norm_ms);
    w.w_uptime * score.uptime_score
        + w.w_success * score.success_rate
        + w.w_bandwidth * score.bandwidth_score
        + w.w_relay * score.relay_score
        + w.w_nat * score.nat_compat_score
        + w.w_trust * score.trust_score
        + w.w_geo * score.geo_score
        - w.w_load * score.load_penalty
        - w.w_latency * lp
}

pub fn rank_peers(
    peers: &[PeerId],
    scores: impl Fn(&PeerId) -> PeerScore,
    w: &PeerScoreWeights,
) -> Vec<PeerId> {
    let mut v: Vec<(PeerId, f32)> = peers
        .iter()
        .map(|p| {
            let s = scores(p);
            let t = total_score(&s, w);
            (p.clone(), t)
        })
        .collect();
    v.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    v.into_iter().map(|(p, _)| p).collect()
}

pub fn select_top_k(
    peers: &[PeerId],
    scores: impl Fn(&PeerId) -> PeerScore,
    w: &PeerScoreWeights,
    k: usize,
) -> Vec<PeerId> {
    rank_peers(peers, scores, w).into_iter().take(k).collect()
}

pub fn select_best_relay(
    peers: &[PeerId],
    scores: impl Fn(&PeerId) -> PeerScore,
    base_weights: &PeerScoreWeights,
) -> Option<PeerId> {
    let w = base_weights.clone().for_context(PeerSelectionContext::Relay);
    select_top_k(peers, scores, &w, 1).into_iter().next()
}

pub fn select_storage_replicas(
    peers: &[PeerId],
    scores: impl Fn(&PeerId) -> PeerScore,
    base_weights: &PeerScoreWeights,
    k: usize,
) -> Vec<PeerId> {
    let w = base_weights
        .clone()
        .for_context(PeerSelectionContext::StorageReplication);
    select_top_k(peers, scores, &w, k)
}

pub fn select_committee_candidates(
    peers: &[PeerId],
    scores: impl Fn(&PeerId) -> PeerScore,
    base_weights: &PeerScoreWeights,
    k: usize,
) -> Vec<PeerId> {
    let w = base_weights
        .clone()
        .for_context(PeerSelectionContext::Committee);
    select_top_k(peers, scores, &w, k)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerConnectionPolicy {
    pub min_active_peers: usize,
    pub target_active_peers: usize,
    pub max_active_peers: usize,
}

impl Default for PeerConnectionPolicy {
    fn default() -> Self {
        Self {
            min_active_peers: 8,
            target_active_peers: 16,
            max_active_peers: 32,
        }
    }
}

impl PeerConnectionPolicy {
    pub fn normalized(&self) -> Self {
        let mut max = self.max_active_peers.max(1);
        let mut min = self.min_active_peers.max(1);
        if min > max {
            std::mem::swap(&mut min, &mut max);
        }
        let target = self.target_active_peers.clamp(min, max);
        Self {
            min_active_peers: min,
            target_active_peers: target,
            max_active_peers: max,
        }
    }
}
