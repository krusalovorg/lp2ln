use std::collections::HashMap;
use std::sync::Arc;

use crate::node::options::NodeRole;
use crate::packet::Packet;
use crate::peer_score::{total_score, PeerScoreStore, PeerScoreWeights};
use crate::protocol::control::NetworkControlPayload;
use crate::router::Router;
use crate::sessions::Session;
use crate::topology::{select_peers_for_discovery_response, NodeDescriptor, PeerCatalog};
use crate::types::{PeerId, SessionId};

pub const REGULAR_BOOTSTRAP_DIAL_QUOTA: usize = 3;
pub const INCOMING_ROTATION_INTERVAL_MS: u64 = 1_500;
pub const BOOTSTRAP_INCOMING_HEADROOM: usize = 3;
pub const REGULAR_INCOMING_RESERVE_SLOTS: usize = 0;
pub const BOOTSTRAP_INCOMING_RESERVE_SLOTS: usize = 1;
pub const BOOTSTRAP_RESEED_INTERVAL_MS: u64 = 12_000;
const OVERLOAD_REDIRECT_LIMIT: usize = 24;
const DIAL_HUB_PRESSURE_PENALTY: f32 = 0.10;
const DIAL_SATURATION_PENALTY: f32 = 2.0;
const DIAL_NO_DESCRIPTOR_PENALTY: f32 = 0.25;
const DIAL_BOOTSTRAP_RECOVERY_BONUS: f32 = 1.25;

pub fn rank_dial_candidates(
    candidates: &mut [PeerId],
    peer_store: &PeerScoreStore,
    weights: &PeerScoreWeights,
    desc_by_peer: &HashMap<PeerId, NodeDescriptor>,
    local_peer_id: &str,
    node_role: NodeRole,
    dial_target: usize,
    connected_bootstrap: usize,
    bootstrap_quota: usize,
) {
    candidates.sort_by(|a, b| {
        let sa = dial_candidate_score(
            a,
            peer_store,
            weights,
            desc_by_peer,
            local_peer_id,
            node_role,
            dial_target,
            connected_bootstrap,
            bootstrap_quota,
        );
        let sb = dial_candidate_score(
            b,
            peer_store,
            weights,
            desc_by_peer,
            local_peer_id,
            node_role,
            dial_target,
            connected_bootstrap,
            bootstrap_quota,
        );
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });
}

pub fn should_skip_for_bootstrap_quota(
    desc: &NodeDescriptor,
    node_role: NodeRole,
    connected_bootstrap: usize,
    bootstrap_quota: usize,
    current_peers: usize,
    min_active_peers: usize,
) -> bool {
    matches!(node_role, NodeRole::Regular)
        && desc.capabilities.bootstrap_entry
        && connected_bootstrap >= bootstrap_quota
        && current_peers >= min_active_peers
}

pub fn bootstrap_dial_quota(node_role: NodeRole) -> usize {
    if matches!(node_role, NodeRole::Regular) {
        REGULAR_BOOTSTRAP_DIAL_QUOTA
    } else {
        usize::MAX
    }
}

pub fn dial_reserve_slots(node_role: NodeRole) -> usize {
    if matches!(node_role, NodeRole::BootstrapJoin) {
        BOOTSTRAP_INCOMING_RESERVE_SLOTS
    } else {
        REGULAR_INCOMING_RESERVE_SLOTS
    }
}

pub fn should_reseed_bootstrap(
    active_peers: usize,
    min_active_peers: usize,
    connected_bootstrap: usize,
    now_ms: u64,
    last_reseed_ms: u64,
) -> bool {
    let low_connectivity = active_peers == 0 || (active_peers < min_active_peers && connected_bootstrap == 0);
    low_connectivity && now_ms.saturating_sub(last_reseed_ms) >= BOOTSTRAP_RESEED_INTERVAL_MS
}

pub fn peers_to_drop_when_overloaded(
    connected: Vec<PeerId>,
    drop_n: usize,
    catalog: &PeerCatalog,
    peer_store: &PeerScoreStore,
    weights: &PeerScoreWeights,
    node_role: NodeRole,
) -> Vec<PeerId> {
    if drop_n == 0 || connected.is_empty() {
        return vec![];
    }
    let score = |p: &PeerId| total_score(&peer_store.get(p), weights);
    let mut boot: Vec<_> = connected
        .iter()
        .filter(|p| catalog.peer_is_bootstrap_entry(p))
        .cloned()
        .collect();
    let mut regular: Vec<_> = connected
        .iter()
        .filter(|p| !catalog.peer_is_bootstrap_entry(p))
        .cloned()
        .collect();
    boot.sort_by(|a, b| {
        score(a)
            .partial_cmp(&score(b))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    regular.sort_by(|a, b| {
        score(a)
            .partial_cmp(&score(b))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let ordered: Vec<PeerId> = match node_role {
        NodeRole::Regular => boot.into_iter().chain(regular.into_iter()).collect(),
        NodeRole::BootstrapJoin => regular.into_iter().chain(boot.into_iter()).collect(),
    };
    ordered.into_iter().take(drop_n).collect()
}

pub async fn send_discovery_redirect_and_close(
    router: &Arc<Router>,
    session: Arc<dyn Session>,
    session_id: &SessionId,
    newcomer: &PeerId,
    our_peer_id: &str,
    catalog: &PeerCatalog,
    random_fraction: f32,
) {
    router.register_session_only(session_id.clone(), session);
    let descriptors = select_peers_for_discovery_response(
        catalog
            .descriptors()
            .into_iter()
            .filter(|d| d.peer_id != newcomer.as_str())
            .filter(|d| d.dynamic_status.accepts_new_sessions || d.capabilities.bootstrap_entry)
            .collect(),
        Some(newcomer.as_str()),
        OVERLOAD_REDIRECT_LIMIT,
        random_fraction,
    );
    if !descriptors.is_empty() {
        let msg = NetworkControlPayload::PeersResponse { descriptors };
        if let Ok(data) = msg.encode() {
            let packet = Packet {
                signature: None,
                data,
                nodes: vec![],
                sender: our_peer_id.to_string(),
                receiver: newcomer.as_str().to_string(),
                max_hops: 2,
                chunk_stream_id: None,
                chunk_index: None,
                total_chunks: None,
            };
            let _ = router.send_to_session(session_id.clone(), packet).await;
        }
    }
    let _ = router.teardown_session(session_id).await;
}

fn dial_candidate_score(
    pid: &PeerId,
    peer_store: &PeerScoreStore,
    weights: &PeerScoreWeights,
    desc_by_peer: &HashMap<PeerId, NodeDescriptor>,
    local_peer_id: &str,
    node_role: NodeRole,
    dial_target: usize,
    connected_bootstrap: usize,
    bootstrap_quota: usize,
) -> f32 {
    let mut score = total_score(&peer_store.get(pid), weights);
    let Some(desc) = desc_by_peer.get(pid) else {
        return score - DIAL_NO_DESCRIPTOR_PENALTY;
    };

    let cap = desc.capabilities.base_session_limit.max(1) as f32;
    let utilization = (desc.dynamic_status.active_connections as f32 / cap).max(0.0);
    score -= utilization * DIAL_SATURATION_PENALTY;

    let over_target = (desc.dynamic_status.active_connections as f32 - dial_target as f32).max(0.0);
    score -= over_target * DIAL_HUB_PRESSURE_PENALTY;

    if !desc.dynamic_status.accepts_new_sessions && !desc.capabilities.bootstrap_entry {
        score -= 10.0;
    }
    if desc.capabilities.bootstrap_entry && matches!(node_role, NodeRole::Regular) {
        score -= 0.35;
        if connected_bootstrap == 0 {
            score += DIAL_BOOTSTRAP_RECOVERY_BONUS;
        }
        if connected_bootstrap >= bootstrap_quota {
            score -= 2.5;
        }
    }

    score += diversity_jitter(local_peer_id, pid.as_str(), 0.12);

    score
}

fn diversity_jitter(local_peer_id: &str, candidate_peer_id: &str, amplitude: f32) -> f32 {
    let mut h: u32 = 0x811C9DC5;
    for b in local_peer_id
        .as_bytes()
        .iter()
        .chain(candidate_peer_id.as_bytes().iter())
    {
        h ^= u32::from(*b);
        h = h.wrapping_mul(16777619);
    }
    let norm = (h as f32) / (u32::MAX as f32);
    (norm * 2.0 - 1.0) * amplitude
}

