use std::cmp::Ordering;
use std::collections::HashSet;

use rand::seq::SliceRandom;

use super::NodeDescriptor;

pub fn descriptor_ok_for_discovery_redirect(desc: &NodeDescriptor) -> bool {
    if desc.capabilities.bootstrap_entry {
        return true;
    }
    if desc.dynamic_status.accepts_new_sessions {
        return true;
    }
    let cap = desc.capabilities.base_session_limit.max(1) as u32;
    (desc.dynamic_status.active_connections as u32) < cap.saturating_sub(1)
}

pub fn select_peers_for_discovery_response(
    mut descriptors: Vec<NodeDescriptor>,
    exclude_peer_id: Option<&str>,
    limit: usize,
    random_fraction: f32,
) -> Vec<NodeDescriptor> {
    let lim = limit.clamp(1, 64);
    if let Some(ex) = exclude_peer_id {
        descriptors.retain(|d| d.peer_id != ex);
    }
    if descriptors.len() <= lim {
        return descriptors;
    }
    let rf = random_fraction.clamp(0.0, 0.9);
    let n_random = ((lim as f32) * rf).round() as usize;
    let n_random = n_random.min(lim.saturating_sub(1));
    let n_sorted = lim - n_random;
    let requester = exclude_peer_id.unwrap_or_default();

    descriptors.sort_by(|a, b| {
        let sa = discovery_descriptor_score(a, requester);
        let sb = discovery_descriptor_score(b, requester);
        sb.partial_cmp(&sa)
            .unwrap_or(Ordering::Equal)
            .then_with(|| b.version.cmp(&a.version))
            .then_with(|| b.timestamp_ms.cmp(&a.timestamp_ms))
    });

    let max_bootstrap_in_sorted = (n_sorted / 3).clamp(1, 3);
    let mut out: Vec<NodeDescriptor> = Vec::with_capacity(lim);
    let mut picked: HashSet<String> = HashSet::new();
    let mut bootstrap_picked = 0usize;

    for d in descriptors.iter().cloned() {
        if out.len() >= n_sorted {
            break;
        }
        if picked.contains(&d.peer_id) {
            continue;
        }
        if d.capabilities.bootstrap_entry {
            if bootstrap_picked >= max_bootstrap_in_sorted {
                continue;
            }
            bootstrap_picked += 1;
        }
        picked.insert(d.peer_id.clone());
        out.push(d);
    }
    if out.len() < n_sorted {
        for d in descriptors.iter().cloned() {
            if out.len() >= n_sorted {
                break;
            }
            if picked.contains(&d.peer_id) {
                continue;
            }
            picked.insert(d.peer_id.clone());
            out.push(d);
        }
    }

    let mut rest: Vec<NodeDescriptor> = descriptors
        .into_iter()
        .filter(|d| !picked.contains(&d.peer_id))
        .collect();
    let mut rng = rand::rng();
    rest.shuffle(&mut rng);
    for d in rest {
        if out.len() >= lim {
            break;
        }
        if picked.insert(d.peer_id.clone()) {
            out.push(d);
        }
    }
    out
}

fn discovery_descriptor_score(desc: &NodeDescriptor, requester_peer_id: &str) -> f32 {
    let cap = desc.capabilities.base_session_limit.max(1) as f32;
    let util = (desc.dynamic_status.active_connections as f32 / cap).clamp(0.0, 1.5);
    let mut score = 0.0;
    if desc.dynamic_status.accepts_new_sessions {
        score += 1.0;
    }
    score += (1.0 - util.min(1.0)) * 1.55;
    if !desc.capabilities.bootstrap_entry {
        score += 0.5;
    }
    if desc.capabilities.bootstrap_entry {
        score += 0.08;
    }
    let hub_excess = (desc.dynamic_status.active_connections as f32 - 6.0).max(0.0);
    score -= hub_excess * 0.11;
    if desc.capabilities.bootstrap_entry && desc.dynamic_status.active_connections >= 14 {
        score -= 0.35;
    }
    score + discovery_jitter(requester_peer_id, &desc.peer_id, 0.28)
}

fn discovery_jitter(requester_peer_id: &str, candidate_peer_id: &str, amplitude: f32) -> f32 {
    let mut h: u32 = 0x811C9DC5;
    for b in requester_peer_id
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
