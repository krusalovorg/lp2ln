use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::node::options::{BootstrapNode, TopologyTuning};
use crate::protocol::control::NetworkControlPayload;
use crate::router::Router;
use crate::sessions::manager::SessionManager;
use crate::sessions::session::IncomingPacket;
use crate::topology::{
    PeerCatalog, descriptor_ok_for_discovery_redirect, select_peers_for_discovery_response,
};
use crate::transport::Transport;
use crate::types::PeerId;

use super::packet_helpers::control_packet;
use super::policy::AdaptiveTickPolicy;
use super::{
    BootstrapDialDedupe, SHEPHERD_FINAL_PEERS_LIMIT, SHEPHERD_GRACE_MS, SHEPHERD_MIN_MESH,
    SHEPHERD_SKIP_IF_CONNECTED_AT_MOST, SHEPHERD_SWEEP_INTERVAL_MS, dial_bootstrap_address,
};
use crate::node::options::NodeRole;

fn bootstrap_identity(target: &BootstrapNode) -> String {
    if let Some(hint) = target.peer_id_hint.as_ref() {
        hint.as_str().to_string()
    } else {
        target.addr.to_string()
    }
}

fn rank_bootstrap_targets_for_peer(
    local_peer_id: &str,
    targets: &[BootstrapNode],
) -> Vec<BootstrapNode> {
    let mut weighted: Vec<(u64, BootstrapNode)> = targets
        .iter()
        .cloned()
        .map(|t| {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            local_peer_id.hash(&mut hasher);
            bootstrap_identity(&t).hash(&mut hasher);
            (hasher.finish(), t)
        })
        .collect();
    weighted.sort_by(|a, b| b.0.cmp(&a.0));
    weighted.into_iter().map(|(_, t)| t).collect()
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_bootstrap_reseed(
    reseed_for_low: bool,
    reseed_for_bridge: bool,
    n: usize,
    adaptive_min_active_peers: usize,
    connected_bootstrap_now: usize,
    bootstrap_targets_maint: &[BootstrapNode],
    our_peer_maint: &str,
    topology_tuning: &TopologyTuning,
    bootstrap_deny_until: &mut HashMap<SocketAddr, u64>,
    now: u64,
    adaptive_tick: &AdaptiveTickPolicy,
    transports_maint: &[Arc<dyn Transport>],
    router_maint: &Arc<Router>,
    incoming_maint: &tokio::sync::mpsc::Sender<IncomingPacket>,
    maintenance_handshake_payload: &[u8],
    bootstrap_dial_dedupe: &Arc<Mutex<HashSet<(String, SocketAddr)>>>,
    bootstrap_dial_ok_ms: &Arc<Mutex<HashMap<SocketAddr, u64>>>,
) -> bool {
    if bootstrap_targets_maint.is_empty() || !(reseed_for_low || reseed_for_bridge) {
        return false;
    }
    crate::debug!(
        "[NodeRuntime] bootstrap reseed: active={} min={} boot-connected={} targets={} reason={}",
        n,
        adaptive_min_active_peers,
        connected_bootstrap_now,
        bootstrap_targets_maint.len(),
        if reseed_for_low {
            "low-connectivity"
        } else {
            "bridge-rejoin"
        }
    );
    let max_reseed_targets = if reseed_for_low {
        bootstrap_targets_maint.len()
    } else {
        1
    };
    let ranked_targets = rank_bootstrap_targets_for_peer(our_peer_maint, bootstrap_targets_maint);
    let mut attempted = 0usize;
    let top_k = topology_tuning
        .adaptive_bootstrap_top_k
        .max(1)
        .min(ranked_targets.len());
    for target in ranked_targets.into_iter().take(top_k) {
        if attempted >= max_reseed_targets {
            break;
        }
        if bootstrap_deny_until
            .get(&target.addr)
            .is_some_and(|until| now < *until)
        {
            continue;
        }
        attempted = attempted.saturating_add(1);
        let dedupe_ctx = BootstrapDialDedupe {
            active_peers: n,
            set: bootstrap_dial_dedupe.clone(),
        };
        let ok = dial_bootstrap_address(
            transports_maint,
            router_maint,
            incoming_maint,
            our_peer_maint,
            &target,
            maintenance_handshake_payload,
            Some(&dedupe_ctx),
            Some((bootstrap_dial_ok_ms, now)),
        )
        .await;
        if ok {
            bootstrap_deny_until.remove(&target.addr);
        } else {
            bootstrap_deny_until.insert(
                target.addr,
                now.saturating_add(adaptive_tick.bridge_rejoin_cooldown_ms),
            );
        }
    }
    true
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_bootstrap_shepherd(
    node_role: NodeRole,
    now: u64,
    last_shepherd_sweep_ms: u64,
    router_maint: &Arc<Router>,
    sm: &Arc<SessionManager>,
    catalog: &Arc<PeerCatalog>,
    peer_admission_ms: &mut HashMap<PeerId, u64>,
    our_peer_maint: &str,
) -> (bool, usize) {
    if !matches!(node_role, NodeRole::BootstrapJoin)
        || now.saturating_sub(last_shepherd_sweep_ms) < SHEPHERD_SWEEP_INTERVAL_MS
    {
        return (false, 0);
    }
    let connected = router_maint.connected_peers();
    for pid in connected.iter() {
        peer_admission_ms.entry(pid.clone()).or_insert(now);
    }
    if connected.len() <= SHEPHERD_SKIP_IF_CONNECTED_AT_MOST {
        return (true, 0);
    }
    let tracked: Vec<PeerId> = peer_admission_ms.keys().cloned().collect();
    for pid in tracked {
        if !sm.is_connected_to_peer(&pid) {
            peer_admission_ms.remove(&pid);
        }
    }
    let mut shepherded = 0usize;
    for pid in connected.iter() {
        if catalog.peer_is_bootstrap_entry(pid) {
            continue;
        }
        let Some(admitted_at) = peer_admission_ms.get(pid).copied() else {
            continue;
        };
        if now.saturating_sub(admitted_at) < SHEPHERD_GRACE_MS {
            continue;
        }
        let Some(desc) = catalog.descriptor_of(pid) else {
            continue;
        };
        let peer_mesh_size = desc.dynamic_status.active_connections.saturating_sub(1);
        if peer_mesh_size < SHEPHERD_MIN_MESH {
            continue;
        }
        let descriptors = select_peers_for_discovery_response(
            catalog
                .descriptors()
                .into_iter()
                .filter(|d| d.peer_id != pid.as_str())
                .filter(descriptor_ok_for_discovery_redirect)
                .collect(),
            Some(pid.as_str()),
            SHEPHERD_FINAL_PEERS_LIMIT,
            0.4,
        );
        if !descriptors.is_empty() {
            let msg = NetworkControlPayload::PeersResponse { descriptors };
            if let Ok(data) = msg.encode() {
                let packet = control_packet(our_peer_maint, pid.as_str().to_string(), data, 2);
                let _ = router_maint.send_to_peer(pid.clone(), packet, None).await;
            }
        }
        let _ = sm.close_all_sessions_for_peer(pid).await;
        peer_admission_ms.remove(pid);
        shepherded += 1;
    }
    if shepherded > 0 {
        crate::info!(
            "[NodeRuntime] shepherd sweep: closed {} settled peer(s) to free bootstrap slot",
            shepherded
        );
    }
    (true, shepherded)
}
