use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dashmap::DashMap;

use crate::db::P2PDatabase;
use crate::metrics::contract::AggregatedMetricsSnapshot;
use crate::node::addressing::advertised_addr_for_protocol;
use crate::node::options::NodeRole;
use crate::peer_score::PeerConnectionPolicy;
use crate::protocol::control::NetworkControlPayload;
use crate::router::Router;
use crate::topology::{
    NodeCapabilities, NodeDescriptor, NodeDynamicStatus, PeerCatalog, sign_descriptor,
};
use crate::transport::Transport;

use super::packet_helpers::control_packet;

#[allow(clippy::too_many_arguments)]
pub(super) async fn publish_descriptor_if_due(
    now: u64,
    last_publish: u64,
    descriptor_interval: Duration,
    descriptor_ttl_secs: u64,
    descriptor_ver: &Arc<AtomicU64>,
    transports_maint: &[Arc<dyn Transport>],
    listens: &DashMap<String, SocketAddr>,
    advertise_addrs: &HashMap<String, SocketAddr>,
    advertise_fallback_ip: Option<IpAddr>,
    node_role: NodeRole,
    adaptive: &PeerConnectionPolicy,
    metrics: &AggregatedMetricsSnapshot,
    n: usize,
    our_peer_maint: &str,
    signing_key: &k256::ecdsa::SigningKey,
    catalog: &Arc<PeerCatalog>,
    db: &Option<Arc<P2PDatabase>>,
    router_maint: &Arc<Router>,
) -> u64 {
    if now.saturating_sub(last_publish) < descriptor_interval.as_millis() as u64 {
        return last_publish;
    }
    let version = descriptor_ver.fetch_add(1, Ordering::Relaxed) + 1;
    let mut srflx_by_proto: HashMap<String, SocketAddr> = HashMap::new();
    for transport in transports_maint {
        if !transport.supports_tunneling() {
            continue;
        }
        let proto = transport.name().to_string();
        let Some(listen_addr) = listens.get(&proto).map(|r| *r.value()) else {
            continue;
        };
        match transport.get_public_address(listen_addr.port()).await {
            Ok(public) => {
                if let Ok(ip) = public.ip.parse::<IpAddr>() {
                    srflx_by_proto.insert(proto, SocketAddr::new(ip, public.port));
                }
            }
            Err(e) => {
                crate::debug!(
                    "[NodeRuntime] STUN unavailable for {}:{}: {}",
                    proto,
                    listen_addr.port(),
                    e
                );
            }
        }
    }
    let mut proto_list: Vec<(String, SocketAddr)> = listens
        .iter()
        .map(|r| {
            let proto = r.key().clone();
            let advertised = advertised_addr_for_protocol(
                &proto,
                *r.value(),
                advertise_addrs,
                advertise_fallback_ip,
            );
            (proto, advertised)
        })
        .collect();
    proto_list.sort_by(|a, b| a.0.cmp(&b.0));
    let mut observed_addrs: Vec<String> = proto_list
        .into_iter()
        .map(|(p, a)| format!("{}:{}", p.to_lowercase(), a))
        .collect();
    for (proto, addr) in srflx_by_proto {
        observed_addrs.push(format!("{}:{}", proto.to_lowercase(), addr));
    }
    observed_addrs.sort();
    observed_addrs.dedup();
    let mut caps = NodeCapabilities::default();
    if matches!(node_role, NodeRole::BootstrapJoin) {
        caps.bootstrap_entry = true;
    }
    let base_cap = adaptive
        .max_active_peers
        .max(caps.base_session_limit as usize)
        .min(u16::MAX as usize) as u16;
    let load = metrics
        .node
        .cpu_load_estimate
        .max(metrics.node.memory_pressure_estimate)
        .clamp(0.0, 1.0);
    let pressure_factor = (1.0 - ((load - 0.5).max(0.0) * 2.0)).clamp(0.3, 1.0);
    let effective_cap = (((base_cap as f32) * pressure_factor).round() as u16).max(4);
    caps.base_session_limit = effective_cap;
    let descriptor = NodeDescriptor::new_unsigned(
        our_peer_maint.to_string(),
        caps,
        {
            let mut s = NodeDynamicStatus::from(&metrics.node);
            s.accepts_new_sessions = n < adaptive.max_active_peers && pressure_factor >= 0.5;
            s
        },
        observed_addrs,
        descriptor_ttl_secs,
        version,
    );
    let mut descriptor = descriptor;
    if sign_descriptor(&mut descriptor, signing_key).is_ok() {
        let _ = catalog.upsert_descriptor(descriptor.clone());
        if let Some(db) = db.as_ref() {
            let _ = db.upsert_peer_descriptor(&descriptor);
        }
        let msg = NetworkControlPayload::AnnounceNodeDescriptor { descriptor };
        if let Ok(data) = msg.encode() {
            for p in router_maint.connected_peers() {
                let packet =
                    control_packet(our_peer_maint, p.as_str().to_string(), data.clone(), 2);
                let _ = router_maint.send_to_peer(p, packet, None).await;
            }
        }
    }
    now
}
