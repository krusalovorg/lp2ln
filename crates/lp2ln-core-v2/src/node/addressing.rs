use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

use crate::node::options::{BootstrapNode, NodeOptions};
use crate::peer_score::{total_score, PeerScoreStore};

pub fn ordered_bootstrap_targets(options: &NodeOptions, peer_scores: &PeerScoreStore) -> Vec<BootstrapNode> {
    let mut targets = if options.bootstrap_nodes.is_empty() {
        options
            .default_nodes
            .iter()
            .copied()
            .map(|addr| BootstrapNode {
                addr,
                protocols: vec!["tcp".to_string(), "udp".to_string()],
                peer_id_hint: options.bootstrap_peer_hints.get(&addr).cloned(),
            })
            .collect::<Vec<_>>()
    } else {
        options.bootstrap_nodes.clone()
    };

    let hints = &options.bootstrap_peer_hints;
    let weights = &options.peer_score_weights;
    targets.sort_by(|a, b| {
        let pa = a.peer_id_hint.as_ref().or_else(|| hints.get(&a.addr));
        let pb = b.peer_id_hint.as_ref().or_else(|| hints.get(&b.addr));
        let ta = pa
            .map(|p| total_score(&peer_scores.get(p), weights))
            .unwrap_or(f32::MIN);
        let tb = pb
            .map(|p| total_score(&peer_scores.get(p), weights))
            .unwrap_or(f32::MIN);
        tb.partial_cmp(&ta).unwrap_or(std::cmp::Ordering::Equal)
    });
    targets
}

pub fn detect_lan_advertise_ip(
    bootstrap_targets: &[BootstrapNode],
    default_nodes: &[SocketAddr],
) -> Option<IpAddr> {
    let mut probes: Vec<SocketAddr> = bootstrap_targets.iter().map(|n| n.addr).collect();
    probes.extend(default_nodes.iter().copied());
    probes.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53));
    probes.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));

    for remote in probes {
        let bind_addr = if remote.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let Ok(sock) = UdpSocket::bind(bind_addr) else {
            continue;
        };
        if sock.connect(remote).is_err() {
            continue;
        }
        let Ok(local) = sock.local_addr() else {
            continue;
        };
        let ip = local.ip();
        if !ip.is_unspecified() && !ip.is_loopback() {
            return Some(ip);
        }
    }
    None
}

pub fn advertised_addr_for_protocol(
    protocol: &str,
    listen_addr: SocketAddr,
    advertise_addrs: &HashMap<String, SocketAddr>,
    fallback_ip: Option<IpAddr>,
) -> SocketAddr {
    if let Some(addr) = advertise_addrs.get(protocol) {
        return *addr;
    }
    if listen_addr.ip().is_unspecified() || listen_addr.ip().is_loopback() {
        if let Some(ip) = fallback_ip {
            return SocketAddr::new(ip, listen_addr.port());
        }
    }
    listen_addr
}
