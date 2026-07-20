//! Local seed address book: known endpoints from config, not a network role.
//!
//! A peer is a "seed" for *this* node when it matches `bootstrap_nodes`
//! (addr / peer_id_hint / advertised observed addrs). That is independent of
//! `capabilities.bootstrap_entry` on the wire.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use dashmap::DashMap;

use crate::node::options::BootstrapNode;
use crate::topology::{NodeDescriptor, PeerCatalog, parse_observed_addr_line};
use crate::types::PeerId;

/// True when `pid` matches a local seed target via hint, dial_book addr, or
/// catalog descriptor observed addresses. Falls back to `bootstrap_entry` only
/// when no seed targets are configured (legacy peers).
pub fn is_local_seed_peer(
    pid: &PeerId,
    catalog: &PeerCatalog,
    dial_book: &DashMap<PeerId, Vec<(String, SocketAddr)>>,
    seed_targets: &[BootstrapNode],
) -> bool {
    if seed_targets.is_empty() {
        return catalog.peer_is_bootstrap_entry(pid);
    }
    if seed_targets
        .iter()
        .any(|t| t.peer_id_hint.as_ref() == Some(pid))
    {
        return true;
    }
    if let Some(desc) = catalog.descriptor_of(pid) {
        if seed_targets
            .iter()
            .any(|t| descriptor_announces_seed_target(&desc, t))
        {
            return true;
        }
    }
    if let Some(entry) = dial_book.get(pid) {
        return seed_targets.iter().any(|t| {
            entry.value().iter().any(|(proto, addr)| {
                *addr == t.addr
                    && (t.protocols.is_empty()
                        || t.protocols.iter().any(|tp| tp.eq_ignore_ascii_case(proto)))
            })
        });
    }
    false
}

pub fn descriptor_announces_seed_target(desc: &NodeDescriptor, t: &BootstrapNode) -> bool {
    desc.observed_addrs.iter().any(|line| {
        parse_observed_addr_line(line).is_some_and(|(proto, addr)| {
            addr == t.addr
                && (t.protocols.is_empty()
                    || t.protocols.iter().any(|tp| tp.eq_ignore_ascii_case(&proto)))
        })
    })
}

/// Count connected peers that match the local seed book.
pub fn connected_seed_count(
    connected: &[PeerId],
    catalog: &PeerCatalog,
    seed_targets: &[BootstrapNode],
    dial_book: &DashMap<PeerId, Vec<(String, SocketAddr)>>,
) -> usize {
    let mut seen: HashSet<PeerId> = HashSet::new();
    for p in connected {
        if is_local_seed_peer(p, catalog, dial_book, seed_targets) {
            seen.insert(p.clone());
        }
    }
    seen.len()
}

/// Convenience wrapper matching older call sites that also had recent-dial fallback.
pub fn connected_seed_count_with_recent(
    connected: &[PeerId],
    catalog: &PeerCatalog,
    seed_targets: &[BootstrapNode],
    dial_book: &DashMap<PeerId, Vec<(String, SocketAddr)>>,
    recent_dial_ok: &std::collections::HashMap<SocketAddr, u64>,
    now: u64,
    recent_ttl_ms: u64,
) -> usize {
    let n = connected_seed_count(connected, catalog, seed_targets, dial_book);
    if n > 0 {
        return n;
    }
    let any_recent = seed_targets.iter().any(|t| {
        recent_dial_ok
            .get(&t.addr)
            .copied()
            .map(|ts| now.saturating_sub(ts) < recent_ttl_ms)
            .unwrap_or(false)
    });
    if any_recent { 1 } else { 0 }
}

/// Seed peer ids known from catalog descriptors matching the local book
/// (plus legacy `bootstrap_entry` when book is empty).
pub fn seed_peer_ids_from_catalog(
    catalog: &PeerCatalog,
    seed_targets: &[BootstrapNode],
) -> HashSet<PeerId> {
    let descriptors = catalog.descriptors();
    if seed_targets.is_empty() {
        return descriptors
            .iter()
            .filter(|d| d.capabilities.bootstrap_entry)
            .map(|d| PeerId::from(d.peer_id.as_str()))
            .collect();
    }
    let mut out = HashSet::new();
    for d in &descriptors {
        let pid = PeerId::from(d.peer_id.as_str());
        if seed_targets
            .iter()
            .any(|t| t.peer_id_hint.as_ref() == Some(&pid))
            || seed_targets
                .iter()
                .any(|t| descriptor_announces_seed_target(d, t))
        {
            out.insert(pid);
        }
    }
    out
}

/// Least-loaded accepting peers for redirect preamble (role-agnostic).
pub fn less_loaded_peer_descriptors(
    catalog: &PeerCatalog,
    our_peer_id: &str,
    our_active_connections: u16,
    exclude_peer_id: &str,
    recent_hints: &std::collections::HashMap<String, u32>,
    limit: usize,
) -> Vec<NodeDescriptor> {
    use crate::topology::descriptor_ok_for_discovery_redirect;
    let mut candidates: Vec<_> = catalog
        .descriptors()
        .into_iter()
        .filter(|d| d.peer_id != our_peer_id && d.peer_id != exclude_peer_id)
        .filter(|d| d.dynamic_status.active_connections < our_active_connections)
        .filter(descriptor_ok_for_discovery_redirect)
        .collect();
    candidates.sort_by_key(|d| {
        (
            *recent_hints.get(&d.peer_id).unwrap_or(&0),
            d.dynamic_status.active_connections,
        )
    });
    candidates.truncate(limit);
    candidates
}

/// /24 (IPv4) or /64 (IPv6) subnet key for inbound rate limiting.
pub fn inbound_subnet_key(addr: SocketAddr) -> (IpAddr, u8) {
    match addr.ip() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (IpAddr::V4(std::net::Ipv4Addr::new(o[0], o[1], o[2], 0)), 24)
        }
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            for b in o[8..].iter_mut() {
                *b = 0;
            }
            (IpAddr::V6(std::net::Ipv6Addr::from(o)), 64)
        }
    }
}

#[derive(Debug, Clone)]
pub struct InboundRateSlot {
    pub window_start_ms: u64,
    pub count: u32,
}

impl InboundRateSlot {
    pub fn allow(&mut self, now_ms: u64, max_per_sec: u32) -> bool {
        if now_ms.saturating_sub(self.window_start_ms) >= 1_000 {
            self.window_start_ms = now_ms;
            self.count = 0;
        }
        self.count = self.count.saturating_add(1);
        self.count <= max_per_sec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn subnet_key_masks_v4_to_24() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 99), 22000));
        let (ip, prefix) = inbound_subnet_key(addr);
        assert_eq!(prefix, 24);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 1, 2, 0)));
    }
}
