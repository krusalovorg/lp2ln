use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use dashmap::DashMap;

use crate::topology::{PeerCatalog, parse_observed_addr_line};
use crate::types::PeerId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddrRankTier {
    Explicit,
    LanPreferred,
    GlobalRoutable,
    OtherObserved,
}

fn ipv4_private(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified()
}

fn is_global_ipv4(ip: Ipv4Addr) -> bool {
    !ipv4_private(ip) && !ip.is_broadcast() && !ip.is_documentation()
}

fn same_slash24(a: Ipv4Addr, b: Ipv4Addr) -> bool {
    let oa = a.octets();
    let ob = b.octets();
    oa[0] == ob[0] && oa[1] == ob[1] && oa[2] == ob[2]
}

fn local_ipv4s(
    listens: &HashMap<String, SocketAddr>,
    advertise: &HashMap<String, SocketAddr>,
) -> Vec<Ipv4Addr> {
    let mut v = Vec::new();
    for a in listens.values().chain(advertise.values()) {
        if let IpAddr::V4(ip) = a.ip() {
            v.push(ip);
        }
    }
    v.sort_unstable();
    v.dedup();
    v
}

fn our_listen_socket_set(
    listens: &HashMap<String, SocketAddr>,
    advertise: &HashMap<String, SocketAddr>,
) -> HashSet<SocketAddr> {
    listens
        .values()
        .chain(advertise.values())
        .copied()
        .collect()
}

fn lan_match_score(addr: SocketAddr, locals: &[Ipv4Addr]) -> u8 {
    let IpAddr::V4(ip) = addr.ip() else {
        return 0;
    };
    if !ip.is_private() {
        return 0;
    }
    for l in locals {
        if same_slash24(ip, *l) {
            return 2;
        }
        if ip.is_private() && l.is_private() {
            return 1;
        }
    }
    u8::from(ip.is_private())
}

fn tier_for_observed(addr: SocketAddr, prefer_lan: bool, locals: &[Ipv4Addr]) -> AddrRankTier {
    let IpAddr::V4(ip) = addr.ip() else {
        return AddrRankTier::GlobalRoutable;
    };
    if is_global_ipv4(ip) {
        AddrRankTier::GlobalRoutable
    } else if prefer_lan && (lan_match_score(addr, locals) >= 2 || ip.is_private()) {
        AddrRankTier::LanPreferred
    } else {
        AddrRankTier::OtherObserved
    }
}

/// Sort key: lower sorts first (dial earlier).
/// With `prefer_lan_addrs`: explicit → LAN → global → other.
/// Without: explicit → global → LAN → other.
fn dial_sort_rank(tier: AddrRankTier, prefer_lan: bool) -> u8 {
    if prefer_lan {
        match tier {
            AddrRankTier::Explicit => 0,
            AddrRankTier::LanPreferred => 1,
            AddrRankTier::GlobalRoutable => 2,
            AddrRankTier::OtherObserved => 3,
        }
    } else {
        match tier {
            AddrRankTier::Explicit => 0,
            AddrRankTier::GlobalRoutable => 1,
            AddrRankTier::LanPreferred => 2,
            AddrRankTier::OtherObserved => 3,
        }
    }
}

pub fn ranked_dial_targets(
    peer_id: &PeerId,
    our_peer_id: &str,
    catalog: &PeerCatalog,
    dial_book: &DashMap<PeerId, Vec<(String, SocketAddr)>>,
    listens: &HashMap<String, SocketAddr>,
    advertise: &HashMap<String, SocketAddr>,
    prefer_lan_addrs: bool,
) -> Vec<(String, SocketAddr)> {
    if peer_id.as_str() == our_peer_id {
        return Vec::new();
    }

    let locals = local_ipv4s(listens, advertise);
    let our_sockets = our_listen_socket_set(listens, advertise);

    let mut out: Vec<(u8, String, SocketAddr)> = Vec::new();

    if let Some(entry) = dial_book.get(peer_id) {
        for (t, a) in entry.iter() {
            if our_sockets.contains(a) {
                continue;
            }
            let rank = dial_sort_rank(AddrRankTier::Explicit, prefer_lan_addrs);
            out.push((rank, t.clone(), *a));
        }
    }

    if let Some(desc) = catalog.descriptor_of(peer_id) {
        for line in &desc.observed_addrs {
            let Some((t, a)) = parse_observed_addr_line(line) else {
                continue;
            };
            if our_sockets.contains(&a) {
                continue;
            }
            let tier = tier_for_observed(a, prefer_lan_addrs, &locals);
            let rank = dial_sort_rank(tier, prefer_lan_addrs);
            out.push((rank, t, a));
        }
    }

    out.sort_by(|a, b| (a.0, &a.1, a.2).cmp(&(b.0, &b.1, b.2)));

    let mut seen = HashSet::new();
    let mut dedup = Vec::new();
    for (_, t, a) in out {
        let k = (t.clone(), a);
        if seen.insert(k.clone()) {
            dedup.push(k);
        }
    }
    dedup
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::PeerCatalog;
    use crate::types::PeerId;
    use std::str::FromStr;

    #[test]
    fn ranked_returns_dial_book_when_catalog_empty() {
        let cat = PeerCatalog::new();
        let dial = DashMap::new();
        let p = PeerId::from("peer-a");
        let a = SocketAddr::from_str("192.0.2.1:9000").unwrap();
        dial.insert(p.clone(), vec![("tcp".into(), a)]);
        let r = ranked_dial_targets(
            &p,
            "self",
            &cat,
            &dial,
            &HashMap::new(),
            &HashMap::new(),
            false,
        );
        assert_eq!(r, vec![("tcp".into(), a)]);
    }

    #[test]
    fn prefer_lan_orders_private_before_global() {
        let cat = PeerCatalog::new();
        let dial = DashMap::new();
        let peer_kp = crate::crypto::NodeKeypair::generate();
        let remote = PeerId::from_str(peer_kp.peer_id());
        let mut desc = crate::topology::NodeDescriptor::new_unsigned(
            remote.as_str(),
            crate::topology::NodeCapabilities::default(),
            crate::topology::NodeDynamicStatus::default(),
            vec![
                "tcp:198.51.100.10:9001".to_string(),
                "tcp:192.168.1.50:9002".to_string(),
            ],
            60,
            1,
        );
        crate::topology::sign_descriptor(&mut desc, peer_kp.signing_key()).expect("sign");
        cat.upsert_descriptor(desc).expect("upsert");

        let mut listens = HashMap::new();
        listens.insert(
            "tcp".into(),
            SocketAddr::from_str("192.168.1.2:8080").unwrap(),
        );

        let self_kp = crate::crypto::NodeKeypair::generate();
        let r = ranked_dial_targets(
            &remote,
            self_kp.peer_id(),
            &cat,
            &dial,
            &listens,
            &HashMap::new(),
            true,
        );
        assert_eq!(r.len(), 2);
        assert_eq!(
            r[0].1,
            SocketAddr::from_str("192.168.1.50:9002").unwrap(),
            "LAN before global when prefer_lan_addrs"
        );
        assert_eq!(r[1].1, SocketAddr::from_str("198.51.100.10:9001").unwrap());
    }

    #[test]
    fn filters_own_listen_addrs() {
        let cat = PeerCatalog::new();
        let dial = DashMap::new();
        let remote = PeerId::from("remote-peer");
        let local_tcp = SocketAddr::from_str("127.0.0.1:18080").unwrap();
        let mut listens = HashMap::new();
        listens.insert("tcp".into(), local_tcp);

        dial.insert(
            remote.clone(),
            vec![
                ("tcp".into(), local_tcp),
                ("tcp".into(), "10.0.0.5:1".parse().unwrap()),
            ],
        );

        let r = ranked_dial_targets(
            &remote,
            "self-id",
            &cat,
            &dial,
            &listens,
            &HashMap::new(),
            false,
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].1, "10.0.0.5:1".parse().unwrap());
    }
}
