use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use dashmap::DashMap;

use crate::topology::{NodeDescriptor, parse_observed_addr_line};
use crate::types::PeerId;

/// Source of an address record — affects trust and expiry policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSource {
    /// Reported by the peer itself in a signed NodeDescriptor.
    SelfReported,
    /// Received via gossip (PeersResponse from a third party).
    Gossip,
    /// Discovered via LAN multicast (signed LanHello).
    Lan,
}

/// A known dial endpoint for a peer with freshness metadata.
#[derive(Debug, Clone)]
pub struct AddressRecord {
    pub proto: String,
    pub addr: SocketAddr,
    pub source: AddressSource,
    pub last_seen_ms: u64,
    pub expires_at_ms: u64,
}

/// Per-peer dial state: consecutive failure count and exponential backoff.
#[derive(Debug, Clone, Default)]
pub struct DialRecord {
    pub consecutive_failures: u32,
    pub backoff_until_ms: u64,
    pub last_success_ms: u64,
}

#[derive(Debug, Default)]
struct PeerEntry {
    addresses: Vec<AddressRecord>,
    dial: DialRecord,
}

/// Per-peer store of addresses with freshness/expiry and exponential dial backoff.
///
/// Does not own sessions or sockets — pure observable state consumed by the
/// planner snapshot builder and the reconciler.
#[derive(Debug, Default)]
pub struct PeerDirectory {
    peers: DashMap<PeerId, PeerEntry>,
}

impl PeerDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Upsert all valid addresses from a signed descriptor (source = SelfReported).
    /// Addresses in `exclude_addrs` (e.g. our own listen sockets) are skipped.
    pub fn upsert_from_descriptor(
        &self,
        desc: &NodeDescriptor,
        exclude_addrs: &HashSet<SocketAddr>,
    ) {
        let pid = PeerId::from(desc.peer_id.as_str());
        let expires_at = desc.expires_at_ms();
        let last_seen = desc.timestamp_ms;
        let mut entry = self.peers.entry(pid).or_default();
        for addr_line in &desc.observed_addrs {
            let Some((proto, addr)) = parse_observed_addr_line(addr_line) else {
                continue;
            };
            if addr.ip().is_unspecified() || exclude_addrs.contains(&addr) {
                continue;
            }
            if proto != "tcp" && proto != "udp" && proto != "quic" {
                continue;
            }
            if let Some(rec) = entry
                .addresses
                .iter_mut()
                .find(|r| r.proto == proto && r.addr == addr)
            {
                if last_seen >= rec.last_seen_ms {
                    rec.last_seen_ms = last_seen;
                    rec.expires_at_ms = expires_at;
                    rec.source = AddressSource::SelfReported;
                }
            } else {
                entry.addresses.push(AddressRecord {
                    proto,
                    addr,
                    source: AddressSource::SelfReported,
                    last_seen_ms: last_seen,
                    expires_at_ms: expires_at,
                });
            }
        }
    }

    /// Record a successful dial; reset consecutive failure counter and clear backoff.
    pub fn record_dial_success(&self, peer_id: &PeerId, now: u64) {
        let mut entry = self.peers.entry(peer_id.clone()).or_default();
        entry.dial.consecutive_failures = 0;
        entry.dial.backoff_until_ms = 0;
        entry.dial.last_success_ms = now;
    }

    /// Record a dial failure and compute exponential backoff from `base_ms`.
    /// Backoff is capped at 5 minutes.
    pub fn record_dial_failure(&self, peer_id: &PeerId, base_ms: u64, now: u64) {
        const MAX_BACKOFF_MS: u64 = 5 * 60_000;
        let mut entry = self.peers.entry(peer_id.clone()).or_default();
        let f = entry.dial.consecutive_failures.saturating_add(1).min(10);
        entry.dial.consecutive_failures = f;
        let backoff = base_ms.saturating_mul(1u64 << f).min(MAX_BACKOFF_MS);
        let until = now.saturating_add(backoff);
        if until > entry.dial.backoff_until_ms {
            entry.dial.backoff_until_ms = until;
        }
    }

    /// Set an explicit backoff deadline (e.g. from a `DropIntent` cooldown).
    pub fn set_backoff(&self, peer_id: &PeerId, until_ms: u64) {
        let mut entry = self.peers.entry(peer_id.clone()).or_default();
        if until_ms > entry.dial.backoff_until_ms {
            entry.dial.backoff_until_ms = until_ms;
        }
    }

    /// Clear backoff state (e.g. when a peer reappears via another route).
    pub fn clear_backoff(&self, peer_id: &PeerId) {
        if let Some(mut entry) = self.peers.get_mut(peer_id) {
            entry.dial.backoff_until_ms = 0;
            entry.dial.consecutive_failures = 0;
        }
    }

    /// True if the peer is in a backoff window and must not be dialed yet.
    pub fn in_backoff(&self, peer_id: &PeerId, now: u64) -> bool {
        self.peers
            .get(peer_id)
            .is_some_and(|e| now < e.dial.backoff_until_ms)
    }

    /// Build a dial book containing only non-expired addresses.
    /// Consumed by `build_topology_snapshot` → `TopologySnapshot.dial_book`.
    pub fn dial_book(&self, now: u64) -> HashMap<PeerId, Vec<(String, SocketAddr)>> {
        self.peers
            .iter()
            .filter_map(|entry| {
                let addrs: Vec<(String, SocketAddr)> = entry
                    .addresses
                    .iter()
                    .filter(|r| r.expires_at_ms > now)
                    .map(|r| (r.proto.clone(), r.addr))
                    .collect();
                if addrs.is_empty() {
                    None
                } else {
                    Some((entry.key().clone(), addrs))
                }
            })
            .collect()
    }

    /// Backoff/cooldown map consumed by `TopologySnapshot.dial_cooldowns`.
    pub fn cooldowns(&self) -> HashMap<PeerId, u64> {
        self.peers
            .iter()
            .filter(|entry| entry.dial.backoff_until_ms > 0)
            .map(|entry| (entry.key().clone(), entry.dial.backoff_until_ms))
            .collect()
    }

    /// Replace all Lan-sourced addresses for a peer with a new set.
    /// Called when a new LanHello arrives (new boot_id or higher seq).
    pub fn replace_lan_addresses(
        &self,
        peer_id: &PeerId,
        endpoints: &[(String, SocketAddr)],
        expires_at_ms: u64,
        last_seen_ms: u64,
    ) {
        let mut entry = self.peers.entry(peer_id.clone()).or_default();
        entry.addresses.retain(|r| r.source != AddressSource::Lan);
        for (proto, addr) in endpoints {
            entry.addresses.push(AddressRecord {
                proto: proto.clone(),
                addr: *addr,
                source: AddressSource::Lan,
                last_seen_ms,
                expires_at_ms,
            });
        }
    }

    /// Remove peers whose addresses have all expired and whose backoff has ended.
    pub fn cleanup_expired(&self, now: u64) {
        let to_remove: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|entry| {
                entry.addresses.iter().all(|r| r.expires_at_ms <= now)
                    && entry.dial.backoff_until_ms <= now
            })
            .map(|entry| entry.key().clone())
            .collect();
        for pid in to_remove {
            self.peers.remove(&pid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_addr(port: u16) -> SocketAddr {
        format!("1.2.3.4:{port}").parse().unwrap()
    }

    #[test]
    fn exponential_backoff_doubles_each_failure() {
        let dir = PeerDirectory::new();
        let pid = PeerId::from("peer1");
        let base = 1_000u64;
        let now = 100_000u64;

        dir.record_dial_failure(&pid, base, now);
        let after_1 = dir.peers.get(&pid).unwrap().dial.backoff_until_ms;
        assert_eq!(after_1, now + base * 2); // 1 << 1 = 2

        dir.record_dial_failure(&pid, base, now);
        let after_2 = dir.peers.get(&pid).unwrap().dial.backoff_until_ms;
        assert_eq!(after_2, now + base * 4); // 1 << 2 = 4

        assert!(dir.in_backoff(&pid, now));
        assert!(!dir.in_backoff(&pid, after_2 + 1));
    }

    #[test]
    fn success_clears_backoff() {
        let dir = PeerDirectory::new();
        let pid = PeerId::from("peer1");
        dir.record_dial_failure(&pid, 1_000, 100_000);
        assert!(dir.in_backoff(&pid, 100_000));
        dir.record_dial_success(&pid, 100_001);
        assert!(!dir.in_backoff(&pid, 100_001));
    }

    #[test]
    fn dial_book_excludes_expired_addresses() {
        let dir = PeerDirectory::new();
        let pid = PeerId::from("peer1");
        let now = 100_000u64;
        {
            let mut entry = dir.peers.entry(pid.clone()).or_default();
            entry.addresses.push(AddressRecord {
                proto: "tcp".into(),
                addr: make_addr(1234),
                source: AddressSource::SelfReported,
                last_seen_ms: now - 1,
                expires_at_ms: now + 60_000, // fresh
            });
            entry.addresses.push(AddressRecord {
                proto: "tcp".into(),
                addr: make_addr(5678),
                source: AddressSource::SelfReported,
                last_seen_ms: now - 1000,
                expires_at_ms: now - 1, // expired
            });
        }
        let book = dir.dial_book(now);
        let addrs = book.get(&pid).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].1.port(), 1234);
    }

    #[test]
    fn replace_lan_addresses_clears_stale_lan_and_inserts_new() {
        let dir = PeerDirectory::new();
        let pid = PeerId::from("peer1");
        let now = 100_000u64;

        // Первый набор LAN-адресов.
        dir.replace_lan_addresses(
            &pid,
            &[("tcp".into(), make_addr(1111))],
            now + 60_000,
            now,
        );
        let book = dir.dial_book(now);
        assert_eq!(book[&pid].len(), 1);
        assert_eq!(book[&pid][0].1.port(), 1111);

        // Замена (новый boot_id).
        dir.replace_lan_addresses(
            &pid,
            &[("tcp".into(), make_addr(2222))],
            now + 60_000,
            now,
        );
        let book = dir.dial_book(now);
        assert_eq!(book[&pid].len(), 1);
        assert_eq!(book[&pid][0].1.port(), 2222, "старый LAN-адрес должен быть заменён");
    }

    #[test]
    fn replace_lan_does_not_remove_self_reported_addresses() {
        let dir = PeerDirectory::new();
        let pid = PeerId::from("peer1");
        let now = 100_000u64;

        // SelfReported-адрес через дескриптор.
        {
            let mut entry = dir.peers.entry(pid.clone()).or_default();
            entry.addresses.push(AddressRecord {
                proto: "tcp".into(),
                addr: make_addr(8080),
                source: AddressSource::SelfReported,
                last_seen_ms: now,
                expires_at_ms: now + 60_000,
            });
        }

        // LAN replace не должен его трогать.
        dir.replace_lan_addresses(
            &pid,
            &[("tcp".into(), make_addr(9090))],
            now + 60_000,
            now,
        );

        let book = dir.dial_book(now);
        let ports: Vec<u16> = book[&pid].iter().map(|(_, a)| a.port()).collect();
        assert!(ports.contains(&8080), "SelfReported адрес должен остаться");
        assert!(ports.contains(&9090), "LAN адрес должен добавиться");
    }

    #[test]
    fn cleanup_removes_fully_expired_peers() {
        let dir = PeerDirectory::new();
        let pid = PeerId::from("peer1");
        let now = 100_000u64;
        {
            let mut entry = dir.peers.entry(pid.clone()).or_default();
            entry.addresses.push(AddressRecord {
                proto: "tcp".into(),
                addr: make_addr(1234),
                source: AddressSource::SelfReported,
                last_seen_ms: now - 1000,
                expires_at_ms: now - 1, // expired
            });
        }
        dir.cleanup_expired(now);
        assert!(!dir.peers.contains_key(&pid));
    }
}
