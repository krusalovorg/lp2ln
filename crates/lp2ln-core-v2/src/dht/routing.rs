// Kademlia-style XOR routing table (DHT-0)
//
// 256 k-buckets (one per bit of NodeId).
// K = 20, ALPHA = 3 (standard Kademlia parameters).

use std::collections::VecDeque;

use crate::dht::records::{NodeId, NodeRecord, leading_zeros, xor_distance};

pub const K: usize = 20;
pub const ALPHA: usize = 3;

#[derive(Default, Clone)]
struct KBucket {
    contacts: VecDeque<NodeRecord>,
}

impl KBucket {
    fn update(&mut self, record: NodeRecord) {
        // Move to tail (most-recently-seen) if already present.
        if let Some(pos) = self
            .contacts
            .iter()
            .position(|r| r.peer_id == record.peer_id)
        {
            self.contacts.remove(pos);
        } else if self.contacts.len() >= K {
            // ponytail: evict head without ping; add LRU-with-ping in DHT-3
            self.contacts.pop_front();
        }
        self.contacts.push_back(record);
    }

    fn contains(&self, peer_id: &str) -> bool {
        self.contacts.iter().any(|r| r.peer_id == peer_id)
    }
}

pub struct RoutingTable {
    local_id: NodeId,
    // ponytail: flat Vec<KBucket> keyed by leading-zero count — 256 max; most stay empty.
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    pub fn new(local_id: NodeId) -> Self {
        Self {
            local_id,
            buckets: vec![KBucket::default(); 256],
        }
    }

    fn bucket_index(&self, id: &NodeId) -> usize {
        let d = xor_distance(&self.local_id, id);
        leading_zeros(&d).min(255)
    }

    /// Insert or refresh a contact.
    pub fn update(&mut self, record: NodeRecord) {
        if record.node_id == self.local_id || record.is_expired() {
            return;
        }
        let idx = self.bucket_index(&record.node_id);
        self.buckets[idx].update(record);
    }

    /// Return up to `n` live contacts closest to `target` by XOR.
    pub fn find_closest(&self, target: &NodeId, n: usize) -> Vec<NodeRecord> {
        let mut contacts: Vec<NodeRecord> = self
            .buckets
            .iter()
            .flat_map(|b| b.contacts.iter())
            .filter(|r| !r.is_expired())
            .cloned()
            .collect();

        contacts.sort_by_key(|r| xor_distance(&r.node_id, target));
        contacts.truncate(n);
        contacts
    }

    pub fn contains(&self, peer_id: &str) -> bool {
        self.buckets.iter().any(|b| b.contains(peer_id))
    }

    pub fn all_contacts(&self) -> Vec<NodeRecord> {
        self.buckets
            .iter()
            .flat_map(|b| b.contacts.iter().cloned())
            .collect()
    }
}
