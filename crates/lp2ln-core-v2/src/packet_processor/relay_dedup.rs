use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;

use crate::packet::Packet;

/// Suppresses a relayed packet that reaches us twice over different paths.
///
/// Only the relay path needs this: a direct link rides QUIC or TCP, which
/// already drop their own duplicates (AD-19). A relayed packet has no such
/// guarantee — two neighbors can independently forward the same packet.
///
/// Identity is `(sender, receiver, request_id, chunk_index)`, the fields that
/// survive relaying. `request_id` is a per-sender monotonic counter, so it is
/// unique per originated packet; `receiver` keeps two replies that reuse an
/// incoming request id apart; `chunk_index` keeps the chunks of one stream
/// apart, since they deliberately share a `request_id`.
///
/// Eviction is FIFO rather than true LRU: for duplicate suppression the only
/// thing that matters is that a recent packet is still remembered, and a
/// wrongly evicted key costs nothing (the packet is simply not deduped).
pub struct RelayDedup {
    capacity: usize,
    inner: Mutex<DedupInner>,
}

#[derive(Clone, Hash, Eq, PartialEq)]
struct DedupKey {
    sender: String,
    receiver: String,
    request_id: u64,
    chunk_index: u32,
}

struct DedupInner {
    seen: HashSet<DedupKey>,
    order: VecDeque<DedupKey>,
}

const NO_CHUNK: u32 = u32::MAX;

impl RelayDedup {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Mutex::new(DedupInner {
                seen: HashSet::new(),
                order: VecDeque::new(),
            }),
        }
    }

    pub fn check_and_record(&self, packet: &Packet) -> bool {
        if self.capacity == 0 {
            return true;
        }
        let Some(request_id) = packet.request_id else {
            return true;
        };
        let key = DedupKey {
            sender: packet.sender.clone(),
            receiver: packet.receiver.clone(),
            request_id,
            chunk_index: packet.chunk_index.unwrap_or(NO_CHUNK),
        };

        let Ok(mut inner) = self.inner.lock() else {
            return true;
        };
        if !inner.seen.insert(key.clone()) {
            return false;
        }
        inner.order.push_back(key);
        while inner.order.len() > self.capacity {
            if let Some(old) = inner.order.pop_front() {
                inner.seen.remove(&old);
            }
        }
        true
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|i| i.order.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(sender: &str, receiver: &str, request_id: u64, chunk_index: Option<u32>) -> Packet {
        Packet {
            signature: None,
            data: vec![1, 2, 3],
            nodes: vec!["relay".to_string()],
            sender: sender.to_string(),
            receiver: receiver.to_string(),
            max_hops: 8,
            request_id: Some(request_id),
            chunk_stream_id: chunk_index.map(|_| request_id),
            chunk_index,
            total_chunks: chunk_index.map(|_| 4),
            protocol_id: None,
        }
    }

    #[test]
    fn second_copy_of_the_same_packet_is_suppressed() {
        let d = RelayDedup::new(16);
        let p = packet("a", "b", 7, None);
        assert!(d.check_and_record(&p));
        assert!(!d.check_and_record(&p));
    }

    #[test]
    fn replies_to_different_peers_reusing_a_request_id_both_pass() {
        let d = RelayDedup::new(16);
        // Node "b" answers two different requesters that each picked id 5.
        assert!(d.check_and_record(&packet("b", "a", 5, None)));
        assert!(d.check_and_record(&packet("b", "c", 5, None)));
    }

    #[test]
    fn chunks_of_one_stream_are_not_mistaken_for_duplicates() {
        let d = RelayDedup::new(16);
        for i in 0..4 {
            assert!(
                d.check_and_record(&packet("a", "b", 9, Some(i))),
                "chunk {i} should pass"
            );
        }
        assert!(!d.check_and_record(&packet("a", "b", 9, Some(2))));
    }

    #[test]
    fn table_never_grows_past_capacity() {
        let d = RelayDedup::new(4);
        for i in 0..100 {
            assert!(d.check_and_record(&packet("a", "b", i, None)));
        }
        assert_eq!(d.len(), 4);
        // The oldest key was evicted, so it is treated as new again — safe.
        assert!(d.check_and_record(&packet("a", "b", 0, None)));
    }

    #[test]
    fn zero_capacity_disables_dedup() {
        let d = RelayDedup::new(0);
        let p = packet("a", "b", 1, None);
        assert!(d.check_and_record(&p));
        assert!(d.check_and_record(&p));
    }

    #[test]
    fn packet_without_request_id_is_never_deduped() {
        let d = RelayDedup::new(16);
        let mut p = packet("a", "b", 1, None);
        p.request_id = None;
        assert!(d.check_and_record(&p));
        assert!(d.check_and_record(&p));
    }
}
