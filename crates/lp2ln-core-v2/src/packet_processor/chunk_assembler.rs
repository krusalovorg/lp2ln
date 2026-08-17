use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::node::options::DeliveryLimits;
use crate::packet::Packet;
use crate::sessions::IncomingPacket;

pub enum ChunkAssemblerResult {
    Merged(IncomingPacket),
    PassThrough(IncomingPacket),
    Collecting,
    Rejected { reason: &'static str },
}

#[derive(Clone, Hash, Eq, PartialEq)]
struct ChunkStreamKey {
    session_id: String,
    from: String,
    chunk_stream_id: u64,
}

struct ChunkBuffer {
    total_chunks: u32,
    chunks: HashMap<u32, Vec<u8>>,
    buffered_bytes: u64,
    last_activity: Instant,
    sender: String,
    receiver: String,
    nodes: Vec<String>,
    max_hops: u8,
    request_id: Option<u64>,
}

/// Reassembles chunked packets addressed to this node.
///
/// Every buffer here is paid for by *us* while a remote peer decides whether to
/// finish the stream, so each one is bounded three ways: a TTL (a stream that
/// stalls is dropped), a count cap (global and per session), and a byte budget
/// per stream. Without these a single lost chunk pins memory until restart, and
/// a hostile peer can declare a huge `total_chunks` and never send the rest.
pub struct ChunkAssembler {
    our_peer_id: String,
    limits: DeliveryLimits,
    streams: DashMap<ChunkStreamKey, ChunkBuffer>,
    per_session: DashMap<String, usize>,
    last_sweep: Mutex<Instant>,
    rejected: AtomicU64,
}

enum Outcome {
    Merged(Packet),
    Collecting,
    Rejected(&'static str),
}

impl ChunkAssembler {
    pub fn new(our_peer_id: impl Into<String>) -> Self {
        Self::with_limits(our_peer_id, DeliveryLimits::default())
    }

    pub fn with_limits(our_peer_id: impl Into<String>, limits: DeliveryLimits) -> Self {
        Self {
            our_peer_id: our_peer_id.into(),
            limits,
            streams: DashMap::new(),
            per_session: DashMap::new(),
            last_sweep: Mutex::new(Instant::now()),
            rejected: AtomicU64::new(0),
        }
    }

    pub fn should_assemble(&self, packet: &Packet) -> bool {
        packet.is_chunk() && packet.receiver == self.our_peer_id
    }

    /// Streams currently being assembled (observability / tests).
    pub fn active_streams(&self) -> usize {
        self.streams.len()
    }

    /// Chunks refused by a limit since startup (observability / tests).
    pub fn rejected_count(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    pub fn add(&self, incoming: IncomingPacket) -> ChunkAssemblerResult {
        let packet = &incoming.packet;
        if !packet.is_chunk() || packet.receiver != self.our_peer_id {
            return ChunkAssemblerResult::PassThrough(incoming);
        }

        let (Some(stream_id), Some(index), Some(total)) = (
            packet.chunk_stream_id,
            packet.chunk_index,
            packet.total_chunks,
        ) else {
            return ChunkAssemblerResult::PassThrough(incoming);
        };

        // Validate the stream shape before allocating anything for it.
        if total == 0 || total > self.limits.max_chunks_per_stream {
            return self.reject("total_chunks out of range");
        }
        if index >= total {
            return self.reject("chunk_index out of range");
        }

        self.sweep_expired_if_due();

        let from = incoming
            .from_node
            .as_deref()
            .unwrap_or(packet.sender.as_str())
            .to_string();
        let key = ChunkStreamKey {
            session_id: incoming.session_id.clone(),
            from,
            chunk_stream_id: stream_id,
        };

        // Admission for a stream we have not seen before. The check/insert pair
        // is not atomic, so concurrent workers can overshoot a cap by a handful
        // of streams — harmless for a resource bound, and cheaper than holding a
        // global lock across every chunk.
        if !self.streams.contains_key(&key) {
            if self.streams.len() >= self.limits.max_chunk_streams {
                self.sweep_expired();
                if self.streams.len() >= self.limits.max_chunk_streams {
                    return self.reject("chunk stream table full");
                }
            }
            let live = self
                .per_session
                .get(&key.session_id)
                .map(|n| *n)
                .unwrap_or(0);
            if live >= self.limits.max_chunk_streams_per_session {
                return self.reject("per-session chunk stream limit");
            }
        }

        let mut created = false;
        let outcome = {
            let mut entry = self.streams.entry(key.clone()).or_insert_with(|| {
                created = true;
                ChunkBuffer {
                    total_chunks: total,
                    chunks: HashMap::new(),
                    buffered_bytes: 0,
                    last_activity: Instant::now(),
                    sender: packet.sender.clone(),
                    receiver: packet.receiver.clone(),
                    nodes: packet.nodes.clone(),
                    max_hops: packet.max_hops,
                    request_id: packet.request_id,
                }
            });

            if entry.total_chunks != total {
                Outcome::Rejected("total_chunks mismatch within stream")
            } else if entry.chunks.contains_key(&index) {
                // Duplicate chunk: reassembly is idempotent per index, so just
                // keep the stream alive and wait for the ones still missing.
                entry.last_activity = Instant::now();
                Outcome::Collecting
            } else if entry.buffered_bytes + packet.data.len() as u64
                > self.limits.max_chunk_stream_bytes
            {
                Outcome::Rejected("chunk stream byte budget exceeded")
            } else {
                entry.buffered_bytes += packet.data.len() as u64;
                entry.chunks.insert(index, packet.data.clone());
                entry.last_activity = Instant::now();
                if entry.chunks.len() as u32 == entry.total_chunks {
                    Outcome::Merged(merge(&mut entry))
                } else {
                    Outcome::Collecting
                }
            }
        };

        if created {
            *self
                .per_session
                .entry(key.session_id.clone())
                .or_insert(0) += 1;
        }

        match outcome {
            Outcome::Merged(merged) => {
                self.remove_stream(&key);
                ChunkAssemblerResult::Merged(IncomingPacket {
                    session_id: incoming.session_id,
                    from_node: incoming.from_node,
                    packet: merged,
                })
            }
            Outcome::Collecting => ChunkAssemblerResult::Collecting,
            Outcome::Rejected(reason) => {
                if created {
                    // Never leave an empty buffer behind for a chunk we refused.
                    self.remove_stream(&key);
                }
                self.reject(reason)
            }
        }
    }

    pub fn is_chunk_packet(packet: &Packet) -> bool {
        packet.is_chunk()
    }

    fn reject(&self, reason: &'static str) -> ChunkAssemblerResult {
        let n = self.rejected.fetch_add(1, Ordering::Relaxed);
        if n == 0 || n % 256 == 0 {
            crate::warn!(
                "[ChunkAssembler] refused chunk: {} ({} refused so far)",
                reason,
                n.saturating_add(1)
            );
        }
        ChunkAssemblerResult::Rejected { reason }
    }

    fn remove_stream(&self, key: &ChunkStreamKey) {
        if self.streams.remove(key).is_none() {
            return;
        }
        if let Some(mut live) = self.per_session.get_mut(&key.session_id) {
            *live = live.saturating_sub(1);
        }
        self.per_session.remove_if(&key.session_id, |_, n| *n == 0);
    }

    /// Sweep at most once per quarter-TTL: an O(n) scan on every chunk would
    /// make a large stream table quadratic.
    fn sweep_expired_if_due(&self) {
        let interval = Duration::from_millis((self.limits.chunk_stream_ttl_ms / 4).max(250));
        {
            let Ok(mut last) = self.last_sweep.lock() else {
                return;
            };
            if last.elapsed() < interval {
                return;
            }
            *last = Instant::now();
        }
        self.sweep_expired();
    }

    fn sweep_expired(&self) {
        let ttl = Duration::from_millis(self.limits.chunk_stream_ttl_ms);
        let expired: Vec<ChunkStreamKey> = self
            .streams
            .iter()
            .filter(|entry| entry.last_activity.elapsed() >= ttl)
            .map(|entry| entry.key().clone())
            .collect();
        if expired.is_empty() {
            return;
        }
        crate::debug!(
            "[ChunkAssembler] dropping {} chunk stream(s) idle for >{}ms",
            expired.len(),
            self.limits.chunk_stream_ttl_ms
        );
        for key in expired {
            self.remove_stream(&key);
        }
    }
}

/// Concatenate a complete buffer in chunk order.
fn merge(entry: &mut ChunkBuffer) -> Packet {
    let total = entry.total_chunks;
    let mut data = Vec::with_capacity(entry.buffered_bytes as usize);
    for i in 0..total {
        if let Some(chunk) = entry.chunks.remove(&i) {
            data.extend_from_slice(&chunk);
        }
    }
    Packet {
        signature: None,
        data,
        nodes: entry.nodes.clone(),
        sender: entry.sender.clone(),
        receiver: entry.receiver.clone(),
        max_hops: entry.max_hops,
        request_id: entry.request_id,
        chunk_stream_id: None,
        chunk_index: None,
        total_chunks: None,
        protocol_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "me";

    fn chunk(stream: u64, index: u32, total: u32, data: &[u8]) -> IncomingPacket {
        IncomingPacket {
            session_id: "s1".to_string(),
            from_node: Some("peer".to_string()),
            packet: Packet {
                signature: None,
                data: data.to_vec(),
                nodes: vec![],
                sender: "peer".to_string(),
                receiver: ME.to_string(),
                max_hops: 8,
                request_id: Some(stream),
                chunk_stream_id: Some(stream),
                chunk_index: Some(index),
                total_chunks: Some(total),
                protocol_id: None,
            },
        }
    }

    fn assert_rejected(result: ChunkAssemblerResult) -> &'static str {
        match result {
            ChunkAssemblerResult::Rejected { reason } => reason,
            _ => panic!("expected Rejected"),
        }
    }

    #[test]
    fn merges_complete_stream_in_order() {
        let a = ChunkAssembler::new(ME);
        assert!(matches!(
            a.add(chunk(1, 1, 2, b"world")),
            ChunkAssemblerResult::Collecting
        ));
        let ChunkAssemblerResult::Merged(out) = a.add(chunk(1, 0, 2, b"hello ")) else {
            panic!("expected Merged");
        };
        assert_eq!(out.packet.data, b"hello world");
        assert!(!out.packet.is_chunk());
        // Completed streams must not stay resident.
        assert_eq!(a.active_streams(), 0);
    }

    #[test]
    fn duplicate_chunk_does_not_corrupt_or_double_count() {
        let a = ChunkAssembler::new(ME);
        assert!(matches!(
            a.add(chunk(1, 0, 2, b"aa")),
            ChunkAssemblerResult::Collecting
        ));
        assert!(matches!(
            a.add(chunk(1, 0, 2, b"aa")),
            ChunkAssemblerResult::Collecting
        ));
        let ChunkAssemblerResult::Merged(out) = a.add(chunk(1, 1, 2, b"bb")) else {
            panic!("expected Merged");
        };
        assert_eq!(out.packet.data, b"aabb");
    }

    #[test]
    fn stalled_stream_is_evicted_after_ttl() {
        let limits = DeliveryLimits {
            chunk_stream_ttl_ms: 1,
            ..DeliveryLimits::default()
        };
        let a = ChunkAssembler::with_limits(ME, limits);
        a.add(chunk(1, 0, 100, b"partial"));
        assert_eq!(a.active_streams(), 1);
        std::thread::sleep(Duration::from_millis(300));
        // Any later chunk triggers the due sweep.
        a.add(chunk(2, 0, 100, b"other"));
        assert!(
            !a.streams.iter().any(|e| e.key().chunk_stream_id == 1),
            "stalled stream 1 should have been swept"
        );
    }

    #[test]
    fn absurd_total_chunks_is_refused_without_allocating() {
        let a = ChunkAssembler::new(ME);
        let reason = assert_rejected(a.add(chunk(1, 0, u32::MAX, b"x")));
        assert_eq!(reason, "total_chunks out of range");
        assert_eq!(a.active_streams(), 0);
        assert_eq!(a.rejected_count(), 1);
    }

    #[test]
    fn zero_total_and_out_of_range_index_are_refused() {
        let a = ChunkAssembler::new(ME);
        assert_eq!(
            assert_rejected(a.add(chunk(1, 0, 0, b"x"))),
            "total_chunks out of range"
        );
        assert_eq!(
            assert_rejected(a.add(chunk(1, 5, 2, b"x"))),
            "chunk_index out of range"
        );
        assert_eq!(a.active_streams(), 0);
    }

    #[test]
    fn per_session_stream_cap_is_enforced_and_released() {
        let limits = DeliveryLimits {
            max_chunk_streams_per_session: 2,
            ..DeliveryLimits::default()
        };
        let a = ChunkAssembler::with_limits(ME, limits);
        a.add(chunk(1, 0, 2, b"x"));
        a.add(chunk(2, 0, 2, b"x"));
        assert_eq!(
            assert_rejected(a.add(chunk(3, 0, 2, b"x"))),
            "per-session chunk stream limit"
        );
        // Finishing a stream frees its slot again.
        assert!(matches!(
            a.add(chunk(1, 1, 2, b"y")),
            ChunkAssemblerResult::Merged(_)
        ));
        assert!(matches!(
            a.add(chunk(3, 0, 2, b"x")),
            ChunkAssemblerResult::Collecting
        ));
    }

    #[test]
    fn global_stream_cap_is_enforced() {
        let limits = DeliveryLimits {
            max_chunk_streams: 1,
            ..DeliveryLimits::default()
        };
        let a = ChunkAssembler::with_limits(ME, limits);
        a.add(chunk(1, 0, 2, b"x"));
        assert_eq!(
            assert_rejected(a.add(chunk(2, 0, 2, b"x"))),
            "chunk stream table full"
        );
        assert_eq!(a.active_streams(), 1);
    }

    #[test]
    fn byte_budget_stops_a_stream_that_grows_too_large() {
        let limits = DeliveryLimits {
            max_chunk_stream_bytes: 4,
            ..DeliveryLimits::default()
        };
        let a = ChunkAssembler::with_limits(ME, limits);
        assert!(matches!(
            a.add(chunk(1, 0, 3, b"abc")),
            ChunkAssemblerResult::Collecting
        ));
        assert_eq!(
            assert_rejected(a.add(chunk(1, 1, 3, b"def"))),
            "chunk stream byte budget exceeded"
        );
    }

    #[test]
    fn total_chunks_mismatch_within_stream_is_refused() {
        let a = ChunkAssembler::new(ME);
        a.add(chunk(1, 0, 4, b"x"));
        assert_eq!(
            assert_rejected(a.add(chunk(1, 1, 9, b"y"))),
            "total_chunks mismatch within stream"
        );
    }

    #[test]
    fn packets_for_other_receivers_pass_through_untouched() {
        let a = ChunkAssembler::new(ME);
        let mut ip = chunk(1, 0, 2, b"x");
        ip.packet.receiver = "someone-else".to_string();
        assert!(matches!(a.add(ip), ChunkAssemblerResult::PassThrough(_)));
        assert_eq!(a.active_streams(), 0);
    }
}
