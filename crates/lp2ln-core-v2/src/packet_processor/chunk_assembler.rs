use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::node::options::DeliveryLimits;
use crate::packet::Packet;
use crate::router::admission::IngressPermit;
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
    permits: Vec<IngressPermit>,
    buffered_bytes: u64,
    charged_bytes: u64,
    last_activity: Instant,
    sender: String,
    receiver: String,
    nodes: Vec<String>,
    max_hops: u8,
    request_id: Option<u64>,
    protocol_id: Option<u16>,
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
    state: Mutex<ChunkState>,
    aggregate_budget: u64,
    rejected: AtomicU64,
}

const MAX_REASSEMBLY_BYTES: u64 = 128 * 1024 * 1024;

struct ChunkState {
    streams: HashMap<ChunkStreamKey, ChunkBuffer>,
    per_session: HashMap<String, usize>,
    charged_bytes: u64,
    last_sweep: Instant,
}

impl ChunkState {
    fn remove(&mut self, key: &ChunkStreamKey) -> Option<ChunkBuffer> {
        let stream = self.streams.remove(key)?;
        self.charged_bytes -= stream.charged_bytes;
        if let std::collections::hash_map::Entry::Occupied(mut count) =
            self.per_session.entry(key.session_id.clone())
        {
            *count.get_mut() -= 1;
            if *count.get() == 0 {
                count.remove();
            }
        }
        Some(stream)
    }

    fn expire(&mut self, ttl: Duration) {
        let expired: Vec<_> = self
            .streams
            .iter()
            .filter(|(_, stream)| stream.last_activity.elapsed() >= ttl)
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.remove(&key);
        }
        self.last_sweep = Instant::now();
    }
}

impl ChunkAssembler {
    pub fn new(our_peer_id: impl Into<String>) -> Self {
        Self::with_limits(our_peer_id, DeliveryLimits::default())
    }

    pub fn with_limits(our_peer_id: impl Into<String>, limits: DeliveryLimits) -> Self {
        Self {
            our_peer_id: our_peer_id.into(),
            limits,
            state: Mutex::new(ChunkState {
                streams: HashMap::new(),
                per_session: HashMap::new(),
                charged_bytes: 0,
                last_sweep: Instant::now(),
            }),
            rejected: AtomicU64::new(0),
            aggregate_budget: MAX_REASSEMBLY_BYTES,
        }
    }

    pub fn should_assemble(&self, packet: &Packet) -> bool {
        packet.is_chunk() && packet.receiver == self.our_peer_id
    }

    /// Streams currently being assembled (observability / tests).
    pub fn active_streams(&self) -> usize {
        self.state.lock().unwrap().streams.len()
    }

    /// Chunks refused by a limit since startup (observability / tests).
    pub fn rejected_count(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    pub fn add(&self, incoming: IncomingPacket) -> ChunkAssemblerResult {
        self.add_admitted(incoming, None).0
    }

    pub(crate) fn add_admitted(
        &self,
        mut incoming: IncomingPacket,
        permit: Option<IngressPermit>,
    ) -> (ChunkAssemblerResult, Option<IngressPermit>) {
        let packet = &mut incoming.packet;
        if !packet.is_chunk() || packet.receiver != self.our_peer_id {
            return (ChunkAssemblerResult::PassThrough(incoming), permit);
        }

        let (Some(stream_id), Some(index), Some(total)) = (
            packet.chunk_stream_id,
            packet.chunk_index,
            packet.total_chunks,
        ) else {
            return (ChunkAssemblerResult::PassThrough(incoming), permit);
        };

        // Validate the stream shape before allocating anything for it.
        if total == 0 || total > self.limits.max_chunks_per_stream {
            return (self.reject("total_chunks out of range"), None);
        }
        if index >= total {
            return (self.reject("chunk_index out of range"), None);
        }

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

        // Include allocation capacity and a fixed charge for each map entry.
        // Stream metadata is bounded separately by stream count and admission.
        let chunk_charge = (packet.data.capacity() as u64).saturating_add(64);
        let mut state = self.state.lock().unwrap();
        let ttl = Duration::from_millis(self.limits.chunk_stream_ttl_ms);
        let sweep_interval = Duration::from_millis((self.limits.chunk_stream_ttl_ms / 4).max(250));
        if state.last_sweep.elapsed() >= sweep_interval {
            state.expire(ttl);
        }

        if let Some(stream) = state.streams.get(&key) {
            if stream.last_activity.elapsed() >= ttl {
                state.remove(&key);
            }
        }
        if let Some(stream) = state.streams.get(&key) {
            if stream.total_chunks != total {
                return (self.reject("total_chunks mismatch within stream"), None);
            }
            if stream.sender != packet.sender
                || stream.protocol_id != packet.protocol_id
                || stream.request_id != packet.request_id
            {
                return (self.reject("chunk metadata mismatch within stream"), None);
            }
            if stream.chunks.contains_key(&index) {
                return (ChunkAssemblerResult::Collecting, None);
            }
            if stream
                .buffered_bytes
                .saturating_add(packet.data.len() as u64)
                > self.limits.max_chunk_stream_bytes
            {
                return (self.reject("chunk stream byte budget exceeded"), None);
            }
        } else {
            if packet.data.len() as u64 > self.limits.max_chunk_stream_bytes {
                return (self.reject("chunk stream byte budget exceeded"), None);
            }
            if state.streams.len() >= self.limits.max_chunk_streams
                || state.per_session.get(&key.session_id).copied().unwrap_or(0)
                    >= self.limits.max_chunk_streams_per_session
            {
                state.expire(ttl);
            }
            if state.streams.len() >= self.limits.max_chunk_streams {
                return (self.reject("chunk stream table full"), None);
            }
            if state.per_session.get(&key.session_id).copied().unwrap_or(0)
                >= self.limits.max_chunk_streams_per_session
            {
                return (self.reject("per-session chunk stream limit"), None);
            }
        }

        let is_new = !state.streams.contains_key(&key);
        let stream_charge = if is_new {
            let metadata = packet.nodes.iter().map(String::capacity).sum::<usize>()
                + packet.nodes.capacity() * std::mem::size_of::<String>()
                + packet.sender.capacity()
                + packet.receiver.capacity()
                + key.session_id.capacity()
                + key.from.capacity();
            (metadata as u64).saturating_add(256)
        } else {
            0
        };
        let charge = stream_charge.saturating_add(chunk_charge);
        if charge > self.aggregate_budget.saturating_sub(state.charged_bytes) {
            return (self.reject("aggregate chunk byte budget exceeded"), None);
        }

        if is_new {
            *state.per_session.entry(key.session_id.clone()).or_default() += 1;
        }
        state.charged_bytes += charge;
        let entry = state
            .streams
            .entry(key.clone())
            .or_insert_with(|| ChunkBuffer {
                total_chunks: total,
                chunks: HashMap::new(),
                permits: Vec::new(),
                buffered_bytes: 0,
                charged_bytes: 0,
                last_activity: Instant::now(),
                sender: packet.sender.clone(),
                receiver: packet.receiver.clone(),
                nodes: packet.nodes.clone(),
                max_hops: packet.max_hops,
                request_id: packet.request_id,
                protocol_id: packet.protocol_id,
            });
        entry.charged_bytes += charge;
        entry.buffered_bytes += packet.data.len() as u64;
        entry.chunks.insert(index, std::mem::take(&mut packet.data));
        if let Some(permit) = permit {
            entry.permits.push(permit);
        }
        entry.last_activity = Instant::now();
        if entry.chunks.len() as u32 != entry.total_chunks {
            return (ChunkAssemblerResult::Collecting, None);
        }

        let mut complete = state.remove(&key).expect("completed stream exists");
        drop(state);
        // The output allocation overlaps the source chunks until merge ends.
        // Never wait on an additional permit while holding the source permits.
        let merged_permit = if let Some(source) = complete.permits.first() {
            let metadata = complete.nodes.iter().map(|n| n.len() + 24).sum::<usize>()
                + complete.sender.len()
                + complete.receiver.len()
                + incoming.session_id.len()
                + incoming.from_node.as_ref().map_or(0, String::len)
                + 1024;
            let bytes = (complete.buffered_bytes as usize).saturating_add(metadata);
            let Some(copy) = source.try_copy(bytes) else {
                return (self.reject("chunk merge admission exhausted"), None);
            };
            Some(copy)
        } else {
            None
        };
        (
            ChunkAssemblerResult::Merged(IncomingPacket {
                session_id: incoming.session_id,
                from_node: incoming.from_node,
                packet: merge(&mut complete),
            }),
            merged_permit,
        )
    }

    pub(crate) fn reap(&self) {
        let ttl = Duration::from_millis(self.limits.chunk_stream_ttl_ms);
        self.state.lock().unwrap().expire(ttl);
    }

    pub(crate) fn remove_session(&self, session_id: &str) {
        let mut state = self.state.lock().unwrap();
        let keys: Vec<_> = state
            .streams
            .keys()
            .filter(|key| key.session_id == session_id)
            .cloned()
            .collect();
        for key in keys {
            state.remove(&key);
        }
    }

    pub(crate) fn clear(&self) {
        let mut state = self.state.lock().unwrap();
        state.streams.clear();
        state.per_session.clear();
        state.charged_bytes = 0;
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
        protocol_id: entry.protocol_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_chunk_budget_is_released_on_completion() {
        let mut assembler = ChunkAssembler::new("me");
        assembler.aggregate_budget = 640;
        assert!(matches!(
            assembler.add(chunk(1, 0, 2, &[1; 64])),
            ChunkAssemblerResult::Collecting
        ));
        assert!(matches!(
            assembler.add(chunk(2, 0, 2, &[2; 64])),
            ChunkAssemblerResult::Rejected {
                reason: "aggregate chunk byte budget exceeded"
            }
        ));
        assert!(matches!(
            assembler.add(chunk(1, 1, 2, &[3; 64])),
            ChunkAssemblerResult::Merged(_)
        ));
        assert!(matches!(
            assembler.add(chunk(2, 0, 2, &[2; 64])),
            ChunkAssemblerResult::Collecting
        ));
    }

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
            !a.state
                .lock()
                .unwrap()
                .streams
                .keys()
                .any(|key| key.chunk_stream_id == 1),
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
