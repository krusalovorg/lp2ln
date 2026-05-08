use std::collections::HashMap;

use dashmap::DashMap;

use crate::packet::Packet;
use crate::sessions::IncomingPacket;

pub enum ChunkAssemblerResult {
    Merged(IncomingPacket),
    PassThrough(IncomingPacket),
    Collecting,
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
    sender: String,
    receiver: String,
    nodes: Vec<String>,
    max_hops: u8,
    request_id: Option<u64>,
}

pub struct ChunkAssembler {
    our_peer_id: String,
    streams: DashMap<ChunkStreamKey, ChunkBuffer>,
}

impl ChunkAssembler {
    pub fn new(our_peer_id: impl Into<String>) -> Self {
        Self {
            our_peer_id: our_peer_id.into(),
            streams: DashMap::new(),
        }
    }

    pub fn should_assemble(&self, packet: &Packet) -> bool {
        packet.is_chunk() && packet.receiver == self.our_peer_id
    }

    pub fn add(&self, incoming: IncomingPacket) -> ChunkAssemblerResult {
        let packet = &incoming.packet;
        if !packet.is_chunk() {
            return ChunkAssemblerResult::PassThrough(incoming);
        }
        if packet.receiver != self.our_peer_id {
            return ChunkAssemblerResult::PassThrough(incoming);
        }

        let stream_id = match packet.chunk_stream_id {
            Some(s) => s,
            None => return ChunkAssemblerResult::PassThrough(incoming),
        };
        let index = match packet.chunk_index {
            Some(i) => i,
            None => return ChunkAssemblerResult::PassThrough(incoming),
        };
        let total = match packet.total_chunks {
            Some(t) => t,
            None => return ChunkAssemblerResult::PassThrough(incoming),
        };
        let from = incoming
            .from_node
            .as_deref()
            .unwrap_or_else(|| packet.sender.as_str())
            .to_string();

        let key = ChunkStreamKey {
            session_id: incoming.session_id.clone(),
            from: from.clone(),
            chunk_stream_id: stream_id,
        };

        let merged = {
            let mut entry = self
                .streams
                .entry(key.clone())
                .or_insert_with(|| ChunkBuffer {
                    total_chunks: total,
                    chunks: HashMap::new(),
                    sender: packet.sender.clone(),
                    receiver: packet.receiver.clone(),
                    nodes: packet.nodes.clone(),
                    max_hops: packet.max_hops,
                    request_id: packet.request_id,
                });

            if entry.total_chunks != total {
                return ChunkAssemblerResult::Collecting;
            }
            entry.chunks.insert(index, packet.data.clone());
            if entry.chunks.len() as u32 != entry.total_chunks {
                return ChunkAssemblerResult::Collecting;
            }
            let total_chunks = entry.total_chunks;
            let mut data =
                Vec::with_capacity(entry.chunks.values().map(|c| c.len()).sum::<usize>());
            for i in 0..total_chunks {
                if let Some(chunk) = entry.chunks.remove(&i) {
                    data.extend_from_slice(&chunk);
                }
            }
            Some(Packet {
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
            })
        };

        if let Some(merged) = merged {
            self.streams.remove(&key);
            ChunkAssemblerResult::Merged(IncomingPacket {
                session_id: incoming.session_id,
                from_node: incoming.from_node,
                packet: merged,
            })
        } else {
            ChunkAssemblerResult::Collecting
        }
    }

    pub fn is_chunk_packet(packet: &Packet) -> bool {
        packet.is_chunk()
    }
}
