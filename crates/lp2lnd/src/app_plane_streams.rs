//! Bulk stream table for App Plane IPC (P3-05).
//!
//! Credit-window backpressure: sidecar may send [`AppCmd::StreamChunk`] only while
//! the host has granted credits via [`AppEvent::StreamWindow`]. Cancellation is
//! explicit via [`AppCmd::StreamCancel`] → [`AppEvent::StreamClosed`].

use std::collections::HashMap;

use lp2ln_core_v2::app_plane::{
    AppErrorCode, AppEvent, DEFAULT_STREAM_CREDITS, MAX_STREAM_CHUNK_BYTES,
    MAX_STREAMS_PER_CONNECTION,
};

#[derive(Debug)]
pub struct BulkStream {
    #[allow(dead_code)]
    pub stream_id: u64,
    #[allow(dead_code)]
    pub protocol_id: u16,
    #[allow(dead_code)]
    pub peer_id: String,
    /// Credits remaining for sidecar → host chunks.
    pub inbound_credits: u32,
    /// Credits remaining for host → sidecar chunks (echo / future peer push).
    pub outbound_credits: u32,
    pub next_seq_in: u64,
    pub next_seq_out: u64,
}

#[derive(Debug, Default)]
pub struct StreamTable {
    streams: HashMap<u64, BulkStream>,
    /// When true, host returns one credit after each accepted inbound chunk.
    pub auto_refill: bool,
}

impl StreamTable {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            auto_refill: true,
        }
    }

    pub fn with_auto_refill(mut self, auto_refill: bool) -> Self {
        self.auto_refill = auto_refill;
        self
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    #[allow(dead_code)]
    pub fn contains(&self, stream_id: u64) -> bool {
        self.streams.contains_key(&stream_id)
    }

    /// Open a stream. Returns events to send (Ack is handled by caller).
    pub fn open(
        &mut self,
        stream_id: u64,
        protocol_id: u16,
        peer_id: String,
    ) -> Result<Vec<AppEvent>, AppErrorCode> {
        if self.streams.contains_key(&stream_id) {
            return Err(AppErrorCode::Internal);
        }
        if self.streams.len() >= MAX_STREAMS_PER_CONNECTION {
            return Err(AppErrorCode::QueueOverflow);
        }
        self.streams.insert(
            stream_id,
            BulkStream {
                stream_id,
                protocol_id,
                peer_id,
                inbound_credits: DEFAULT_STREAM_CREDITS,
                outbound_credits: 0,
                next_seq_in: 0,
                next_seq_out: 0,
            },
        );
        Ok(vec![AppEvent::StreamWindow {
            stream_id,
            credits: DEFAULT_STREAM_CREDITS,
        }])
    }

    /// Accept an inbound chunk. May return refill window and/or echo chunk.
    pub fn on_chunk(
        &mut self,
        stream_id: u64,
        seq: u64,
        payload: Vec<u8>,
    ) -> Result<Vec<AppEvent>, AppErrorCode> {
        if payload.len() > MAX_STREAM_CHUNK_BYTES {
            return Err(AppErrorCode::BadFrame);
        }
        let Some(s) = self.streams.get_mut(&stream_id) else {
            return Err(AppErrorCode::Internal);
        };
        if s.inbound_credits == 0 {
            return Err(AppErrorCode::QueueOverflow);
        }
        if seq != s.next_seq_in {
            return Err(AppErrorCode::BadFrame);
        }
        s.inbound_credits -= 1;
        s.next_seq_in = s.next_seq_in.saturating_add(1);

        let mut out = Vec::new();

        // Echo when client has granted outbound credits (local round-trip).
        if s.outbound_credits > 0 {
            s.outbound_credits -= 1;
            let echo_seq = s.next_seq_out;
            s.next_seq_out = s.next_seq_out.saturating_add(1);
            out.push(AppEvent::StreamChunk {
                stream_id,
                seq: echo_seq,
                payload,
            });
        }

        if self.auto_refill {
            s.inbound_credits = s.inbound_credits.saturating_add(1);
            out.push(AppEvent::StreamWindow {
                stream_id,
                credits: 1,
            });
        }

        Ok(out)
    }

    /// Client advertises how many host→sidecar chunks it can accept.
    pub fn on_window(&mut self, stream_id: u64, credits: u32) -> Result<Vec<AppEvent>, AppErrorCode> {
        let Some(s) = self.streams.get_mut(&stream_id) else {
            return Err(AppErrorCode::Internal);
        };
        s.outbound_credits = s.outbound_credits.saturating_add(credits);
        Ok(vec![])
    }

    /// Cancel and remove the stream.
    pub fn cancel(&mut self, stream_id: u64) -> Result<Vec<AppEvent>, AppErrorCode> {
        if self.streams.remove(&stream_id).is_none() {
            return Err(AppErrorCode::Internal);
        }
        Ok(vec![AppEvent::StreamClosed {
            stream_id,
            error: Some(AppErrorCode::Canceled),
        }])
    }

    /// Drop all streams on connection close (no events — socket is gone).
    pub fn clear(&mut self) {
        self.streams.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_grants_initial_window() {
        let mut t = StreamTable::new().with_auto_refill(false);
        let evs = t.open(1, 7, "peer".into()).unwrap();
        assert!(matches!(
            &evs[..],
            [AppEvent::StreamWindow {
                stream_id: 1,
                credits: DEFAULT_STREAM_CREDITS
            }]
        ));
        assert!(t.contains(1));
    }

    #[test]
    fn backpressure_rejects_when_credits_exhausted() {
        let mut t = StreamTable::new().with_auto_refill(false);
        t.open(1, 7, "p".into()).unwrap();
        for i in 0..DEFAULT_STREAM_CREDITS {
            t.on_chunk(1, i as u64, vec![i as u8]).unwrap();
        }
        assert_eq!(
            t.on_chunk(1, DEFAULT_STREAM_CREDITS as u64, vec![9]),
            Err(AppErrorCode::QueueOverflow)
        );
        assert!(t.contains(1), "overflow must not close the stream");
    }

    #[test]
    fn cancel_closes_stream() {
        let mut t = StreamTable::new();
        t.open(2, 1, "p".into()).unwrap();
        let evs = t.cancel(2).unwrap();
        assert!(matches!(
            &evs[..],
            [AppEvent::StreamClosed {
                stream_id: 2,
                error: Some(AppErrorCode::Canceled)
            }]
        ));
        assert!(!t.contains(2));
    }

    #[test]
    fn window_enables_echo() {
        let mut t = StreamTable::new().with_auto_refill(false);
        t.open(3, 1, "p".into()).unwrap();
        t.on_window(3, 1).unwrap();
        let evs = t.on_chunk(3, 0, b"hi".to_vec()).unwrap();
        assert!(matches!(
            &evs[..],
            [AppEvent::StreamChunk {
                stream_id: 3,
                seq: 0,
                payload
            }] if payload == b"hi"
        ));
    }

    #[test]
    fn chunk_too_large_rejected() {
        let mut t = StreamTable::new().with_auto_refill(false);
        t.open(1, 1, "p".into()).unwrap();
        let big = vec![0u8; MAX_STREAM_CHUNK_BYTES + 1];
        assert_eq!(t.on_chunk(1, 0, big), Err(AppErrorCode::BadFrame));
    }

    #[test]
    fn auto_refill_keeps_credits() {
        let mut t = StreamTable::new().with_auto_refill(true);
        t.open(1, 1, "p".into()).unwrap();
        for i in 0..20 {
            let evs = t.on_chunk(1, i, vec![1]).unwrap();
            assert!(evs.iter().any(|e| matches!(
                e,
                AppEvent::StreamWindow {
                    stream_id: 1,
                    credits: 1
                }
            )));
        }
        assert!(t.contains(1));
    }
}
