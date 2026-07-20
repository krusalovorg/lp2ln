//! LP2LN App Plane wire protocol (P3).
//!
//! Framing: `[u32 LE length][postcard body]`.
//! Pure types only — no tokio / transport.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Negotiated App Plane protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum postcard body size accepted in one frame (16 MiB).
pub const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

/// Per-subscriber inbound queue capacity (host side).
pub const QUEUE_CAP: usize = 256;

/// Initial credit window granted on [`AppCmd::OpenStream`] (P3-05).
pub const DEFAULT_STREAM_CREDITS: u32 = 8;

/// Maximum payload size of one [`AppCmd::StreamChunk`] / [`AppEvent::StreamChunk`].
pub const MAX_STREAM_CHUNK_BYTES: usize = 64 * 1024;

/// Soft cap on concurrent open streams per IPC connection.
pub const MAX_STREAMS_PER_CONNECTION: usize = 32;

/// Capability bits requested in [`AppCmd::Hello`] / granted in [`AppEvent::HelloAck`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AppCapability {
    Subscribe = 1,
    Send = 2,
    QueryStatus = 3,
    OpenStream = 4,
}

/// Stable error codes for [`AppEvent::Error`] / failed [`AppEvent::HelloAck`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum AppErrorCode {
    BadFrame = 1,
    UnsupportedVersion = 2,
    Unauthorized = 3,
    UnknownProtocol = 4,
    QueueOverflow = 5,
    Canceled = 6,
    Internal = 7,
}

impl fmt::Display for AppErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFrame => write!(f, "bad_frame"),
            Self::UnsupportedVersion => write!(f, "unsupported_version"),
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::UnknownProtocol => write!(f, "unknown_protocol"),
            Self::QueueOverflow => write!(f, "queue_overflow"),
            Self::Canceled => write!(f, "canceled"),
            Self::Internal => write!(f, "internal"),
        }
    }
}

/// Messages from sidecar → node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppCmd {
    /// Version negotiation + capability request. Must be first on a new connection (P3-04).
    Hello {
        version: u16,
        capabilities: Vec<AppCapability>,
        /// Optional daemon-issued app token (auth wiring in P3-04).
        token: Option<String>,
    },
    /// Register interest in packets with this protocol_id.
    Subscribe { protocol_id: u16 },
    /// Remove subscription.
    Unsubscribe { protocol_id: u16 },
    /// Send raw payload to a peer via routing, tagged with protocol_id.
    Send {
        peer_id: String,
        protocol_id: u16,
        payload: Vec<u8>,
    },
    /// Open a bulk stream (behavior in P3-05).
    OpenStream {
        stream_id: u64,
        protocol_id: u16,
        peer_id: String,
    },
    /// Bulk data chunk (behavior in P3-05).
    StreamChunk {
        stream_id: u64,
        seq: u64,
        payload: Vec<u8>,
    },
    /// Advertise receive window / backpressure (behavior in P3-05).
    StreamWindow { stream_id: u64, credits: u32 },
    /// Cancel a bulk stream (behavior in P3-05).
    StreamCancel { stream_id: u64 },
}

/// Messages from node → sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppEvent {
    /// Response to [`AppCmd::Hello`].
    HelloAck {
        version: u16,
        capabilities: Vec<AppCapability>,
        error: Option<AppErrorCode>,
        message: Option<String>,
    },
    /// Raw payload received from a remote peer.
    Incoming {
        from: String,
        protocol_id: u16,
        payload: Vec<u8>,
    },
    /// Acknowledgement for a control command (Subscribe/Send/…).
    Ack { ok: bool, error: Option<String> },
    /// Structured error (handshake / policy / stream).
    Error {
        code: AppErrorCode,
        message: Option<String>,
    },
    /// Bulk data chunk toward sidecar (behavior in P3-05).
    StreamChunk {
        stream_id: u64,
        seq: u64,
        payload: Vec<u8>,
    },
    /// Advertise send/receive window (behavior in P3-05).
    StreamWindow { stream_id: u64, credits: u32 },
    /// Peer or host closed the stream (behavior in P3-05).
    StreamClosed {
        stream_id: u64,
        error: Option<AppErrorCode>,
    },
    /// Cancel notification (behavior in P3-05).
    StreamCancel { stream_id: u64 },
}

/// Encode a length-prefixed postcard frame.
pub fn encode_frame<T: Serialize>(msg: &T) -> Vec<u8> {
    let body = postcard::to_allocvec(msg).expect("postcard encode");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Encode a single [`AppEvent`] frame: `[4-byte LE len][postcard bytes]`.
pub fn encode_event(ev: &AppEvent) -> Vec<u8> {
    encode_frame(ev)
}

/// Encode a single [`AppCmd`] frame.
pub fn encode_cmd(cmd: &AppCmd) -> Vec<u8> {
    encode_frame(cmd)
}

/// Decode an [`AppCmd`] from a length-prefixed frame body (body only, no length prefix).
pub fn decode_cmd(body: &[u8]) -> Result<AppCmd, postcard::Error> {
    postcard::from_bytes(body)
}

/// Decode an [`AppEvent`] from a frame body (body only).
pub fn decode_event(body: &[u8]) -> Result<AppEvent, postcard::Error> {
    postcard::from_bytes(body)
}

/// Split a full frame into `(body_len, body)` after validating the length prefix.
///
/// Returns `None` if `buf` is shorter than 4 bytes or shorter than `4 + len`.
/// Returns `Err` if `len == 0` or `len > MAX_FRAME_BYTES`.
pub fn peek_frame(buf: &[u8]) -> Result<Option<&[u8]>, AppErrorCode> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(AppErrorCode::BadFrame);
    }
    let need = 4 + len as usize;
    if buf.len() < need {
        return Ok(None);
    }
    Ok(Some(&buf[4..need]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_cmd(cmd: AppCmd) {
        let frame = encode_cmd(&cmd);
        let body = peek_frame(&frame).unwrap().unwrap();
        let decoded = decode_cmd(body).unwrap();
        assert_eq!(decoded, cmd);
    }

    fn roundtrip_event(ev: AppEvent) {
        let frame = encode_event(&ev);
        let body = peek_frame(&frame).unwrap().unwrap();
        let decoded = decode_event(body).unwrap();
        assert_eq!(decoded, ev);
    }

    #[test]
    fn constants_smoke() {
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(MAX_FRAME_BYTES, 16 * 1024 * 1024);
        assert_eq!(QUEUE_CAP, 256);
        assert_eq!(DEFAULT_STREAM_CREDITS, 8);
        assert_eq!(MAX_STREAM_CHUNK_BYTES, 64 * 1024);
        assert_eq!(MAX_STREAMS_PER_CONNECTION, 32);
    }

    #[test]
    fn roundtrip_all_cmds() {
        roundtrip_cmd(AppCmd::Hello {
            version: PROTOCOL_VERSION,
            capabilities: vec![AppCapability::Subscribe, AppCapability::Send],
            token: Some("tok".into()),
        });
        roundtrip_cmd(AppCmd::Subscribe { protocol_id: 42 });
        roundtrip_cmd(AppCmd::Unsubscribe { protocol_id: 42 });
        roundtrip_cmd(AppCmd::Send {
            peer_id: "peer-a".into(),
            protocol_id: 7,
            payload: vec![1, 2, 3],
        });
        roundtrip_cmd(AppCmd::OpenStream {
            stream_id: 1,
            protocol_id: 9,
            peer_id: "peer-b".into(),
        });
        roundtrip_cmd(AppCmd::StreamChunk {
            stream_id: 1,
            seq: 0,
            payload: vec![9, 9],
        });
        roundtrip_cmd(AppCmd::StreamWindow {
            stream_id: 1,
            credits: 8,
        });
        roundtrip_cmd(AppCmd::StreamCancel { stream_id: 1 });
    }

    #[test]
    fn roundtrip_all_events() {
        roundtrip_event(AppEvent::HelloAck {
            version: PROTOCOL_VERSION,
            capabilities: vec![AppCapability::Subscribe],
            error: None,
            message: None,
        });
        roundtrip_event(AppEvent::HelloAck {
            version: PROTOCOL_VERSION,
            capabilities: vec![],
            error: Some(AppErrorCode::UnsupportedVersion),
            message: Some("need v1".into()),
        });
        roundtrip_event(AppEvent::Incoming {
            from: "peer-a".into(),
            protocol_id: 42,
            payload: b"hi".to_vec(),
        });
        roundtrip_event(AppEvent::Ack {
            ok: true,
            error: None,
        });
        roundtrip_event(AppEvent::Error {
            code: AppErrorCode::Unauthorized,
            message: Some("no token".into()),
        });
        roundtrip_event(AppEvent::StreamChunk {
            stream_id: 2,
            seq: 3,
            payload: vec![4],
        });
        roundtrip_event(AppEvent::StreamWindow {
            stream_id: 2,
            credits: 1,
        });
        roundtrip_event(AppEvent::StreamClosed {
            stream_id: 2,
            error: Some(AppErrorCode::Canceled),
        });
        roundtrip_event(AppEvent::StreamCancel { stream_id: 2 });
    }

    #[test]
    fn error_code_display() {
        assert_eq!(AppErrorCode::UnsupportedVersion.to_string(), "unsupported_version");
    }

    #[test]
    fn peek_frame_rejects_oversize() {
        let mut buf = (MAX_FRAME_BYTES + 1).to_le_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        assert_eq!(peek_frame(&buf), Err(AppErrorCode::BadFrame));
    }

    #[test]
    fn peek_frame_incomplete() {
        assert_eq!(peek_frame(&[1, 0, 0, 0]), Ok(None));
        assert_eq!(peek_frame(&[1, 0]), Ok(None));
    }

    /// Golden postcard body for Subscribe — lock wire encoding for regressions.
    #[test]
    fn golden_subscribe_body() {
        let cmd = AppCmd::Subscribe { protocol_id: 42 };
        let body = postcard::to_allocvec(&cmd).unwrap();
        // Discriminant 1 (Hello=0) + varint protocol_id 42
        assert_eq!(body, vec![1, 42]);
    }

    /// Golden full frame for Incoming event.
    #[test]
    fn golden_incoming_frame() {
        let ev = AppEvent::Incoming {
            from: "a".into(),
            protocol_id: 1,
            payload: vec![0xAB],
        };
        let frame = encode_event(&ev);
        let body = peek_frame(&frame).unwrap().unwrap();
        let decoded = decode_event(body).unwrap();
        assert_eq!(decoded, ev);
        // Discriminant Incoming=1 after HelloAck=0
        assert_eq!(body[0], 1);
        // Persist exact bytes for future compatibility checks.
        assert_eq!(
            frame,
            [
                6, 0, 0, 0, // len = 6
                1, // Incoming
                1, b'a', // string "a"
                1, // protocol_id = 1
                1, 0xAB, // payload len=1, byte
            ]
        );
    }
}
