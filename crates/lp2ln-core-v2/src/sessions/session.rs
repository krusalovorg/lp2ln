use crate::packet::Packet;
use anyhow::Result;
use async_trait::async_trait;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkKind {
    DirectTcp,
    DirectUdp,
    DirectQuic,
    TunnelTcp,
    TunnelUdp,
    Relay,
}

impl fmt::Display for LinkKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkKind::DirectTcp => write!(f, "tcp"),
            LinkKind::DirectUdp => write!(f, "udp"),
            LinkKind::DirectQuic => write!(f, "quic"),
            LinkKind::TunnelTcp => write!(f, "tunnel_tcp"),
            LinkKind::TunnelUdp => write!(f, "tunnel_udp"),
            LinkKind::Relay => write!(f, "relay"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IncomingPacket {
    pub session_id: String,
    pub from_node: Option<String>,
    pub packet: Packet,
}

#[async_trait]
pub trait Session: Send + Sync {
    fn id(&self) -> &str;

    fn peer_id(&self) -> Option<&str>;

    fn kind(&self) -> LinkKind;

    async fn send(&self, packet: Packet) -> Result<u64>;

    /// Send pre-encoded wire bytes (postcard frame payload). Default encodes via [`send`].
    async fn send_wire(&self, encoded: Vec<u8>) -> Result<u64> {
        let _ = encoded;
        Err(anyhow::anyhow!(
            "send_wire not implemented for this session"
        ))
    }

    async fn close(&self) -> Result<()>;

    fn spawn_reader(
        self: std::sync::Arc<Self>,
        incoming_packets_tx: tokio::sync::mpsc::Sender<IncomingPacket>,
    );

    /// Returns true when the session's loss monitor is in compensate mode.
    /// Default: false (non-QUIC sessions never degrade by loss).
    fn is_degraded(&self) -> bool {
        false
    }

    /// Waits for this session's background tasks (reader/writer) to finish.
    ///
    /// Must be called only after `close()` has signalled cancellation, and
    /// always under a bounded timeout by the caller: a writer blocked
    /// mid-write can take up to its own write timeout to unwind. Sessions
    /// that spawn no tasks (fakes, relays) keep the default no-op.
    async fn join_tasks(&self) {}
}
