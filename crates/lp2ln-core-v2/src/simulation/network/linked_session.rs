use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};

use crate::packet::Packet;
use crate::sessions::session::{IncomingPacket, LinkKind, Session};
use crate::transport::tcp::codec::{decode_packet, encode_packet};

/// In-memory session that delivers wire frames to a remote router ingress channel.
pub struct LinkedSession {
    id: String,
    /// Peer id of the node at the far end of this link (who we are connected to).
    remote_peer_id: String,
    /// Our peer id — ingress `from_node` for packets we deliver to the remote.
    local_peer_id: String,
    /// Session id registered on the remote router for this link.
    remote_session_id: String,
    remote_incoming: mpsc::Sender<IncomingPacket>,
    latency_ms: u16,
}

impl LinkedSession {
    pub fn new(
        id: impl Into<String>,
        remote_peer_id: impl Into<String>,
        local_peer_id: impl Into<String>,
        remote_session_id: impl Into<String>,
        remote_incoming: mpsc::Sender<IncomingPacket>,
        latency_ms: u16,
    ) -> Arc<Self> {
        Arc::new(Self {
            id: id.into(),
            remote_peer_id: remote_peer_id.into(),
            local_peer_id: local_peer_id.into(),
            remote_session_id: remote_session_id.into(),
            remote_incoming,
            latency_ms,
        })
    }
}

#[async_trait]
impl Session for LinkedSession {
    fn id(&self) -> &str {
        &self.id
    }

    fn peer_id(&self) -> Option<&str> {
        Some(&self.remote_peer_id)
    }

    fn kind(&self) -> LinkKind {
        LinkKind::DirectTcp
    }

    async fn send(&self, packet: Packet) -> Result<u64> {
        self.send_wire(encode_packet(packet)?).await
    }

    async fn send_wire(&self, encoded: Vec<u8>) -> Result<u64> {
        if self.latency_ms > 0 {
            sleep(Duration::from_millis(u64::from(self.latency_ms))).await;
        }
        let packet = decode_packet(encoded)?;
        let bytes = packet.wire_size_estimate() as u64;
        let incoming = IncomingPacket {
            session_id: self.remote_session_id.clone(),
            from_node: Some(self.local_peer_id.clone()),
            packet,
        };
        // Do not block the sender router on a full remote ingress queue; sim harness
        // prioritizes liveness over backpressure fidelity.
        let tx = self.remote_incoming.clone();
        tokio::spawn(async move {
            let _ = tx.send(incoming).await;
        });
        Ok(bytes)
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }

    fn spawn_reader(self: Arc<Self>, _incoming_packets_tx: mpsc::Sender<IncomingPacket>) {}
}
