use crate::node::runtime::NodeRuntime;
use crate::packet::Packet;
use crate::protocol::handshake;
use crate::sessions::session::IncomingPacket;
use crate::types::{PeerId, SessionId};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use tokio::sync::broadcast::error::RecvError;

impl NodeRuntime {
    pub async fn dial(
        &self,
        transport_name: &str,
        addr: SocketAddr,
    ) -> Result<Arc<dyn crate::sessions::Session>> {
        let transport = self
            .transports
            .iter()
            .find(|t| t.name() == transport_name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Transport '{}' is not registered in runtime",
                    transport_name
                )
            })?;
        transport.dial(addr).await
    }

    pub async fn connect(&self, transport_name: &str, addr: SocketAddr) -> Result<SessionId> {
        let router = self
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Node is not started, call start() first"))?;
        let session = self.dial(transport_name, addr).await?;
        let session_id = SessionId::from(session.id().to_string());
        router.register_session_only(session_id.clone(), session.clone());
        session.spawn_reader(router.incoming_sender());
        let mut obf_protocols: Vec<String> =
            self.options.transport_obfuscation.keys().cloned().collect();
        obf_protocols.sort();
        let handshake_payload =
            handshake::encode_hello(obf_protocols, self.options.quic.obfs.hello_obfs_mode());
        let handshake_pkt = Packet {
            signature: None,
            data: handshake_payload,
            nodes: vec![],
            sender: self.keypair.peer_id().to_string(),
            receiver: String::new(),
            max_hops: 8,
            request_id: None,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
            protocol_id: None,
        };
        router
            .send_to_session(session_id.clone(), handshake_pkt)
            .await?;
        Ok(session_id)
    }

    pub async fn send_with_options(
        &self,
        route_peer_id: PeerId,
        data: Vec<u8>,
        receiver: Option<String>,
        max_hops: Option<u8>,
        nodes: Option<Vec<String>>,
    ) -> Result<u64> {
        let router = self
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Node is not started, call start() first"))?;
        let sender = self.keypair.peer_id();
        let receiver_str = receiver
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| route_peer_id.as_str().to_string());
        let packet = Packet {
            signature: None,
            data,
            nodes: nodes.unwrap_or_default(),
            sender: sender.to_string(),
            receiver: receiver_str,
            max_hops: max_hops.unwrap_or(8),
            request_id: None,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
            protocol_id: None,
        };
        router.send_to_peer(route_peer_id, packet, None).await
    }

    pub async fn send(&self, peer_id: PeerId, data: Vec<u8>) -> Result<u64> {
        self.send_with_options(peer_id, data, None, None, None)
            .await
    }

    pub async fn send_with_options_and_wait_reply(
        &self,
        route_peer_id: PeerId,
        data: Vec<u8>,
        receiver: Option<String>,
        max_hops: Option<u8>,
        nodes: Option<Vec<String>>,
        timeout: Duration,
    ) -> Result<(u64, Vec<u8>)> {
        let router = self
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Node is not started, call start() first"))?;
        let mut sub = router.subscribe();
        let request_id = self
            .send_with_options(route_peer_id.clone(), data, receiver, max_hops, nodes)
            .await?;
        let reply = self
            .recv_reply_matching(&mut sub, &route_peer_id, request_id, timeout)
            .await?;
        Ok((request_id, reply))
    }

    pub async fn send_and_wait_reply(
        &self,
        peer_id: PeerId,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let router = self
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Node is not started, call start() first"))?;
        let mut sub = router.subscribe();
        let request_id = self
            .send_with_options(peer_id.clone(), data, None, None, None)
            .await?;
        self.recv_reply_matching(&mut sub, &peer_id, request_id, timeout)
            .await
    }

    pub async fn send_to_session(&self, session_id: SessionId, data: Vec<u8>) -> Result<u64> {
        let router = self
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Node is not started, call start() first"))?;
        let sender = self.keypair.peer_id();
        let packet = Packet {
            signature: None,
            data,
            nodes: vec![],
            sender: sender.to_string(),
            receiver: sender.to_string(),
            max_hops: 8,
            request_id: None,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
            protocol_id: None,
        };
        router.send_to_session(session_id, packet).await
    }

    pub async fn disconnect_peer(&self, peer_id: &str) -> Result<()> {
        let pid = PeerId::from(peer_id);
        self.session_manager.close_all_sessions_for_peer(&pid).await
    }

    pub async fn disconnect_session(&self, session_id: &str) -> Result<()> {
        let sid = SessionId::from(session_id);
        self.session_manager.close_session(&sid).await
    }

    async fn recv_reply_matching(
        &self,
        sub: &mut tokio::sync::broadcast::Receiver<Arc<IncomingPacket>>,
        route_peer_id: &PeerId,
        request_id: u64,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let our_id = self.keypair.peer_id().to_string();
        let peer_str = route_peer_id.as_str().to_string();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(anyhow::anyhow!(
                    "recv_reply_matching: timeout waiting for request_id {}",
                    request_id
                ));
            }
            let incoming = tokio::time::timeout(remaining, sub.recv())
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "recv_reply_matching: timeout waiting for request_id {}",
                        request_id
                    )
                })?;
            let incoming = match incoming {
                Ok(p) => p,
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => {
                    return Err(anyhow::anyhow!(
                        "recv_reply_matching: incoming channel closed"
                    ));
                }
            };
            let packet = &incoming.packet;
            if packet.request_id != Some(request_id) {
                continue;
            }
            let via = incoming
                .from_node
                .as_deref()
                .unwrap_or(packet.sender.as_str());
            if via != peer_str {
                continue;
            }
            if !packet.receiver.is_empty() && packet.receiver != our_id {
                continue;
            }
            return Ok(packet.data.clone());
        }
    }
}
