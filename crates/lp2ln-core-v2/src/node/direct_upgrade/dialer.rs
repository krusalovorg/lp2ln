use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use rand::Rng;

use crate::crypto::NodeKeypair;
use crate::packet::Packet;
use crate::protocol::control::{NatCandidate, NatCandidateKind, NetworkControlPayload};
use crate::protocol::handshake;
use crate::router::Router;
use crate::transport::Transport;
use crate::types::{PeerId, SessionId};

#[async_trait]
pub trait DirectDialer: Send + Sync {
    async fn direct_connect(
        &self,
        transport_name: &str,
        addr: SocketAddr,
        expected_peer: Option<PeerId>,
    ) -> Result<SessionId>;
}

/// Uses the same handshake path as [`crate::node::runtime::NodeRuntime::connect`].
pub struct CoreDirectDialer {
    pub router: Arc<Router>,
    pub transports: Vec<Arc<dyn Transport>>,
    pub keypair: NodeKeypair,
    pub obfuscation_protocols: Vec<String>,
}

#[async_trait]
impl DirectDialer for CoreDirectDialer {
    async fn direct_connect(
        &self,
        transport_name: &str,
        addr: SocketAddr,
        expected_peer: Option<PeerId>,
    ) -> Result<SessionId> {
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

        let session = transport.dial(addr).await?;
        let session_id = SessionId::from(session.id().to_string());
        if let Some(pid) = expected_peer {
            self.router
                .register_session(pid, session_id.clone(), session.clone());
        } else {
            self.router
                .register_session_only(session_id.clone(), session.clone());
        }
        session.spawn_reader(self.router.incoming_sender());

        let handshake_payload = handshake::encode_hello(self.obfuscation_protocols.clone(), None);
        let handshake = Packet {
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
        };
        self.router
            .send_to_session(session_id.clone(), handshake)
            .await?;
        Ok(session_id)
    }
}

async fn build_local_nat_candidates(
    listens: &HashMap<String, SocketAddr>,
    transports: &[Arc<dyn Transport>],
) -> Vec<NatCandidate> {
    let mut candidates = Vec::new();
    for (proto_raw, addr) in listens {
        let proto = proto_raw.to_ascii_lowercase();
        candidates.push(NatCandidate {
            protocol: proto.clone(),
            addr: addr.to_string(),
            kind: NatCandidateKind::Host,
            priority: 200,
        });
        if proto == "udp" {
            if let Some(transport) = transports
                .iter()
                .find(|t| t.name().eq_ignore_ascii_case("udp"))
            {
                if let Ok(public_addr) = transport.get_public_address(addr.port()).await {
                    candidates.push(NatCandidate {
                        protocol: "udp".to_string(),
                        addr: format!("{}:{}", public_addr.ip, public_addr.port),
                        kind: NatCandidateKind::Srflx,
                        priority: 300,
                    });
                }
            }
        }
    }
    candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
    candidates.dedup_by(|a, b| a.protocol == b.protocol && a.addr == b.addr && a.kind == b.kind);
    candidates
}

#[async_trait]
pub trait NatTraversalTrigger: Send + Sync {
    async fn trigger_nat_traversal(&self, peer_id: PeerId) -> Result<()>;
}

pub struct CoreNatTraversalTrigger {
    pub router: Arc<Router>,
    pub keypair: NodeKeypair,
    pub transports: Vec<Arc<dyn Transport>>,
    pub listens: HashMap<String, SocketAddr>,
    pub nat_state: Arc<crate::nat::NatTraversalState>,
}

#[async_trait]
impl NatTraversalTrigger for CoreNatTraversalTrigger {
    async fn trigger_nat_traversal(&self, route_peer_id: PeerId) -> Result<()> {
        let local_candidates = build_local_nat_candidates(&self.listens, &self.transports).await;
        if local_candidates.is_empty() {
            return Err(anyhow::anyhow!("No local candidates for NAT traversal"));
        }
        let session_id = format!("{:016x}", rand::rng().random::<u64>());
        let offer = self.nat_state.create_offer(
            session_id.clone(),
            route_peer_id.as_str().to_string(),
            local_candidates,
        );
        let payload = NetworkControlPayload::NatOffer { offer }
            .encode()
            .map_err(anyhow::Error::msg)?;
        let packet = Packet {
            signature: None,
            data: payload,
            nodes: vec![],
            sender: self.keypair.peer_id().to_string(),
            receiver: route_peer_id.as_str().to_string(),
            max_hops: 2,
            request_id: None,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };
        let _ = self
            .router
            .send_to_peer(route_peer_id, packet, None)
            .await?;
        Ok(())
    }
}
