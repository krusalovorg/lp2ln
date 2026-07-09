use rand::Rng;

use crate::node::runtime::NodeRuntime;
use crate::protocol::control::{NatCandidate, NatCandidateKind, NetworkControlPayload};
use crate::types::PeerId;

impl NodeRuntime {
    async fn build_local_nat_candidates(&self) -> Vec<NatCandidate> {
        let mut candidates = Vec::new();
        for listen in self.options.listens.iter() {
            let proto = listen.key().to_ascii_lowercase();
            let addr = *listen.value();
            candidates.push(NatCandidate {
                protocol: proto.clone(),
                addr: addr.to_string(),
                kind: NatCandidateKind::Host,
                priority: 200,
            });
            if proto == "udp" {
                if let Some(transport) = self
                    .transports
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
        candidates
            .dedup_by(|a, b| a.protocol == b.protocol && a.addr == b.addr && a.kind == b.kind);
        candidates
    }

    pub async fn start_nat_traversal(&self, route_peer_id: PeerId) -> anyhow::Result<String> {
        let router = self
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Node is not started, call start() first"))?;
        let local_candidates = self.build_local_nat_candidates().await;
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
        let packet = crate::packet::Packet {
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
        let _ = router.send_to_peer(route_peer_id, packet, None).await?;
        Ok(session_id)
    }
}
