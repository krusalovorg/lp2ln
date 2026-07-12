use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::packet::Packet;
use crate::simulation::topology::{SimEdge, SimNodeId, TopologySnapshot};
use crate::types::PeerId;
use crate::{SessionId, sessions::session::IncomingPacket};

use super::graph::{find_farthest_pair, shortest_path_hops, FarthestPair};
use super::linked_session::LinkedSession;
use super::metrics::{
    make_routing_packet, make_routing_packet_with_id, wait_for_deliveries, wait_for_request_id,
    RoutingMetrics,
};
use super::node::SimNode;

pub struct SimNetwork {
    nodes: BTreeMap<SimNodeId, SimNode>,
    cancel: CancellationToken,
}

impl SimNetwork {
    pub async fn from_topology_snapshot(snapshot: &TopologySnapshot) -> Result<Self> {
        let cancel = CancellationToken::new();
        let mut nodes: BTreeMap<SimNodeId, SimNode> = BTreeMap::new();

        for (&node_id, state) in &snapshot.nodes {
            if !state.online {
                continue;
            }
            nodes.insert(node_id, SimNode::spawn(node_id, cancel.clone()));
        }

        for edge in &snapshot.edges {
            wire_edge(snapshot, edge, &nodes)?;
        }

        // Allow router worker tasks to start.
        tokio::task::yield_now().await;

        Ok(Self { nodes, cancel })
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn peer_id(&self, node: SimNodeId) -> &str {
        &self.nodes.get(&node).expect("sim node").peer_id
    }

    pub fn router(&self, node: SimNodeId) -> Arc<crate::router::Router> {
        self.nodes.get(&node).expect("sim node").router.clone()
    }

    pub fn subscribe(
        &self,
        node: SimNodeId,
    ) -> broadcast::Receiver<Arc<IncomingPacket>> {
        self.nodes.get(&node).expect("sim node").router.subscribe()
    }

    pub fn farthest_pair(&self, snapshot: &TopologySnapshot) -> Option<FarthestPair> {
        find_farthest_pair(snapshot)
    }

    pub fn farthest_pair_from_snapshot(snapshot: &TopologySnapshot) -> Option<FarthestPair> {
        find_farthest_pair(snapshot)
    }

    pub async fn wait_one(
        &self,
        to: SimNodeId,
        sender: &str,
        receiver: &str,
        wait_timeout: Duration,
    ) -> RoutingMetrics {
        let mut rx = self.subscribe(to);
        let mut metrics = wait_for_deliveries(&mut rx, 1, sender, receiver, wait_timeout).await;
        metrics.sent = 1;
        metrics
    }

    pub async fn flood_and_wait_count(
        &self,
        from: SimNodeId,
        to: SimNodeId,
        sender: &str,
        receiver: &str,
        count: usize,
        payload_size: usize,
        max_hops: u8,
        wait_timeout: Duration,
    ) -> RoutingMetrics {
        let started = std::time::Instant::now();
        let mut delivered = 0usize;
        let mut total_hops = 0usize;
        let per_packet_timeout = wait_timeout
            .checked_div(count as u32)
            .unwrap_or(Duration::from_secs(3))
            .max(Duration::from_secs(1));
        let mut rx = self.subscribe(to);

        for i in 0..count {
            let request_id = i as u64 + 1;
            let packet = make_routing_packet_with_id(
                sender,
                receiver,
                payload_size,
                max_hops,
                Some(request_id),
            );
            if self.send_from(from, packet).await.is_err() {
                continue;
            }
            if let Some(hops) =
                wait_for_request_id(&mut rx, request_id, sender, receiver, per_packet_timeout).await
            {
                delivered += 1;
                total_hops += hops;
            }
            tokio::task::yield_now().await;
        }

        RoutingMetrics {
            sent: count,
            delivered,
            dropped: count.saturating_sub(delivered),
            total_hops,
            shortest_path_hops: 0,
            wall_time: started.elapsed(),
        }
    }

    pub async fn send_from(
        &self,
        from: SimNodeId,
        packet: Packet,
    ) -> Result<u64> {
        let router = self.router(from);
        let target = PeerId::from(packet.receiver.as_str());
        router.send_to_peer(target, packet, None).await
    }

    pub async fn send_and_wait(
        &self,
        snapshot: &TopologySnapshot,
        from: SimNodeId,
        to: SimNodeId,
        payload_size: usize,
        max_hops: u8,
        wait_timeout: Duration,
    ) -> Result<RoutingMetrics> {
        let sender = self.peer_id(from).to_string();
        let receiver = self.peer_id(to).to_string();
        let mut rx = self.subscribe(to);
        let packet = make_routing_packet(&sender, &receiver, payload_size, max_hops);
        self.send_from(from, packet).await?;
        let mut metrics = wait_for_deliveries(&mut rx, 1, &sender, &receiver, wait_timeout).await;
        metrics.shortest_path_hops = shortest_path_hops(snapshot, from, to).unwrap_or(0);
        metrics.sent = 1;
        Ok(metrics)
    }

    pub async fn flood_and_wait(
        &self,
        snapshot: &TopologySnapshot,
        from: SimNodeId,
        to: SimNodeId,
        count: usize,
        payload_size: usize,
        max_hops: u8,
        wait_timeout: Duration,
    ) -> Result<RoutingMetrics> {
        let sender = self.peer_id(from).to_string();
        let receiver = self.peer_id(to).to_string();
        let mut rx = self.subscribe(to);
        for _ in 0..count {
            let packet = make_routing_packet(&sender, &receiver, payload_size, max_hops);
            self.send_from(from, packet).await?;
        }
        let mut metrics =
            wait_for_deliveries(&mut rx, count, &sender, &receiver, wait_timeout).await;
        metrics.shortest_path_hops = shortest_path_hops(snapshot, from, to).unwrap_or(0);
        metrics.sent = count;
        Ok(metrics)
    }

    pub async fn shutdown(self) {
        self.cancel.cancel();
        let nodes: Vec<SimNode> = self.nodes.into_values().collect();
        for node in &nodes {
            node.router.close_incoming();
        }
        for node in nodes {
            node.join_run().await;
        }
    }
}

fn wire_edge(
    snapshot: &TopologySnapshot,
    edge: &SimEdge,
    nodes: &BTreeMap<SimNodeId, SimNode>,
) -> Result<()> {
    let a = edge.a;
    let b = edge.b;
    let node_a = nodes.get(&a).context("edge endpoint offline")?;
    let node_b = nodes.get(&b).context("edge endpoint offline")?;

    let latency_ms = snapshot
        .nodes
        .get(&a)
        .and_then(|n| n.peers.get(&b))
        .map(|p| p.latency_ms)
        .unwrap_or(0);

    let peer_a = node_a.peer_id.clone();
    let peer_b = node_b.peer_id.clone();
    let sess_a = format!("sess-{a}-{b}");
    let sess_b = format!("sess-{b}-{a}");

    let link_a = LinkedSession::new(
        &sess_a,
        &peer_b,
        &peer_a,
        &sess_b,
        node_b.incoming_sender(),
        latency_ms,
    );
    let link_b = LinkedSession::new(
        &sess_b,
        &peer_a,
        &peer_b,
        &sess_a,
        node_a.incoming_sender(),
        latency_ms,
    );

    node_a.router.register_session(
        PeerId::from(peer_b.as_str()),
        SessionId::from(sess_a.as_str()),
        link_a,
    );
    node_b.router.register_session(
        PeerId::from(peer_a.as_str()),
        SessionId::from(sess_b.as_str()),
        link_b,
    );
    Ok(())
}
