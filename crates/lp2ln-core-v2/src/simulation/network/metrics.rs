use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::broadcast;
use tokio::time::timeout;

use crate::packet::Packet;
use crate::sessions::session::IncomingPacket;

#[derive(Debug, Clone, Default)]
pub struct RoutingMetrics {
    pub sent: usize,
    pub delivered: usize,
    pub dropped: usize,
    pub total_hops: usize,
    pub shortest_path_hops: usize,
    pub wall_time: Duration,
}

impl RoutingMetrics {
    pub fn delivery_rate(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            self.delivered as f64 / self.sent as f64
        }
    }

    pub fn avg_hops(&self) -> f64 {
        if self.delivered == 0 {
            0.0
        } else {
            self.total_hops as f64 / self.delivered as f64
        }
    }
}

pub fn make_routing_packet(
    sender: &str,
    receiver: &str,
    payload_size: usize,
    max_hops: u8,
) -> Packet {
    make_routing_packet_with_id(sender, receiver, payload_size, max_hops, None)
}

pub fn make_routing_packet_with_id(
    sender: &str,
    receiver: &str,
    payload_size: usize,
    max_hops: u8,
    request_id: Option<u64>,
) -> Packet {
    Packet {
        signature: None,
        data: vec![0xAB; payload_size],
        nodes: Vec::new(),
        sender: sender.to_string(),
        receiver: receiver.to_string(),
        max_hops,
        request_id,
        chunk_stream_id: None,
        chunk_index: None,
        total_chunks: None,
        protocol_id: None,
    }
}

/// Wait until `expected` packets matching sender/receiver arrive on the subscriber.
pub async fn wait_for_deliveries(
    rx: &mut broadcast::Receiver<Arc<IncomingPacket>>,
    expected: usize,
    sender: &str,
    receiver: &str,
    wait_timeout: Duration,
) -> RoutingMetrics {
    let started = Instant::now();
    let mut delivered = 0usize;
    let mut total_hops = 0usize;

    let result = timeout(wait_timeout, async {
        while delivered < expected {
            match rx.recv().await {
                Ok(incoming) => {
                    let pkt = &incoming.packet;
                    if pkt.sender == sender && pkt.receiver == receiver {
                        delivered += 1;
                        total_hops += pkt.nodes.len() + 1; // edge count
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
    .await;

    let dropped = if result.is_err() {
        expected.saturating_sub(delivered)
    } else {
        0
    };

    RoutingMetrics {
        sent: expected,
        delivered,
        dropped,
        total_hops,
        shortest_path_hops: 0,
        wall_time: started.elapsed(),
    }
}

/// Wait for one packet with a specific request_id.
pub async fn wait_for_request_id(
    rx: &mut broadcast::Receiver<Arc<IncomingPacket>>,
    request_id: u64,
    sender: &str,
    receiver: &str,
    wait_timeout: Duration,
) -> Option<usize> {
    let result = timeout(wait_timeout, async {
        loop {
            match rx.recv().await {
                Ok(incoming) => {
                    let pkt = &incoming.packet;
                    if pkt.sender == sender
                        && pkt.receiver == receiver
                        && pkt.request_id == Some(request_id)
                    {
                        return Some(pkt.nodes.len() + 1); // edge count
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
    .await;
    result.unwrap_or(None)
}

/// Wait until `expected` unique packets (by request_id) matching sender/receiver arrive.
pub async fn wait_for_unique_deliveries(
    rx: &mut broadcast::Receiver<Arc<IncomingPacket>>,
    expected: usize,
    sender: &str,
    receiver: &str,
    wait_timeout: Duration,
) -> RoutingMetrics {
    wait_for_matching_deliveries(rx, expected, sender, receiver, wait_timeout, |_| true).await
}

pub(super) async fn wait_for_matching_deliveries(
    rx: &mut broadcast::Receiver<Arc<IncomingPacket>>,
    expected: usize,
    sender: &str,
    receiver: &str,
    wait_timeout: Duration,
    matches_id: impl Fn(u64) -> bool,
) -> RoutingMetrics {
    use std::collections::HashSet;
    let started = Instant::now();
    let mut seen = HashSet::new();
    let mut total_hops = 0usize;

    let _ = timeout(wait_timeout, async {
        while seen.len() < expected {
            match rx.recv().await {
                Ok(incoming) => {
                    let pkt = &incoming.packet;
                    if pkt.sender == sender
                        && pkt.receiver == receiver
                        && let Some(rid) = pkt.request_id
                        && matches_id(rid)
                        && seen.insert(rid)
                    {
                        total_hops += pkt.nodes.len() + 1; // edge count
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
    .await;

    let delivered = seen.len();
    let dropped = expected.saturating_sub(delivered);

    RoutingMetrics {
        sent: expected,
        delivered,
        dropped,
        total_hops,
        shortest_path_hops: 0,
        wall_time: started.elapsed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn range_filter_duplicates_and_lag_are_not_deliveries() {
        let (tx, mut rx) = broadcast::channel(4);
        for id in [42, 42, 80, 10, 10, 99] {
            tx.send(Arc::new(IncomingPacket {
                session_id: String::new(),
                from_node: None,
                packet: make_routing_packet_with_id("a", "b", 1, 1, Some(id)),
            }))
            .unwrap();
        }
        drop(tx);
        let sample =
            wait_for_matching_deliveries(&mut rx, 2, "a", "b", Duration::from_secs(1), |id| {
                (10..12).contains(&id)
            })
            .await;
        assert_eq!(sample.delivered, 1);
        assert_eq!(sample.dropped, 1);
    }
}
