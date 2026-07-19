use crate::metrics::contract::{AggregatedMetricsSnapshot, NodeHealthSnapshot, PeerHealthSnapshot};
use crate::sessions::manager::SessionManager;
use crate::types::PeerId;

pub struct MetricsAggregator;

impl MetricsAggregator {
    pub fn aggregate(
        session_manager: &SessionManager,
        max_connections_hint: usize,
    ) -> AggregatedMetricsSnapshot {
        let per_peer = session_manager.peer_metrics_rollup();
        let mut node = NodeHealthSnapshot {
            active_connections: session_manager.total_sessions_count() as u16,
            active_peers: per_peer.len() as u16,
            ..NodeHealthSnapshot::default()
        };
        let mut peers = Vec::with_capacity(per_peer.len());

        for (peer_id, metrics_list) in per_peer {
            let mut s = PeerHealthSnapshot {
                peer_id,
                sessions_count: metrics_list.len() as u16,
                ..PeerHealthSnapshot::default()
            };
            let mut last_activity_sum = 0u64;
            for m in &metrics_list {
                if m.is_active {
                    s.active_sessions_count += 1;
                }
                s.packets_sent += m.packets_sent;
                s.packets_received += m.packets_received;
                s.bytes_sent += m.bytes_sent;
                s.bytes_received += m.bytes_received;
                s.total_errors += m.total_errors();
                last_activity_sum += m.time_since_last_activity().as_secs();
            }
            if s.sessions_count > 0 {
                s.avg_last_activity_secs_ago = last_activity_sum / s.sessions_count as u64;
            }
            node.packets_sent += s.packets_sent;
            node.packets_received += s.packets_received;
            node.bytes_sent += s.bytes_sent;
            node.bytes_received += s.bytes_received;
            node.total_errors += s.total_errors;
            peers.push(s);
        }

        let denom = max_connections_hint.max(1) as f32;
        let conn_pressure = (node.active_connections as f32 / denom).min(1.0);
        let err_pressure = if node.packets_sent + node.packets_received > 0 {
            (node.total_errors as f32 / (node.packets_sent + node.packets_received) as f32).min(1.0)
        } else {
            0.0
        };
        node.conn_load_estimate = (conn_pressure * 0.7 + err_pressure * 0.3).min(1.0);
        node.local_capacity_pressure = (conn_pressure * 0.8 + err_pressure * 0.2).min(1.0);

        AggregatedMetricsSnapshot {
            collected_at_ms: crate::topology::now_ms(),
            node,
            peers,
        }
    }

    pub fn peer_ids(snapshot: &AggregatedMetricsSnapshot) -> Vec<PeerId> {
        snapshot.peers.iter().map(|p| p.peer_id.clone()).collect()
    }
}
