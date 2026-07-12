use std::collections::HashMap;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::node::options::{FlowTraceOptions, NodeRole};
use crate::protocol::control::NetworkControlPayload;
use crate::router::Router;

pub(crate) struct FlowTraceService;

impl FlowTraceService {
    pub(crate) fn is_enabled(options: &FlowTraceOptions) -> bool {
        let enabled_from_env = std::env::var("LP2LN_TRACE_FLOW")
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                matches!(v.as_str(), "1" | "true" | "yes" | "on")
            })
            .unwrap_or(false);
        enabled_from_env || options.enabled
    }

    pub(crate) async fn run(
        router: &Router,
        node_role: NodeRole,
        our_peer_id: String,
        options: &FlowTraceOptions,
        cancel: CancellationToken,
    ) {
        if !Self::is_enabled(options) {
            return;
        }

        let json_packets = options.json_packets;
        let payload_preview_bytes = options.payload_preview_bytes.min(256);
        let mut trace_rx = router.subscribe();
        crate::info!(
            "[NodeRuntime] flow-trace enabled on {:?}; reporting every 10s",
            node_role
        );
        use tokio::sync::broadcast::error::RecvError;
        use tokio::time::{self, MissedTickBehavior};

        let mut interval = time::interval(Duration::from_secs(10));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut counters: HashMap<(String, String, String, u8, u8, bool, String), u64> =
            HashMap::new();

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                evt = trace_rx.recv() => {
                    match evt {
                        Ok(incoming) => {
                            let packet = &incoming.packet;
                            let via = incoming
                                .from_node
                                .clone()
                                .unwrap_or_else(|| packet.sender.clone());
                            let hops_len = packet.nodes.len().min(u8::MAX as usize) as u8;
                            let is_forward =
                                !packet.receiver.is_empty() && packet.receiver != our_peer_id;
                            let payload_kind = payload_kind(&packet.data);
                            if json_packets {
                                let preview = packet
                                    .data
                                    .iter()
                                    .take(payload_preview_bytes)
                                    .map(|b| format!("{:02x}", b))
                                    .collect::<Vec<_>>()
                                    .join("");
                                let row = serde_json::json!({
                                    "sender": packet.sender.clone(),
                                    "receiver": packet.receiver.clone(),
                                    "via": via.clone(),
                                    "payload_kind": payload_kind.clone(),
                                    "payload_len": packet.data.len(),
                                    "payload_preview_hex": preview,
                                    "payload_preview_truncated": packet.data.len() > payload_preview_bytes,
                                    "path_len": hops_len,
                                    "hops_left": packet.max_hops,
                                    "is_forward": is_forward,
                                });
                                match serde_json::to_string_pretty(&row) {
                                    Ok(pretty) => {
                                        crate::info!("[FLOWTRACE]\n{}", pretty);
                                    }
                                    Err(_) => {
                                        crate::info!("[FLOWTRACE] packet {}", row);
                                    }
                                }
                            }
                            let key = (
                                packet.sender.clone(),
                                packet.receiver.clone(),
                                via,
                                hops_len,
                                packet.max_hops,
                                is_forward,
                                payload_kind,
                            );
                            *counters.entry(key).or_insert(0) += 1;
                        }
                        Err(RecvError::Lagged(skipped)) => {
                            crate::warn!("[NodeRuntime] flow-trace lagged, skipped {} packets", skipped);
                        }
                        Err(RecvError::Closed) => break,
                    }
                }
                _ = interval.tick() => {
                    if counters.is_empty() {
                        continue;
                    }
                    let mut rows: Vec<_> = counters.into_iter().collect();
                    rows.sort_by(|a, b| b.1.cmp(&a.1));
                    let top = rows
                        .into_iter()
                        .take(12)
                        .map(|((sender, receiver, via, hops_len, hops_left, is_forward, payload_kind), cnt)| {
                            let kind = if is_forward { "fwd" } else { "local" };
                            format!(
                                "{}:{} {} {}->{} via={} path_len={} hops_left={}",
                                cnt,
                                kind,
                                payload_kind,
                                sender,
                                receiver,
                                via,
                                hops_len,
                                hops_left
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" | ");
                    crate::info!("[FLOWTRACE] top {}", top);
                    counters = HashMap::new();
                }
            }
        }
    }
}

fn payload_kind(data: &[u8]) -> String {
    if data.is_empty() {
        "local:handshake".to_string()
    } else if crate::protocol::handshake::decode_hello(data).is_some() {
        "local:handshake_hello".to_string()
    } else if data == b"hs_ack" {
        "local:handshake_ack".to_string()
    } else if data == b"ping" {
        "local:ping".to_string()
    } else if data == b"pong" {
        "local:pong".to_string()
    } else if let Ok(ctrl) = NetworkControlPayload::decode(data) {
        let tag = match ctrl {
            NetworkControlPayload::AnnounceNodeDescriptor { .. } => {
                "control:AnnounceNodeDescriptor"
            }
            NetworkControlPayload::RequestPeers { .. } => "control:RequestPeers",
            NetworkControlPayload::PeersResponse { .. } => "control:PeersResponse",
            NetworkControlPayload::AnnounceEvidence { .. } => "control:AnnounceEvidence",
            NetworkControlPayload::PingPeerQuality { .. } => "control:PingPeerQuality",
            NetworkControlPayload::PongPeerQuality { .. } => "control:PongPeerQuality",
            NetworkControlPayload::RequestDescriptors { .. } => "control:RequestDescriptors",
            NetworkControlPayload::RequestCapabilities { .. } => "control:RequestCapabilities",
            NetworkControlPayload::FindRelays { .. } => "control:FindRelays",
            NetworkControlPayload::FindProviders { .. } => "control:FindProviders",
            NetworkControlPayload::RequestAdjacency { .. } => "control:RequestAdjacency",
            NetworkControlPayload::AdjacencyResponse { .. } => "control:AdjacencyResponse",
            NetworkControlPayload::NatOffer { .. } => "control:NatOffer",
            NetworkControlPayload::NatAnswer { .. } => "control:NatAnswer",
            NetworkControlPayload::NatPunchStart { .. } => "control:NatPunchStart",
            NetworkControlPayload::NatPunchResult { .. } => "control:NatPunchResult",
        };
        tag.to_string()
    } else {
        "data:opaque".to_string()
    }
}
