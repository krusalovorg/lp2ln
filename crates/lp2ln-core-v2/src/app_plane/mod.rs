//! # EXPERIMENTAL
//!
//! App Plane v2 binary IPC (slice 08-09).
//!
//! Library types for sidecar ↔ node framing. The binary App Plane TCP server in
//! `lp2lnd` (`app_plane_server.rs`) is **not** started by the default daemon;
//! opt-in flag `experimental.app_plane` is reserved until P3/P4 lifecycle.
//!
//! Wire protocol: 4-byte LE length prefix + postcard-encoded AppMsg.
//! Sidecar apps register a protocol_id; packets with that id are routed to
//! a bounded mpsc channel. Slow consumers are dropped from the tail — they
//! cannot block the router broadcast.
//!
//! A separate JSON debug IPC (`ipc_tcp.rs`) remains unchanged.

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

pub const APP_PLANE_QUEUE_CAP: usize = 256;

/// Messages from sidecar → node.
#[derive(Debug, Serialize, Deserialize)]
pub enum AppCmd {
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
}

/// Messages from node → sidecar.
#[derive(Debug, Serialize, Deserialize)]
pub enum AppEvent {
    /// Raw payload received from a remote peer.
    Incoming {
        from: String,
        protocol_id: u16,
        payload: Vec<u8>,
    },
    /// Acknowledgement for a Send command.
    Ack { ok: bool, error: Option<String> },
}

/// Encode a single AppEvent frame: [4-byte LE len][postcard bytes].
pub fn encode_event(ev: &AppEvent) -> Vec<u8> {
    let body = postcard::to_allocvec(ev).expect("postcard encode");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Decode an AppCmd from a length-prefixed frame body (body only, no length prefix).
pub fn decode_cmd(body: &[u8]) -> Result<AppCmd, postcard::Error> {
    postcard::from_bytes(body)
}

/// Per-protocol broadcast to registered sidecar connections.
/// Each connection gets its own bounded channel; if full, the packet is dropped
/// for that connection only — the router is never blocked.
#[derive(Clone, Default)]
pub struct AppPlaneRouter {
    // protocol_id → list of senders (one per connected sidecar)
    subs: Arc<DashMap<u16, Vec<mpsc::Sender<AppEvent>>>>,
}

impl AppPlaneRouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe to a protocol_id; returns the receiving half.
    pub fn subscribe(&self, protocol_id: u16) -> mpsc::Receiver<AppEvent> {
        let (tx, rx) = mpsc::channel(APP_PLANE_QUEUE_CAP);
        self.subs.entry(protocol_id).or_default().push(tx);
        rx
    }

    /// Remove all dead senders for a protocol_id (called when connection closes).
    pub fn prune(&self, protocol_id: u16) {
        if let Some(mut entry) = self.subs.get_mut(&protocol_id) {
            entry.retain(|tx| !tx.is_closed());
        }
    }

    /// Dispatch an incoming event to all live subscribers for `protocol_id`.
    /// Dead senders are lazily pruned.
    pub fn dispatch(&self, protocol_id: u16, ev: AppEvent) {
        let AppEvent::Incoming { from, payload, .. } = ev else {
            return;
        };
        if let Some(mut entry) = self.subs.get_mut(&protocol_id) {
            // try_send: if full, drop for this subscriber — never block.
            entry.retain(|tx| {
                !tx.is_closed()
                    && tx
                        .try_send(AppEvent::Incoming {
                            from: from.clone(),
                            protocol_id,
                            payload: payload.clone(),
                        })
                        .is_ok()
            });
        }
    }
}
