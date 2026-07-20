//! # EXPERIMENTAL
//!
//! App Plane host-side fanout (P3).
//!
//! Wire types live in `lp2ln-app-protocol`. This module keeps the bounded
//! per-subscriber router used by the IPC host.
//!
//! The binary App Plane server in `lp2lnd` starts when `experimental.app_plane`
//! is set (P3-02: UDS / named pipe). Subscribe push-to-socket is P3-03.
//!
//! A separate JSON debug IPC (`ipc_tcp.rs`) remains unchanged.

use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

pub use lp2ln_app_protocol::{
    AppCapability, AppCmd, AppErrorCode, AppEvent, DEFAULT_STREAM_CREDITS, MAX_FRAME_BYTES,
    MAX_STREAM_CHUNK_BYTES, MAX_STREAMS_PER_CONNECTION, PROTOCOL_VERSION, QUEUE_CAP, decode_cmd,
    decode_event, encode_cmd, encode_event, encode_frame, peek_frame,
};

/// Compat alias for [`QUEUE_CAP`].
pub const APP_PLANE_QUEUE_CAP: usize = QUEUE_CAP;

/// Per-protocol broadcast to registered sidecar connections.
/// Each connection gets its own bounded channel; if full, the packet is dropped
/// for that connection only — the router is never blocked, and the subscriber
/// stays registered (slow sidecar isolation).
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
        let (tx, rx) = mpsc::channel(QUEUE_CAP);
        self.subs.entry(protocol_id).or_default().push(tx);
        rx
    }

    /// Remove closed senders for a protocol_id (connection close / unsubscribe).
    pub fn prune(&self, protocol_id: u16) {
        if let Some(mut entry) = self.subs.get_mut(&protocol_id) {
            entry.retain(|tx| !tx.is_closed());
            if entry.is_empty() {
                drop(entry);
                self.subs.remove(&protocol_id);
            }
        }
    }

    /// Number of live senders for `protocol_id` (tests / diagnostics).
    pub fn subscriber_count(&self, protocol_id: u16) -> usize {
        self.subs
            .get(&protocol_id)
            .map(|e| e.iter().filter(|tx| !tx.is_closed()).count())
            .unwrap_or(0)
    }

    /// Dispatch an incoming event to all live subscribers for `protocol_id`.
    /// Full queues drop the frame for that subscriber only — never remove a healthy sub.
    pub fn dispatch(&self, protocol_id: u16, ev: AppEvent) {
        let AppEvent::Incoming { from, payload, .. } = ev else {
            return;
        };
        if let Some(mut entry) = self.subs.get_mut(&protocol_id) {
            entry.retain(|tx| {
                if tx.is_closed() {
                    return false;
                }
                match tx.try_send(AppEvent::Incoming {
                    from: from.clone(),
                    protocol_id,
                    payload: payload.clone(),
                }) {
                    Ok(()) => true,
                    Err(TrySendError::Full(_)) => true,
                    Err(TrySendError::Closed(_)) => false,
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn slow_subscriber_keeps_registration() {
        let router = AppPlaneRouter::new();
        let mut rx = router.subscribe(9);
        for i in 0..QUEUE_CAP {
            router.dispatch(
                9,
                AppEvent::Incoming {
                    from: "a".into(),
                    protocol_id: 9,
                    payload: vec![i as u8],
                },
            );
        }
        assert_eq!(router.subscriber_count(9), 1);
        router.dispatch(
            9,
            AppEvent::Incoming {
                from: "a".into(),
                protocol_id: 9,
                payload: vec![255],
            },
        );
        assert_eq!(router.subscriber_count(9), 1);
        let _ = rx.recv().await;
        router.dispatch(
            9,
            AppEvent::Incoming {
                from: "b".into(),
                protocol_id: 9,
                payload: b"ok".to_vec(),
            },
        );
        let mut saw = false;
        while let Ok(ev) = rx.try_recv() {
            if let AppEvent::Incoming { from, payload, .. } = ev {
                if from == "b" && payload == b"ok" {
                    saw = true;
                    break;
                }
            }
        }
        assert!(saw, "healthy sub still receives after overflow");
    }

    #[tokio::test]
    async fn dropped_rx_prunes() {
        let router = AppPlaneRouter::new();
        let rx = router.subscribe(3);
        assert_eq!(router.subscriber_count(3), 1);
        drop(rx);
        router.prune(3);
        assert_eq!(router.subscriber_count(3), 0);
    }
}
