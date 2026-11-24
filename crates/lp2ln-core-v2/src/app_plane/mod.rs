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

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use tokio::sync::mpsc;

use crate::router::Router;
use crate::router::admission::{IngressBudget, IngressPermit};

pub use lp2ln_app_protocol::{
    AppCapability, AppCmd, AppErrorCode, AppEvent, DEFAULT_STREAM_CREDITS, MAX_FRAME_BYTES,
    MAX_STREAM_CHUNK_BYTES, MAX_STREAMS_PER_CONNECTION, PROTOCOL_VERSION, QUEUE_CAP, decode_cmd,
    decode_event, encode_cmd, encode_event, encode_frame, peek_frame,
};

/// Compat alias for [`QUEUE_CAP`].
pub const APP_PLANE_QUEUE_CAP: usize = QUEUE_CAP;

static NEXT_SUBSCRIBER: AtomicU64 = AtomicU64::new(1);

struct Subscriber {
    id: u64,
    tx: mpsc::Sender<AppEvent>,
    charges: VecDeque<IngressPermit>,
}

impl Subscriber {
    fn reap(&mut self) {
        let queued = self.tx.max_capacity() - self.tx.capacity();
        let released = self.charges.len().saturating_sub(queued);
        self.charges.drain(..released);
    }
}

/// Retains node capacity through IPC decode or socket write. IPC host code
/// drops this when its allocation leaves the host.
pub struct AppPlaneMemoryCharge {
    _permit: IngressPermit,
}

pub struct AppPlaneConnectionBudget {
    budget: Arc<IngressBudget>,
    id: u64,
}

impl AppPlaneConnectionBudget {
    pub fn reserve(&self, bytes: usize) -> Option<AppPlaneMemoryCharge> {
        self.budget
            .fanout(bytes, Some(self.id))
            .map(|permit| AppPlaneMemoryCharge { _permit: permit })
    }
}

/// Each sidecar gets a bounded best-effort subscription. Retained copies are
/// charged only until the host receives each event from its subscriber queue.
#[derive(Clone, Default)]
pub struct AppPlaneRouter {
    subs: Arc<DashMap<u16, Vec<Subscriber>>>,
    budget: Arc<IngressBudget>,
    refused: Arc<AtomicU64>,
}

impl AppPlaneRouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Shares the node's fanout byte pool with the legacy rings.
    pub fn with_router(router: &Router) -> Self {
        Self {
            budget: router.ingress_budget().clone(),
            ..Self::default()
        }
    }

    pub fn connection_budget(&self) -> Arc<AppPlaneConnectionBudget> {
        Arc::new(AppPlaneConnectionBudget {
            budget: self.budget.clone(),
            id: NEXT_SUBSCRIBER.fetch_add(1, Ordering::Relaxed),
        })
    }

    pub fn subscribe(&self, protocol_id: u16) -> mpsc::Receiver<AppEvent> {
        let (tx, rx) = mpsc::channel(QUEUE_CAP);
        let id = NEXT_SUBSCRIBER.fetch_add(1, Ordering::Relaxed);
        self.subs.entry(protocol_id).or_default().push(Subscriber {
            id,
            tx,
            charges: VecDeque::new(),
        });
        rx
    }

    pub fn prune(&self, protocol_id: u16) {
        if let Some(mut entry) = self.subs.get_mut(&protocol_id) {
            entry.retain_mut(|sub| {
                sub.reap();
                !sub.tx.is_closed()
            });
        }
        self.subs
            .remove_if(&protocol_id, |_, entry| entry.is_empty());
    }

    pub fn subscriber_count(&self, protocol_id: u16) -> usize {
        self.subs
            .get(&protocol_id)
            .map(|entry| entry.iter().filter(|sub| !sub.tx.is_closed()).count())
            .unwrap_or(0)
    }

    pub fn record_refused(&self, count: u64) {
        self.refused.fetch_add(count, Ordering::Relaxed);
    }

    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    pub fn dispatch(&self, protocol_id: u16, ev: AppEvent) {
        if let AppEvent::Incoming { from, payload, .. } = ev {
            self.dispatch_incoming(protocol_id, &from, &payload);
        }
    }

    /// Reserves each actual payload allocation before cloning for a subscriber.
    pub fn dispatch_incoming(&self, protocol_id: u16, from: &str, payload: &[u8]) {
        if let Some(mut entry) = self.subs.get_mut(&protocol_id) {
            entry.retain_mut(|sub| {
                sub.reap();
                let slot = match sub.tx.try_reserve() {
                    Ok(slot) => slot,
                    Err(mpsc::error::TrySendError::Closed(_)) => return false,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        self.refused.fetch_add(1, Ordering::Relaxed);
                        return true;
                    }
                };
                let bytes = payload.len() + from.len() + std::mem::size_of::<AppEvent>() + 128;
                let Some(charge) = self.budget.fanout(bytes, Some(sub.id)) else {
                    self.refused.fetch_add(1, Ordering::Relaxed);
                    return true;
                };
                sub.charges.push_back(charge);
                slot.send(AppEvent::Incoming {
                    from: from.to_owned(),
                    protocol_id,
                    payload: payload.to_vec(),
                });
                true
            });
        }
    }

    /// Release charges from idle legacy receivers that consumed their items.
    pub fn reap(&self) {
        self.subs.retain(|_, entry| {
            entry.retain_mut(|sub| {
                sub.reap();
                !sub.tx.is_closed()
            });
            !entry.is_empty()
        });
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
