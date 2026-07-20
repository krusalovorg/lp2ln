// P4 — peer-to-peer block transfer protocol.
//
// BLOCK_PROTOCOL_ID rides on App Plane (same pattern as DHT).
// Pull:  Request  → Response (None = not found).
// Push:  Push     → PushAck(stored=true) — receiver verifies hash and durably
//                   stores before acking; sender awaits ack.
//
// Limits: Push payload > MAX_BLOCK_SIZE is rejected (stored=false ack).
//         max_local_blocks > 0 caps how many pushed blocks this node accepts.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::packet::Packet;
use crate::router::Router;
use crate::storage::{BlockStore, ContentId, hash_bytes};

pub const BLOCK_PROTOCOL_ID: u16 = 0x424C; // "BL"
pub const MAX_BLOCK_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockMsg {
    Request {
        content_id: ContentId,
        request_id: u64,
    },
    Response {
        request_id: u64,
        data: Option<Vec<u8>>,
    },
    Push {
        content_id: ContentId,
        data: Vec<u8>,
        request_id: u64,
    },
    PushAck {
        content_id: ContentId,
        request_id: u64,
        stored: bool,
    },
}

pub struct BlockTransferService {
    pub store: BlockStore,
    router: Arc<Router>,
    local_peer_id: String,
    pending: DashMap<u64, oneshot::Sender<Option<Vec<u8>>>>,
    push_ack_pending: DashMap<u64, oneshot::Sender<bool>>,
    next_rid: std::sync::atomic::AtomicU64,
    max_local_blocks: usize,
    received_blocks: AtomicUsize,
}

impl BlockTransferService {
    pub fn new(
        store: BlockStore,
        router: Arc<Router>,
        local_peer_id: impl Into<String>,
        max_local_blocks: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            router,
            local_peer_id: local_peer_id.into(),
            pending: DashMap::new(),
            push_ack_pending: DashMap::new(),
            next_rid: std::sync::atomic::AtomicU64::new(1),
            max_local_blocks,
            received_blocks: AtomicUsize::new(0),
        })
    }

    fn next_rid(&self) -> u64 {
        self.next_rid
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    async fn send_msg(&self, peer_id: &str, msg: &BlockMsg) -> anyhow::Result<()> {
        let pkt = Packet {
            signature: None,
            data: postcard::to_allocvec(msg)?,
            nodes: vec![],
            sender: self.local_peer_id.clone(),
            receiver: peer_id.to_string(),
            max_hops: 16,
            request_id: None,
            protocol_id: Some(BLOCK_PROTOCOL_ID),
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };
        self.router.send_to_peer(peer_id.into(), pkt, None).await?;
        Ok(())
    }

    pub fn handle_raw(self: &Arc<Self>, from_peer: &str, data: &[u8]) {
        let Ok(msg) = postcard::from_bytes::<BlockMsg>(data) else {
            return;
        };
        let svc = self.clone();
        let from = from_peer.to_string();
        tokio::spawn(async move { svc.handle_msg(&from, msg).await });
    }

    async fn handle_msg(self: &Arc<Self>, from: &str, msg: BlockMsg) {
        match msg {
            BlockMsg::Request {
                content_id,
                request_id,
            } => {
                let data = self.store.get(&content_id).ok().flatten();
                self.send_msg(from, &BlockMsg::Response { request_id, data })
                    .await
                    .ok();
            }
            BlockMsg::Response { request_id, data } => {
                if let Some((_, tx)) = self.pending.remove(&request_id) {
                    tx.send(data).ok();
                }
            }
            BlockMsg::Push { content_id, data, request_id } => {
                let stored = if data.len() > MAX_BLOCK_SIZE {
                    false
                } else if self.max_local_blocks > 0
                    && self.received_blocks.load(Ordering::Relaxed) >= self.max_local_blocks
                {
                    false
                } else if hash_bytes(&data) == content_id {
                    let ok = self.store.put(&data).is_ok();
                    if ok {
                        self.received_blocks.fetch_add(1, Ordering::Relaxed);
                    }
                    ok
                } else {
                    false
                };
                self.send_msg(from, &BlockMsg::PushAck { content_id, request_id, stored })
                    .await
                    .ok();
            }
            BlockMsg::PushAck { request_id, stored, .. } => {
                if let Some((_, tx)) = self.push_ack_pending.remove(&request_id) {
                    tx.send(stored).ok();
                }
            }
        }
    }

    /// Pull a block from `peer_id`, verify hash. Err on timeout/missing/mismatch.
    pub async fn fetch_from(
        &self,
        peer_id: &str,
        content_id: ContentId,
    ) -> anyhow::Result<Vec<u8>> {
        let rid = self.next_rid();
        let (tx, rx) = oneshot::channel();
        self.pending.insert(rid, tx);
        match self
            .send_msg(
                peer_id,
                &BlockMsg::Request {
                    content_id,
                    request_id: rid,
                },
            )
            .await
        {
            Ok(_) => {}
            Err(e) => {
                self.pending.remove(&rid);
                return Err(e);
            }
        }
        let data = match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(Some(d))) => d,
            Ok(Ok(None)) => return Err(anyhow::anyhow!("peer {} does not have block", peer_id)),
            Ok(Err(_)) => return Err(anyhow::anyhow!("channel closed")),
            Err(_) => {
                self.pending.remove(&rid);
                return Err(anyhow::anyhow!("timeout fetching from {}", peer_id));
            }
        };
        anyhow::ensure!(
            hash_bytes(&data) == content_id,
            "hash mismatch from {}",
            peer_id
        );
        Ok(data)
    }

    /// Try providers in order; skip corrupted or unresponsive ones.
    pub async fn fetch_from_providers(
        &self,
        content_id: ContentId,
        providers: &[String],
    ) -> anyhow::Result<Vec<u8>> {
        for peer_id in providers {
            if let Ok(data) = self.fetch_from(peer_id, content_id).await {
                return Ok(data);
            }
        }
        anyhow::bail!("no valid provider for {}", hex::encode(content_id))
    }

    /// Push a block to `peer_id`; waits for PushAck confirming durable store.
    pub async fn push_to(
        &self,
        peer_id: &str,
        content_id: ContentId,
        data: Vec<u8>,
    ) -> anyhow::Result<()> {
        let rid = self.next_rid();
        let (tx, rx) = oneshot::channel();
        self.push_ack_pending.insert(rid, tx);
        match self
            .send_msg(peer_id, &BlockMsg::Push { content_id, data, request_id: rid })
            .await
        {
            Ok(_) => {}
            Err(e) => {
                self.push_ack_pending.remove(&rid);
                return Err(e);
            }
        }
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) => Err(anyhow::anyhow!("peer {} did not store block", peer_id)),
            Ok(Err(_)) => Err(anyhow::anyhow!("push ack channel closed")),
            Err(_) => {
                self.push_ack_pending.remove(&rid);
                Err(anyhow::anyhow!("timeout waiting for PushAck from {}", peer_id))
            }
        }
    }

    pub fn spawn(self: Arc<Self>, cancel: CancellationToken) {
        let mut sub = self.router.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    msg = sub.recv() => match msg {
                        Ok(inc) if inc.packet.protocol_id == Some(BLOCK_PROTOCOL_ID) => {
                            self.handle_raw(&inc.packet.sender, &inc.packet.data);
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(_) => break,
                    }
                }
            }
        });
    }
}
