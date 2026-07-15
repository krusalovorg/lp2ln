// DHT background service — iterative lookup, announce, expiry (DHT-0/1)
//
// Runs as a Tokio task alongside the node. Subscribes to the router for
// packets with protocol_id = DHT_PROTOCOL_ID and handles DHT RPCs.
//
// send path: node.send_with_options(peer_id, postcard(DhtMsg), protocol_id=DHT_PROTOCOL_ID)
// recv path: router broadcast → DhtService::handle_raw

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::dht::records::{
    DHT_PROTOCOL_ID, DhtMsg, NodeId, NodeRecord, ProviderRecord, node_id_of, unix_now,
};
use crate::dht::routing::{ALPHA, K, RoutingTable};
use crate::dht::store::DhtStore;
use crate::packet::Packet;
use crate::router::Router;

const NODE_RECORD_TTL_SECS: u64 = 3600; // 1 hour

pub struct DhtService {
    pub local_record: NodeRecord,
    routing: std::sync::Mutex<RoutingTable>,
    pub store: DhtStore,
    router: Arc<Router>,
    // pending find_node / get_record requests: request_id → reply channel
    pending_fn: DashMap<u64, oneshot::Sender<Vec<NodeRecord>>>,
    pending_gr: DashMap<u64, oneshot::Sender<Option<NodeRecord>>>,
    pending_fp: DashMap<u64, oneshot::Sender<Vec<ProviderRecord>>>,
    next_rid: std::sync::atomic::AtomicU64,
}

impl DhtService {
    pub fn new(peer_id: &str, router: Arc<Router>, addrs: Vec<String>) -> Arc<Self> {
        let peer_id = peer_id.to_string();
        let node_id = node_id_of(&peer_id);
        let local_record = NodeRecord {
            node_id,
            peer_id: peer_id.clone(),
            addrs,
            seq: 0,
            expires_at: unix_now() + NODE_RECORD_TTL_SECS,
            signature: vec![], // ponytail: unsigned in DHT-0; add signing in DHT-3
        };
        Arc::new(Self {
            local_record,
            routing: std::sync::Mutex::new(RoutingTable::new(node_id)),
            store: DhtStore::new(),
            router,
            pending_fn: DashMap::new(),
            pending_gr: DashMap::new(),
            pending_fp: DashMap::new(),
            next_rid: std::sync::atomic::AtomicU64::new(1),
        })
    }

    fn next_rid(&self) -> u64 {
        self.next_rid.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Store self in DHT and seed routing table with bootstrap contacts.
    pub fn seed(&self, peers: Vec<NodeRecord>) {
        self.store.put_node(self.local_record.clone(), None);
        let mut rt = self.routing.lock().expect("rt lock");
        for p in peers {
            rt.update(p.clone());
            self.store.put_node(p, None);
        }
    }

    /// Build and send a DHT message to a specific peer.
    async fn send_to(&self, peer_id: &str, msg: &DhtMsg) -> anyhow::Result<()> {
        let payload = postcard::to_allocvec(msg)?;
        let my_id = self.local_record.peer_id.clone();
        let pkt = Packet {
            signature: None,
            data: payload,
            nodes: vec![],
            sender: my_id,
            receiver: peer_id.to_string(),
            max_hops: 16,
            request_id: None,
            protocol_id: Some(DHT_PROTOCOL_ID),
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };
        self.router.send_to_peer(peer_id.into(), pkt, None).await?;
        Ok(())
    }

    /// Handle a raw incoming packet (called from the listener task).
    pub fn handle_raw(self: &Arc<Self>, from_peer: &str, data: &[u8]) {
        let Ok(msg) = postcard::from_bytes::<DhtMsg>(data) else { return };
        let svc = self.clone();
        let from = from_peer.to_string();
        tokio::spawn(async move { svc.handle_msg(&from, msg).await });
    }

    async fn handle_msg(self: &Arc<Self>, from: &str, msg: DhtMsg) {
        match msg {
            DhtMsg::FindNode { target, request_id } => {
                let closer = self.routing.lock().expect("rt").find_closest(&target, K);
                let reply = DhtMsg::FindNodeReply { request_id, closer };
                self.send_to(from, &reply).await.ok();
            }
            DhtMsg::FindNodeReply { request_id, closer } => {
                // Update routing table with received contacts.
                {
                    let mut rt = self.routing.lock().expect("rt");
                    for r in &closer { rt.update(r.clone()); }
                }
                if let Some((_, tx)) = self.pending_fn.remove(&request_id) {
                    tx.send(closer).ok();
                }
            }
            DhtMsg::PutRecord { record } => {
                // ponytail: no signature verification in DHT-0; add in DHT-3
                self.routing.lock().expect("rt").update(record.clone());
                self.store.put_node(record, None);
            }
            DhtMsg::GetRecord { node_id, request_id } => {
                let record = self.store.get_node(&node_id);
                let reply = DhtMsg::GetRecordReply { request_id, record };
                self.send_to(from, &reply).await.ok();
            }
            DhtMsg::GetRecordReply { request_id, record } => {
                if let Some(r) = &record {
                    self.routing.lock().expect("rt").update(r.clone());
                }
                if let Some((_, tx)) = self.pending_gr.remove(&request_id) {
                    tx.send(record).ok();
                }
            }
            DhtMsg::AnnounceProvider { record } => {
                self.store.put_provider(record, None);
            }
            DhtMsg::FindProviders { content_id, request_id } => {
                let providers = self.store.get_providers(&content_id);
                let reply = DhtMsg::FindProvidersReply { request_id, providers };
                self.send_to(from, &reply).await.ok();
            }
            DhtMsg::FindProvidersReply { request_id, providers } => {
                if let Some((_, tx)) = self.pending_fp.remove(&request_id) {
                    tx.send(providers).ok();
                }
            }
        }
    }

    // ── Iterative find_node ────────────────────────────────────────────────────

    /// Kademlia-style iterative find_node. Returns up to K closest known nodes.
    pub async fn find_node(&self, target: NodeId) -> Vec<NodeRecord> {
        let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut best = self.routing.lock().expect("rt").find_closest(&target, K);
        visited.insert(self.local_record.peer_id.clone());

        for _round in 0..8 {
            let to_query: Vec<_> = best
                .iter()
                .filter(|r| !visited.contains(&r.peer_id))
                .take(ALPHA)
                .cloned()
                .collect();
            if to_query.is_empty() { break; }

            // Send all ALPHA queries before waiting — parallel, single shared deadline.
            let mut rids = Vec::new();
            let mut rxs = Vec::new();
            for contact in &to_query {
                visited.insert(contact.peer_id.clone());
                let rid = self.next_rid();
                let (tx, rx) = oneshot::channel();
                self.pending_fn.insert(rid, tx);
                self.send_to(&contact.peer_id, &DhtMsg::FindNode { target, request_id: rid }).await.ok();
                rids.push(rid);
                rxs.push(rx);
            }
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut replies = Vec::new();
            for rx in rxs {
                if let Ok(Ok(closer)) = tokio::time::timeout_at(deadline, rx).await {
                    replies.extend(closer);
                }
            }
            for rid in rids { self.pending_fn.remove(&rid); }

            // Merge replies into best set.
            for r in replies {
                if !best.iter().any(|b| b.peer_id == r.peer_id) {
                    best.push(r.clone());
                    self.routing.lock().expect("rt").update(r);
                }
            }
            best.sort_by_key(|r| crate::dht::records::xor_distance(&r.node_id, &target));
            best.truncate(K);
        }
        best
    }

    /// Announce self to the K closest peers we know about.
    pub async fn announce_self(&self) {
        let target = self.local_record.node_id;
        let closest = self.routing.lock().expect("rt").find_closest(&target, K);
        let msg = DhtMsg::PutRecord { record: self.local_record.clone() };
        for contact in closest.iter().take(K) {
            self.send_to(&contact.peer_id, &msg).await.ok();
        }
    }

    /// Announce that we provide a given ContentId.
    pub async fn announce_provider(&self, content_id: [u8; 32]) {
        let record = ProviderRecord {
            content_id,
            provider: self.local_record.clone(),
        };
        let msg = DhtMsg::AnnounceProvider { record: record.clone() };
        let closest = self.routing.lock().expect("rt").find_closest(&content_id, K);
        for contact in closest.iter().take(K) {
            self.send_to(&contact.peer_id, &msg).await.ok();
        }
        self.store.put_provider(record, None);
    }

    /// Find providers for a ContentId.
    /// ponytail: single-round ALPHA query, no iterative refinement; add in DHT-3 if needed.
    pub async fn find_providers(&self, content_id: [u8; 32]) -> Vec<ProviderRecord> {
        let local = self.store.get_providers(&content_id);
        if !local.is_empty() { return local; }

        let closest = self.routing.lock().expect("rt").find_closest(&content_id, ALPHA);
        let mut rids = Vec::new();
        let mut rxs = Vec::new();
        for contact in &closest {
            let rid = self.next_rid();
            let (tx, rx) = oneshot::channel();
            self.pending_fp.insert(rid, tx);
            self.send_to(&contact.peer_id, &DhtMsg::FindProviders { content_id, request_id: rid }).await.ok();
            rids.push(rid);
            rxs.push(rx);
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut results = Vec::new();
        for rx in rxs {
            if let Ok(Ok(mut providers)) = tokio::time::timeout_at(deadline, rx).await {
                results.append(&mut providers);
            }
        }
        for rid in rids { self.pending_fp.remove(&rid); }
        results
    }

    // ── Background task ────────────────────────────────────────────────────────

    /// Spawns the DHT listener and periodic maintenance tasks.
    pub fn spawn(self: Arc<Self>, cancel: CancellationToken) {
        let cancel2 = cancel.clone();
        // Listener: subscribe to router for DHT packets.
        let svc = self.clone();
        let mut sub = self.router.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    msg = sub.recv() => {
                        match msg {
                            Ok(inc) if inc.packet.protocol_id == Some(DHT_PROTOCOL_ID) => {
                                svc.handle_raw(&inc.packet.sender, &inc.packet.data);
                            }
                            Ok(_) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        // Periodic: re-announce self + evict expired records.
        let svc = self;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(600));
            loop {
                tokio::select! {
                    _ = cancel2.cancelled() => break,
                    _ = interval.tick() => {
                        svc.store.evict_expired();
                        svc.announce_self().await;
                    }
                }
            }
        });
    }
}
