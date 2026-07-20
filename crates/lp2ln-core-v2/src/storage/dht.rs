// P4 — DHT provider protocol.
//
// ProviderRecord is signed by the announcer (k256 ECDSA over postcard payload).
// DhtStore is in-memory only; bounded by max_records.
// DhtService rides on App Plane — protocol 0x4448 ("DH").
//
// Protocol:
//   Announce { record }              → peers store the record if sig/expiry valid
//   FindProviders { cid, rid }       → peer replies with FoundProviders
//   FoundProviders { cid, rid, recs }

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::packet::Packet;
use crate::router::Router;
use crate::storage::ContentId;

pub const DHT_PROTOCOL_ID: u16 = 0x4448;
const DEFAULT_TTL_SECS: u64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRecord {
    pub content_id: ContentId,
    pub peer_id: String,
    pub seq: u64,
    pub expires_at_secs: u64,
    pub sig: String, // hex k256 ECDSA over postcard(content_id, peer_id, seq, expires_at_secs)
}

fn signing_payload(r: &ProviderRecord) -> Vec<u8> {
    postcard::to_allocvec(&(&r.content_id, &r.peer_id, r.seq, r.expires_at_secs))
        .expect("postcard infallible for ProviderRecord payload")
}

pub fn sign_record(key: &SigningKey, r: &mut ProviderRecord) {
    let payload = signing_payload(r);
    let sig: Signature = key.sign(&payload);
    r.sig = hex::encode(sig.to_bytes());
}

pub fn verify_record(r: &ProviderRecord) -> bool {
    let Ok(pub_bytes) = hex::decode(&r.peer_id) else { return false; };
    let Ok(vk) = VerifyingKey::from_sec1_bytes(&pub_bytes) else { return false; };
    let Ok(sig_bytes) = hex::decode(&r.sig) else { return false; };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else { return false; };
    let payload = signing_payload(r);
    vk.verify(&payload, &sig).is_ok()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtMsg {
    Announce {
        record: ProviderRecord,
    },
    FindProviders {
        content_id: ContentId,
        request_id: u64,
    },
    FoundProviders {
        content_id: ContentId,
        request_id: u64,
        records: Vec<ProviderRecord>,
    },
}

pub struct DhtStore {
    records: DashMap<ContentId, Vec<ProviderRecord>>,
    total: AtomicU64,
    max_records: usize,
}

impl DhtStore {
    pub fn new(max_records: usize) -> Self {
        Self {
            records: DashMap::new(),
            total: AtomicU64::new(0),
            max_records,
        }
    }

    /// Insert a verified, non-expired record. Higher seq wins same-peer slot.
    pub fn insert(&self, record: ProviderRecord) -> bool {
        let now = lp2ln_content::unix_now();
        if record.expires_at_secs <= now {
            return false;
        }
        if !verify_record(&record) {
            return false;
        }
        let mut entry = self.records.entry(record.content_id).or_default();
        if let Some(existing) = entry.iter_mut().find(|r| r.peer_id == record.peer_id) {
            if record.seq > existing.seq {
                *existing = record;
            }
            return true;
        }
        if self.total.load(Ordering::Relaxed) as usize >= self.max_records {
            return false;
        }
        self.total.fetch_add(1, Ordering::Relaxed);
        entry.push(record);
        true
    }

    pub fn get_providers(&self, content_id: &ContentId) -> Vec<ProviderRecord> {
        let now = lp2ln_content::unix_now();
        self.records
            .get(content_id)
            .map(|v| {
                v.iter()
                    .filter(|r| r.expires_at_secs > now)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

pub struct DhtService {
    pub store: Arc<DhtStore>,
    router: Arc<Router>,
    local_peer_id: String,
    signing_key: SigningKey,
    pending: DashMap<u64, oneshot::Sender<Vec<ProviderRecord>>>,
    next_rid: AtomicU64,
}

impl DhtService {
    pub fn new(
        router: Arc<Router>,
        local_peer_id: String,
        signing_key: SigningKey,
        max_records: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            store: Arc::new(DhtStore::new(max_records)),
            router,
            local_peer_id,
            signing_key,
            pending: DashMap::new(),
            next_rid: AtomicU64::new(1),
        })
    }

    fn next_rid(&self) -> u64 {
        self.next_rid.fetch_add(1, Ordering::Relaxed)
    }

    async fn send_msg(&self, peer_id: &str, msg: &DhtMsg) -> anyhow::Result<()> {
        let pkt = Packet {
            signature: None,
            data: postcard::to_allocvec(msg)?,
            nodes: vec![],
            sender: self.local_peer_id.clone(),
            receiver: peer_id.to_string(),
            max_hops: 4,
            request_id: None,
            protocol_id: Some(DHT_PROTOCOL_ID),
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };
        self.router.send_to_peer(peer_id.into(), pkt, None).await?;
        Ok(())
    }

    /// Create, sign, locally store, and broadcast a provider record.
    pub async fn announce(&self, content_id: ContentId) -> anyhow::Result<()> {
        let now = lp2ln_content::unix_now();
        let mut record = ProviderRecord {
            content_id,
            peer_id: self.local_peer_id.clone(),
            seq: now,
            expires_at_secs: now + DEFAULT_TTL_SECS,
            sig: String::new(),
        };
        sign_record(&self.signing_key, &mut record);
        self.store.insert(record.clone());
        let msg = DhtMsg::Announce { record };
        for peer_id in self.router.connected_peers() {
            self.send_msg(peer_id.as_str(), &msg).await.ok();
        }
        Ok(())
    }

    /// Check local store, then query `peer_id` if empty.
    pub async fn find_providers(
        &self,
        peer_id: &str,
        content_id: ContentId,
    ) -> anyhow::Result<Vec<ProviderRecord>> {
        let local = self.store.get_providers(&content_id);
        if !local.is_empty() {
            return Ok(local);
        }
        let rid = self.next_rid();
        let (tx, rx) = oneshot::channel();
        self.pending.insert(rid, tx);
        match self
            .send_msg(peer_id, &DhtMsg::FindProviders { content_id, request_id: rid })
            .await
        {
            Ok(_) => {}
            Err(e) => {
                self.pending.remove(&rid);
                return Err(e);
            }
        }
        match tokio::time::timeout(Duration::from_secs(10), rx).await {
            Ok(Ok(records)) => Ok(records),
            Ok(Err(_)) => Err(anyhow::anyhow!("dht channel closed")),
            Err(_) => {
                self.pending.remove(&rid);
                Err(anyhow::anyhow!("timeout finding providers from {}", peer_id))
            }
        }
    }

    pub fn handle_raw(self: &Arc<Self>, from_peer: &str, data: &[u8]) {
        let Ok(msg) = postcard::from_bytes::<DhtMsg>(data) else {
            return;
        };
        let svc = self.clone();
        let from = from_peer.to_string();
        tokio::spawn(async move { svc.handle_msg(&from, msg).await });
    }

    async fn handle_msg(self: &Arc<Self>, from: &str, msg: DhtMsg) {
        match msg {
            DhtMsg::Announce { record } => {
                self.store.insert(record);
            }
            DhtMsg::FindProviders { content_id, request_id } => {
                let records = self.store.get_providers(&content_id);
                self.send_msg(
                    from,
                    &DhtMsg::FoundProviders { content_id, request_id, records },
                )
                .await
                .ok();
            }
            DhtMsg::FoundProviders { request_id, records, .. } => {
                if let Some((_, tx)) = self.pending.remove(&request_id) {
                    tx.send(records).ok();
                }
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
                        Ok(inc) if inc.packet.protocol_id == Some(DHT_PROTOCOL_ID) => {
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
