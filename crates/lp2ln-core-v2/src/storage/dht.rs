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

/// Mutable signed key→value record (P7: namespace head pointers).
/// Higher seq wins. Signed by the announcing node's key like ProviderRecord;
/// application-level authenticity of `value` is the publisher's concern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueRecord {
    pub key: [u8; 32],
    pub value: Vec<u8>,
    pub seq: u64,
    pub peer_id: String,
    pub expires_at_secs: u64,
    pub sig: String, // hex k256 ECDSA over postcard(key, value, seq, peer_id, expires_at_secs)
}

fn value_signing_payload(r: &ValueRecord) -> Vec<u8> {
    postcard::to_allocvec(&(&r.key, &r.value, r.seq, &r.peer_id, r.expires_at_secs))
        .expect("postcard infallible for ValueRecord payload")
}

pub fn sign_value_record(key: &SigningKey, r: &mut ValueRecord) {
    let sig: Signature = key.sign(&value_signing_payload(r));
    r.sig = hex::encode(sig.to_bytes());
}

pub fn verify_value_record(r: &ValueRecord) -> bool {
    let Ok(pub_bytes) = hex::decode(&r.peer_id) else { return false; };
    let Ok(vk) = VerifyingKey::from_sec1_bytes(&pub_bytes) else { return false; };
    let Ok(sig_bytes) = hex::decode(&r.sig) else { return false; };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else { return false; };
    vk.verify(&value_signing_payload(r), &sig).is_ok()
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
    PutValue {
        record: ValueRecord,
    },
    GetValue {
        key: [u8; 32],
        request_id: u64,
    },
    FoundValue {
        key: [u8; 32],
        request_id: u64,
        record: Option<ValueRecord>,
    },
}

pub struct DhtStore {
    records: DashMap<ContentId, Vec<ProviderRecord>>,
    values: DashMap<[u8; 32], ValueRecord>,
    total: AtomicU64,
    max_records: usize,
}

impl DhtStore {
    pub fn new(max_records: usize) -> Self {
        Self {
            records: DashMap::new(),
            values: DashMap::new(),
            total: AtomicU64::new(0),
            max_records,
        }
    }

    /// Insert a verified, non-expired value record. Higher seq wins.
    pub fn insert_value(&self, record: ValueRecord) -> bool {
        if record.expires_at_secs <= lp2ln_content::unix_now() {
            return false;
        }
        if !verify_value_record(&record) {
            return false;
        }
        // len() check outside entry() — dashmap len() locks all shards.
        if !self.values.contains_key(&record.key) && self.values.len() >= self.max_records {
            return false;
        }
        match self.values.entry(record.key) {
            dashmap::mapref::entry::Entry::Occupied(mut e) => {
                if record.seq > e.get().seq {
                    e.insert(record);
                }
            }
            dashmap::mapref::entry::Entry::Vacant(e) => {
                e.insert(record);
            }
        }
        true
    }

    pub fn get_value(&self, key: &[u8; 32]) -> Option<ValueRecord> {
        self.values
            .get(key)
            .filter(|r| r.expires_at_secs > lp2ln_content::unix_now())
            .map(|r| r.clone())
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
    pending_values: DashMap<u64, oneshot::Sender<Option<ValueRecord>>>,
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
            pending_values: DashMap::new(),
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

    /// Sign, locally store, and broadcast a mutable value record (P7 namespace heads).
    pub async fn put_value(&self, key: [u8; 32], value: Vec<u8>, seq: u64) -> anyhow::Result<()> {
        let mut record = ValueRecord {
            key,
            value,
            seq,
            peer_id: self.local_peer_id.clone(),
            expires_at_secs: lp2ln_content::unix_now() + DEFAULT_TTL_SECS,
            sig: String::new(),
        };
        sign_value_record(&self.signing_key, &mut record);
        self.store.insert_value(record.clone());
        let msg = DhtMsg::PutValue { record };
        for peer_id in self.router.connected_peers() {
            self.send_msg(peer_id.as_str(), &msg).await.ok();
        }
        Ok(())
    }

    /// Query `peer_id` for a value, merge into local store, return the freshest record.
    pub async fn get_value(
        &self,
        peer_id: &str,
        key: [u8; 32],
    ) -> anyhow::Result<Option<ValueRecord>> {
        if !peer_id.is_empty() {
            let rid = self.next_rid();
            let (tx, rx) = oneshot::channel();
            self.pending_values.insert(rid, tx);
            if self
                .send_msg(peer_id, &DhtMsg::GetValue { key, request_id: rid })
                .await
                .is_err()
            {
                self.pending_values.remove(&rid);
            } else {
                match tokio::time::timeout(Duration::from_secs(10), rx).await {
                    Ok(Ok(Some(remote))) => {
                        self.store.insert_value(remote);
                    }
                    Ok(_) => {}
                    Err(_) => {
                        self.pending_values.remove(&rid);
                    }
                }
            }
        }
        Ok(self.store.get_value(&key))
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
            DhtMsg::PutValue { record } => {
                self.store.insert_value(record);
            }
            DhtMsg::GetValue { key, request_id } => {
                let record = self.store.get_value(&key);
                self.send_msg(from, &DhtMsg::FoundValue { key, request_id, record })
                    .await
                    .ok();
            }
            DhtMsg::FoundValue { request_id, record, .. } => {
                if let Some((_, tx)) = self.pending_values.remove(&request_id) {
                    tx.send(record).ok();
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

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    fn make_value(key: &SigningKey, k: [u8; 32], val: &[u8], seq: u64) -> ValueRecord {
        let peer_id = hex::encode(key.verifying_key().to_encoded_point(true).as_bytes());
        let mut r = ValueRecord {
            key: k,
            value: val.to_vec(),
            seq,
            peer_id,
            expires_at_secs: lp2ln_content::unix_now() + 600,
            sig: String::new(),
        };
        sign_value_record(key, &mut r);
        r
    }

    #[test]
    fn value_record_seq_wins_and_verifies() {
        let store = DhtStore::new(16);
        let sk = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let k = [7u8; 32];

        assert!(store.insert_value(make_value(&sk, k, b"v1", 1)));
        assert!(store.insert_value(make_value(&sk, k, b"v3", 3)));
        // Older seq must not replace newer.
        assert!(store.insert_value(make_value(&sk, k, b"v2", 2)));
        assert_eq!(store.get_value(&k).unwrap().value, b"v3");

        // Tampered value must be rejected.
        let mut bad = make_value(&sk, k, b"v9", 9);
        bad.value = b"forged".to_vec();
        assert!(!store.insert_value(bad));
        assert_eq!(store.get_value(&k).unwrap().seq, 3);

        // Expired record must be rejected.
        let mut expired = make_value(&sk, k, b"vx", 10);
        expired.expires_at_secs = 1;
        sign_value_record(&sk, &mut expired);
        assert!(!store.insert_value(expired));
    }
}
