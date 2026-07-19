// DHT local record store with TTL eviction.
//
// NodeRecords: keyed by NodeId (hex).
// ProviderRecords: keyed by content_id hex → list of providers.
// Persisted in redb DHT_TABLE as hex_key → postcard(DhtStoreEntry).

use dashmap::DashMap;
use redb::ReadableTable;
use serde::{Deserialize, Serialize};

use crate::db::P2PDatabase;
use crate::dht::records::{NodeId, NodeRecord, ProviderRecord, unix_now};

#[derive(Debug, Serialize, Deserialize)]
enum DhtStoreEntry {
    Node(NodeRecord),
    Providers(Vec<ProviderRecord>),
}

#[derive(Default, Clone)]
pub struct DhtStore {
    nodes: DashMap<String, NodeRecord>,
    providers: DashMap<String, Vec<ProviderRecord>>,
}

impl DhtStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load persisted records from db; ignores expired entries.
    pub fn load_from_db(&self, db: &P2PDatabase) {
        let lock = db.db.lock().expect("db lock");
        let Ok(txn) = lock.begin_read() else { return };
        let Ok(table) = txn.open_table(crate::db::tables::DHT_TABLE) else {
            return;
        };
        let Ok(iter) = table.iter() else { return };
        for entry in iter {
            let Ok((k, v)) = entry else { continue };
            let key = k.value().to_string();
            if let Ok(e) = postcard::from_bytes::<DhtStoreEntry>(v.value()) {
                match e {
                    DhtStoreEntry::Node(r) if !r.is_expired() => {
                        self.nodes.insert(key, r);
                    }
                    DhtStoreEntry::Providers(list) => {
                        let live: Vec<_> = list
                            .into_iter()
                            .filter(|p| !p.provider.is_expired())
                            .collect();
                        if !live.is_empty() {
                            self.providers.insert(key, live);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn persist_node(db: &P2PDatabase, key: &str, record: &NodeRecord) {
        let Ok(bytes) = postcard::to_allocvec(&DhtStoreEntry::Node(record.clone())) else {
            return;
        };
        let lock = db.db.lock().expect("db lock");
        let Ok(txn) = lock.begin_write() else { return };
        if let Ok(mut t) = txn.open_table(crate::db::tables::DHT_TABLE) {
            t.insert(key, bytes.as_slice()).ok();
        }
        txn.commit().ok();
    }

    fn persist_providers(db: &P2PDatabase, key: &str, list: &[ProviderRecord]) {
        let Ok(bytes) = postcard::to_allocvec(&DhtStoreEntry::Providers(list.to_vec())) else {
            return;
        };
        let lock = db.db.lock().expect("db lock");
        let Ok(txn) = lock.begin_write() else { return };
        if let Ok(mut t) = txn.open_table(crate::db::tables::DHT_TABLE) {
            t.insert(key, bytes.as_slice()).ok();
        }
        txn.commit().ok();
    }

    /// Insert or update a NodeRecord. Returns true if accepted (seq ≥ existing or not present).
    pub fn put_node(&self, record: NodeRecord, db: Option<&P2PDatabase>) -> bool {
        if record.is_expired() {
            return false;
        }
        let key = hex::encode(record.node_id);
        let accepted = {
            match self.nodes.get(&key) {
                Some(existing) if existing.seq > record.seq => false,
                _ => {
                    self.nodes.insert(key.clone(), record.clone());
                    true
                }
            }
        };
        if accepted {
            if let Some(db) = db {
                Self::persist_node(db, &key, &record);
            }
        }
        accepted
    }

    pub fn get_node(&self, id: &NodeId) -> Option<NodeRecord> {
        let key = hex::encode(id);
        self.nodes
            .get(&key)
            .map(|r| r.clone())
            .filter(|r| !r.is_expired())
    }

    /// Announce that a peer provides a ContentId.
    pub fn put_provider(&self, record: ProviderRecord, db: Option<&P2PDatabase>) {
        if record.provider.is_expired() {
            return;
        }
        let key = hex::encode(record.content_id);
        let mut entry = self.providers.entry(key.clone()).or_default();
        // Replace if same provider, otherwise append (up to 20 per content_id).
        if let Some(pos) = entry
            .iter()
            .position(|p| p.provider.peer_id == record.provider.peer_id)
        {
            entry[pos] = record.clone();
        } else if entry.len() < 20 {
            entry.push(record.clone());
        }
        if let Some(db) = db {
            Self::persist_providers(db, &key, &entry);
        }
    }

    pub fn get_providers(&self, content_id: &[u8; 32]) -> Vec<ProviderRecord> {
        let key = hex::encode(content_id);
        self.providers
            .get(&key)
            .map(|v| {
                v.iter()
                    .filter(|p| !p.provider.is_expired())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Remove all expired records from memory (db entries stay until next load).
    pub fn evict_expired(&self) {
        let now = unix_now();
        self.nodes.retain(|_, r| r.expires_at > now);
        self.providers.retain(|_, list| {
            list.retain(|p| p.provider.expires_at > now);
            !list.is_empty()
        });
    }
}
