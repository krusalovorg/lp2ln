use std::collections::HashMap;

use redb::ReadableTable;

use crate::db::tables::{PEER_DESCRIPTOR_TABLE, PEER_SCORE_SNAPSHOT_KEY, PEER_SCORE_TABLE};
use crate::peer_score::PeerScore;
use crate::topology::NodeDescriptor;
use crate::types::PeerId;

use super::P2PDatabase;

impl P2PDatabase {
    pub fn upsert_peer_descriptor(&self, descriptor: &NodeDescriptor) -> Result<(), redb::Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;
        {
            let mut table = tx.open_table(PEER_DESCRIPTOR_TABLE)?;
            let data = serde_json::to_vec(descriptor)
                .map_err(|e| redb::Error::Corrupted(format!("descriptor serialize failed: {}", e)))?;
            table.insert(descriptor.peer_id.as_str(), data.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn remove_peer_descriptor(&self, peer_id: &str) -> Result<(), redb::Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;
        {
            let mut table = tx.open_table(PEER_DESCRIPTOR_TABLE)?;
            table.remove(peer_id)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_peer_descriptors(&self) -> Result<Vec<NodeDescriptor>, redb::Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(PEER_DESCRIPTOR_TABLE)?;
        let mut out = Vec::new();
        for item in table.iter()? {
            let (_, raw) = item?;
            if let Ok(desc) = serde_json::from_slice::<NodeDescriptor>(raw.value()) {
                out.push(desc);
            }
        }
        Ok(out)
    }

    pub fn save_peer_score_snapshot(
        &self,
        entries: &[(PeerId, PeerScore)],
    ) -> Result<(), redb::Error> {
        let mut map: HashMap<String, PeerScore> = HashMap::with_capacity(entries.len());
        for (pid, s) in entries {
            map.insert(pid.as_str().to_string(), s.clone());
        }
        let data = serde_json::to_vec(&map).map_err(|e| {
            redb::Error::Corrupted(format!("peer_scores serialize failed: {}", e))
        })?;
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;
        {
            let mut table = tx.open_table(PEER_SCORE_TABLE)?;
            table.insert(PEER_SCORE_SNAPSHOT_KEY, data.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_peer_score_snapshot(&self) -> Result<Vec<(PeerId, PeerScore)>, redb::Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(PEER_SCORE_TABLE)?;
        let Some(raw) = table.get(PEER_SCORE_SNAPSHOT_KEY)? else {
            return Ok(vec![]);
        };
        let map: HashMap<String, PeerScore> = serde_json::from_slice(raw.value()).map_err(|e| {
            redb::Error::Corrupted(format!("peer_scores deserialize failed: {}", e))
        })?;
        Ok(map
            .into_iter()
            .map(|(k, v)| (PeerId::from(k.as_str()), v))
            .collect())
    }
}
