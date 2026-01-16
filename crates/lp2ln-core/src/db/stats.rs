use redb::{Error, ReadableTable};
use std::time::{SystemTime, UNIX_EPOCH};

use super::db::P2PDatabase;
use super::models::PeerStats;
use super::tables;

impl P2PDatabase {
    pub fn update_peer_stats(&self, public_key: &str, total_space: u64, free_space: u64, stored_files: Vec<String>) -> Result<(), Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;

        let stats = PeerStats {
            public_key: public_key.to_string(),
            total_space,
            free_space,
            stored_files,
            last_update: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        {
            let mut table = tx.open_table(tables::PEER_STATS_TABLE)?;
            let data = serde_json::to_string(&stats).unwrap();
            table.insert(public_key, data.as_bytes())?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn get_peer_with_most_space(&self) -> Option<String> {
        let mut peers: Vec<(String, PeerStats)> = Vec::new();
        
        let db = self.db.lock().unwrap();
        if let Ok(tx) = db.begin_read() {
            if let Ok(table) = tx.open_table(tables::PEER_STATS_TABLE) {
                for item in table.iter().unwrap() {
                    if let Ok((key, value)) = item {
                        if let Ok(peer_data) = serde_json::from_slice::<PeerStats>(value.value()) {
                            peers.push((key.value().to_string(), peer_data));
                        }
                    }
                }
            }
        }
    
        peers.sort_by(|a, b| b.1.free_space.cmp(&a.1.free_space));
        peers.first().map(|(peer_id, _)| peer_id.clone())
    }
    
    pub fn get_peer_stats(&self, peer_id: &str) -> Result<Option<PeerStats>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(tables::PEER_STATS_TABLE)?;

        match table.get(peer_id)? {
            Some(data) => {
                let json_str = String::from_utf8(data.value().to_vec()).unwrap();
                let stats: PeerStats = serde_json::from_str(&json_str).unwrap();
                Ok(Some(stats))
            }
            None => Ok(None),
        }
    }

    pub fn get_all_peer_stats(&self) -> Result<Vec<PeerStats>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(tables::PEER_STATS_TABLE)?;

        let mut stats = Vec::new();
        for item in table.iter()? {
            let (_, value) = item?;
            let json_str = String::from_utf8(value.value().to_vec()).unwrap();
            let peer_stats: PeerStats = serde_json::from_str(&json_str).unwrap();
            stats.push(peer_stats);
        }

        Ok(stats)
    }

    pub fn remove_peer_stats(&self, peer_id: &str) -> Result<(), Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;
        
        {
            let mut table = tx.open_table(tables::PEER_STATS_TABLE)?;
            table.remove(peer_id)?;
        }

        tx.commit()?;
        Ok(())
    }
}
