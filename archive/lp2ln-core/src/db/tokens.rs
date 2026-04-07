use crate::db::{models::{TokenInfo, ValidatorStorageInfo}, tables::{TOKENS_TABLE, VALIDATOR_STORAGE_TABLE}};
use redb::{Error, ReadableTable, ReadableTableMetadata};
use std::time::{SystemTime, UNIX_EPOCH};

use super::P2PDatabase;

impl P2PDatabase {
    pub fn add_token(&self, peer_id: &str, token: &str, free_space: u64) -> Result<(), Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;

        let token_info = TokenInfo {
            token: token.to_string(),
            free_space,
            used_space: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        {
            let mut table = tx.open_table(TOKENS_TABLE)?;
            let data = serde_json::to_string(&token_info).unwrap();
            table.insert(peer_id, data.as_bytes())?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn get_token(&self, peer_id: &str) -> Result<Option<TokenInfo>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(TOKENS_TABLE)?;

        match table.get(peer_id)? {
            Some(data) => {
                let json_str = String::from_utf8(data.value().to_vec()).unwrap();
                let token_info: TokenInfo = serde_json::from_str(&json_str).unwrap();
                Ok(Some(token_info))
            }
            None => Ok(None),
        }
    }

    pub fn get_all_tokens(&self) -> Result<Vec<(String, TokenInfo)>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(TOKENS_TABLE)?;

        let mut tokens = Vec::new();
        for item in table.iter()? {
            let (key, value) = item?;
            let json_str = String::from_utf8(value.value().to_vec()).unwrap();
            let token_info: TokenInfo = serde_json::from_str(&json_str).unwrap();
            tokens.push((key.value().to_string(), token_info));
        }

        Ok(tokens)
    }

    pub fn get_best_token(&self, file_size: u64) -> Result<Option<(String, TokenInfo)>, Error> {
        let my_peer_id = self.get_or_create_peer_id().unwrap();
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(TOKENS_TABLE)?;

        if table.is_empty()? {
            return Ok(None);
        }

        let mut best_token = None;
        let mut best_free_space = 0;
        
        for item in table.iter()? {
            let (key, value) = item?;
            let json_str = String::from_utf8(value.value().to_vec()).unwrap();
            let token_info: TokenInfo = serde_json::from_str(&json_str).unwrap();
            if token_info.free_space >= file_size {
                if token_info.free_space > best_free_space && my_peer_id == key.value().to_string() {
                    best_free_space = token_info.free_space;
                    best_token = Some((key.value().to_string(), token_info));
                }
            }
        }

        Ok(best_token)
    }

    pub fn remove_token(&self, peer_id: &str) -> Result<(), Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;
        
        {
            let mut table = tx.open_table(TOKENS_TABLE)?;
            table.remove(peer_id)?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn update_token_free_space(&self, peer_id: &str, free_space: u64) -> Result<(), Error> {
        if let Some(mut token_info) = self.get_token(peer_id)? {
            token_info.free_space = free_space;
            token_info.timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let db = self.db.lock().unwrap();
            let tx = db.begin_write()?;
            
            {
                let mut table = tx.open_table(TOKENS_TABLE)?;
                let data = serde_json::to_string(&token_info).unwrap();
                table.insert(peer_id, data.as_bytes())?;
            }

            tx.commit()?;
        }
        Ok(())
    }

    pub fn update_validator_storage(&self, peer_id: &str, free_space: u64, total_space: u64) -> Result<(), Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;

        let storage_info = ValidatorStorageInfo {
            peer_id: peer_id.to_string(),
            free_space,
            total_space,
            last_update: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            is_online: true,
        };

        {
            let mut table = tx.open_table(VALIDATOR_STORAGE_TABLE)?;
            let data = serde_json::to_string(&storage_info).unwrap();
            table.insert(peer_id, data.as_bytes())?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn get_validator_storage(&self, peer_id: &str) -> Result<Option<ValidatorStorageInfo>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(VALIDATOR_STORAGE_TABLE)?;

        match table.get(peer_id)? {
            Some(data) => {
                let json_str = String::from_utf8(data.value().to_vec()).unwrap();
                let storage_info: ValidatorStorageInfo = serde_json::from_str(&json_str).unwrap();
                Ok(Some(storage_info))
            }
            None => Ok(None),
        }
    }

    pub fn get_all_validator_storage(&self) -> Result<Vec<ValidatorStorageInfo>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(VALIDATOR_STORAGE_TABLE)?;

        let mut storage_info = Vec::new();
        for item in table.iter()? {
            let (_, value) = item?;
            let json_str = String::from_utf8(value.value().to_vec()).unwrap();
            let info: ValidatorStorageInfo = serde_json::from_str(&json_str).unwrap();
            storage_info.push(info);
        }

        Ok(storage_info)
    }

    pub fn mark_peer_offline(&self, peer_id: &str) -> Result<(), Error> {
        if let Some(mut storage_info) = self.get_validator_storage(peer_id)? {
            storage_info.is_online = false;
            storage_info.last_update = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let db = self.db.lock().unwrap();
            let tx = db.begin_write()?;
            
            {
                let mut table = tx.open_table(VALIDATOR_STORAGE_TABLE)?;
                let data = serde_json::to_string(&storage_info).unwrap();
                table.insert(peer_id, data.as_bytes())?;
            }

            tx.commit()?;
        }
        Ok(())
    }
} 