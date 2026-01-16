use crate::{
    config::Config,
    db::{models::Storage, tables::STORAGE_TABLE},
};
use async_std::stream::StreamExt;
use redb::{Error, ReadableTable};

use super::{models::TokenInfo, tables::{TOKENS_TABLE}, P2PDatabase};

#[derive(Debug)]
pub enum StorageError {
    Redb(redb::Error),
    Io(std::io::Error),
}

impl From<redb::Error> for StorageError {
    fn from(err: redb::Error) -> Self {
        StorageError::Redb(err)
    }
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        StorageError::Io(err)
    }
}

impl P2PDatabase {
    pub fn add_storage_fragment(&self, fragment: Storage) -> Result<(), Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;
        {
            let mut table = tx.open_table(STORAGE_TABLE)?;
            let data = serde_json::to_string(&fragment).unwrap();
            table.insert(fragment.file_hash.as_str(), data.as_bytes())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_storage_fragments(&self) -> Result<Vec<Storage>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(STORAGE_TABLE)?;

        let mut result = Vec::new();
        for item in table.iter()? {
            let (_, value) = item?;
            let data = String::from_utf8(value.value().to_vec()).unwrap();
            let fragment: Storage = serde_json::from_str(&data).unwrap();
            result.push(fragment);
        }

        Ok(result)
    }

    pub fn get_storage_fragments_by_hash(&self, hash: &str) -> Result<Option<Storage>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(STORAGE_TABLE)?;

        if let Some(value) = table.get(hash)? {
            let data = String::from_utf8(value.value().to_vec()).unwrap();
            let fragment: Storage = serde_json::from_str(&data).unwrap();
            Ok(Some(fragment))
        } else {
            Ok(None)
        }
    }

    pub fn get_storage_fragments_by_token(&self, token: &str) -> Result<Vec<Storage>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(STORAGE_TABLE)?;
        let mut fragments = Vec::new();

        if let Some(value) = table.get(token)? {
            let data = String::from_utf8(value.value().to_vec()).unwrap();
            let fragment: Storage = serde_json::from_str(&data).unwrap();
            if fragment.token == token {
                fragments.push(fragment);
            }
        }

        Ok(fragments)
    }

    pub fn get_by_owner_key_fragments(&self, owner_key: &str) -> Result<Vec<Storage>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(STORAGE_TABLE)?;
        let mut fragments = Vec::new();

        for item in table.iter()? {
            let (_, value) = item?;
            let data = String::from_utf8(value.value().to_vec()).unwrap();
            let fragment: Storage = serde_json::from_str(&data).unwrap();
            if fragment.owner_key == owner_key {
                fragments.push(fragment);
            }
        }

        Ok(fragments)
    }

    pub fn search_fragment_in_virtual_storage(
        &self,
        identifier: &str,
        public: Option<bool>,
    ) -> Result<Vec<Storage>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(STORAGE_TABLE)?;
        let mut fragments = Vec::new();

        for item in table.iter()? {
            let (_, value) = item?;
            let data = String::from_utf8(value.value().to_vec()).unwrap();
            let fragment: Storage = serde_json::from_str(&data).unwrap();
            if (fragment.owner_key == identifier
                || fragment.file_hash == identifier
                || fragment.filename == identifier)
            {
                if public.is_none() {
                    fragments.push(fragment);
                } else if public.is_some() == fragment.public {
                    fragments.push(fragment);
                }
            }
        }

        Ok(fragments)
    }

    pub fn get_my_fragments(&self) -> Result<Vec<Storage>, Error> {
        let my_peer_id = self.get_or_create_peer_id().unwrap();
        let fragments = self.get_by_owner_key_fragments(&my_peer_id)?;
        Ok(fragments)
    }

    pub fn get_total_space(&self) -> Result<u64, StorageError> {
        let config = Config::from_file("config.toml");
        Ok(config.storage_size)
    }

    pub async fn get_storage_size(&self) -> Result<u64, StorageError> {
        let path = format!("{}/blobs", self.path);

        if !std::path::Path::new(&path).exists() {
            std::fs::create_dir_all(&path).unwrap();
            return Ok(0);
        }

        let mut total_size = 0u64;

        let mut entries = async_std::fs::read_dir(&path).await?;
        while let Some(entry) = entries.next().await {
            let entry = entry?;
            let metadata = entry.metadata().await?;
            if metadata.is_file() {
                total_size += metadata.len();
            }
        }

        Ok(total_size)
    }

    pub async fn get_storage_free_space(&self) -> Result<u64, StorageError> {
        let config = Config::from_file("config.toml");
        let free_space = config.storage_size - self.get_storage_size().await?;
        Ok(free_space)
    }

    pub fn update_fragment_public_access(
        &self,
        file_hash: &str,
        public: bool,
    ) -> Result<(), Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;

        {
            let mut table = tx.open_table(STORAGE_TABLE)?;
            let fragment_data = if let Some(data) = table.get(file_hash)? {
                let data = String::from_utf8(data.value().to_vec()).unwrap();
                let mut fragment: Storage = serde_json::from_str(&data).unwrap();
                fragment.public = public;
                serde_json::to_string(&fragment).unwrap()
            } else {
                return Err(Error::Corrupted("Фрагмент не найден".into()));
            };
            table.insert(file_hash, fragment_data.as_bytes())?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn remove_fragment(&self, file_hash: &str) -> Result<(), Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;

        {
            let mut table = tx.open_table(STORAGE_TABLE)?;
            table.remove(file_hash)?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn update_fragment_path(&self, file_hash: &str, new_path: &str) -> Result<(), Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;

        {
            let mut table = tx.open_table(STORAGE_TABLE)?;
            let data = table.get(file_hash)?;
            let json_str = String::from_utf8(
                data.ok_or_else(|| Error::Corrupted("Файл не найден".to_string()))?
                    .value()
                    .to_vec(),
            )
            .unwrap();
            let mut fragment: Storage = serde_json::from_str(&json_str).unwrap();
            fragment.filename = new_path.to_string();
            let updated_data = serde_json::to_string(&fragment).unwrap();
            table.insert(file_hash, updated_data.as_bytes())?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn update_token_used_space(&self, peer_id: &str, used_space: u64) -> Result<(), Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;

        {
            let mut table = tx.open_table(TOKENS_TABLE)?;
            let data = table.get(peer_id)?;
            let json_str = String::from_utf8(
                data.ok_or_else(|| Error::Corrupted("Токен не найден".to_string()))?
                    .value()
                    .to_vec(),
            )
            .unwrap();
            let mut token_info: TokenInfo = serde_json::from_str(&json_str).unwrap();
            token_info.used_space = used_space;
            let updated_data = serde_json::to_string(&token_info).unwrap();
            table.insert(peer_id, updated_data.as_bytes())?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn get_token_used_space(&self, peer_id: &str) -> Result<u64, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(TOKENS_TABLE)?;

        if let Some(data) = table.get(peer_id)? {
            let json_str = String::from_utf8(data.value().to_vec()).unwrap();
            let token_info: TokenInfo = serde_json::from_str(&json_str).unwrap();
            Ok(token_info.used_space)
        } else {
            Ok(0)
        }
    }

    pub fn add_file_to_group(&self, group_name: &str, file_hash: &str, tags: Vec<String>) -> Result<(), Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;

        {
            let mut table = tx.open_table(STORAGE_TABLE)?;
            let fragment_data = if let Some(data) = table.get(file_hash)? {
                let data = String::from_utf8(data.value().to_vec()).unwrap();
                let mut fragment: Storage = serde_json::from_str(&data).unwrap();
                
                if !fragment.groups.contains(&group_name.to_string()) {
                    fragment.groups.push(group_name.to_string());
                }
                fragment.tags.extend(tags);
                
                serde_json::to_string(&fragment).unwrap()
            } else {
                return Err(Error::Corrupted("Файл не найден".into()));
            };
            table.insert(file_hash, fragment_data.as_bytes())?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn remove_file_from_group(&self, group_name: &str, file_hash: &str) -> Result<(), Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;

        {
            let mut table = tx.open_table(STORAGE_TABLE)?;
            let fragment_data = if let Some(data) = table.get(file_hash)? {
                let data = String::from_utf8(data.value().to_vec()).unwrap();
                let mut fragment: Storage = serde_json::from_str(&data).unwrap();
                
                fragment.groups.retain(|g| g != group_name);
                
                serde_json::to_string(&fragment).unwrap()
            } else {
                return Err(Error::Corrupted("Файл не найден".into()));
            };
            table.insert(file_hash, fragment_data.as_bytes())?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn get_files_by_group(&self, group_name: &str) -> Result<Vec<Storage>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(STORAGE_TABLE)?;
        let mut fragments = Vec::new();

        for item in table.iter()? {
            let (_, value) = item?;
            let data = String::from_utf8(value.value().to_vec()).unwrap();
            let fragment: Storage = serde_json::from_str(&data).unwrap();
            if fragment.groups.contains(&group_name.to_string()) {
                fragments.push(fragment);
            }
        }

        Ok(fragments)
    }

    pub fn get_files_by_tag(&self, tag: &str) -> Result<Vec<Storage>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(STORAGE_TABLE)?;
        let mut fragments = Vec::new();

        for item in table.iter()? {
            let (_, value) = item?;
            let data = String::from_utf8(value.value().to_vec()).unwrap();
            let fragment: Storage = serde_json::from_str(&data).unwrap();
            if fragment.tags.contains(&tag.to_string()) {
                fragments.push(fragment);
            }
        }

        Ok(fragments)
    }

    pub fn get_all_groups(&self) -> Result<Vec<String>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(STORAGE_TABLE)?;
        let mut groups = std::collections::HashSet::new();

        for item in table.iter()? {
            let (_, value) = item?;
            let data = String::from_utf8(value.value().to_vec()).unwrap();
            let fragment: Storage = serde_json::from_str(&data).unwrap();
            groups.extend(fragment.groups);
        }

        Ok(groups.into_iter().collect())
    }

    pub fn get_all_tags(&self) -> Result<Vec<String>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(STORAGE_TABLE)?;
        let mut tags = std::collections::HashSet::new();

        for item in table.iter()? {
            let (_, value) = item?;
            let data = String::from_utf8(value.value().to_vec()).unwrap();
            let fragment: Storage = serde_json::from_str(&data).unwrap();
            tags.extend(fragment.tags);
        }

        Ok(tags.into_iter().collect())
    }

    pub fn update_fragment_metadata(
        &self,
        file_hash: &str,
        filename: String,
        mime: String,
        encrypted: bool,
        compressed: bool,
        auto_decompress: bool,
        public: bool,
        size: u64,
    ) -> Result<(), Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;

        {
            let mut table = tx.open_table(STORAGE_TABLE)?;
            let fragment_data = if let Some(data) = table.get(file_hash)? {
                let data = String::from_utf8(data.value().to_vec()).unwrap();
                let mut fragment: Storage = serde_json::from_str(&data).unwrap();
                
                fragment.filename = filename;
                fragment.mime = mime;
                fragment.encrypted = encrypted;
                fragment.compressed = compressed;
                fragment.auto_decompress = auto_decompress;
                fragment.public = public;
                fragment.size = size;
                
                serde_json::to_string(&fragment).unwrap()
            } else {
                return Err(Error::Corrupted("Фрагмент не найден".into()));
            };
            table.insert(file_hash, fragment_data.as_bytes())?;
        }

        tx.commit()?;
        Ok(())
    }
}
