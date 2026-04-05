use crate::db::{models::Storage, tables::STORAGE_TABLE};
use async_std::stream::StreamExt;
use redb::{Error, ReadableTable};

use super::P2PDatabase;

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
    /// Добавить файл в хранилище
    pub fn add_file(&self, file: Storage) -> Result<(), Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;
        {
            let mut table = tx.open_table(STORAGE_TABLE)?;
            let data = serde_json::to_string(&file).unwrap();
            table.insert(file.file_hash.as_str(), data.as_bytes())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Получить все файлы из хранилища
    pub fn get_all_files(&self) -> Result<Vec<Storage>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(STORAGE_TABLE)?;

        let mut result = Vec::new();
        for item in table.iter()? {
            let (_, value) = item?;
            let data = String::from_utf8(value.value().to_vec()).unwrap();
            let file: Storage = serde_json::from_str(&data).unwrap();
            result.push(file);
        }

        Ok(result)
    }

    /// Получить файл по хешу
    pub fn get_file_by_hash(&self, hash: &str) -> Result<Option<Storage>, Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_read()?;
        let table = tx.open_table(STORAGE_TABLE)?;

        if let Some(value) = table.get(hash)? {
            let data = String::from_utf8(value.value().to_vec()).unwrap();
            let file: Storage = serde_json::from_str(&data).unwrap();
            Ok(Some(file))
        } else {
            Ok(None)
        }
    }

    /// Удалить файл по хешу
    pub fn remove_file(&self, file_hash: &str) -> Result<(), Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;

        {
            let mut table = tx.open_table(STORAGE_TABLE)?;
            table.remove(file_hash)?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Обновить информацию о файле
    pub fn update_file(&self, file: Storage) -> Result<(), Error> {
        let db = self.db.lock().unwrap();
        let tx = db.begin_write()?;

        {
            let mut table = tx.open_table(STORAGE_TABLE)?;
            let data = serde_json::to_string(&file).unwrap();
            table.insert(file.file_hash.as_str(), data.as_bytes())?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Получить размер хранилища на диске
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
}
