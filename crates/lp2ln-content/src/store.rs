//! Content-addressed block store trait and backends.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use redb::Database;

use crate::error::ContentError;
use crate::id::{ContentId, content_id_hex, hash_bytes};
use crate::tables::BLOCK_TABLE;

/// Durable content-addressed block storage.
pub trait BlockStore: Send + Sync {
    fn put(&self, data: &[u8]) -> Result<ContentId, ContentError>;
    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, ContentError>;
    fn verify(&self, id: &ContentId) -> Result<bool, ContentError>;
    fn delete(&self, id: &ContentId) -> Result<(), ContentError>;
}

/// In-memory store for tests.
#[derive(Clone, Default)]
pub struct MemoryBlockStore {
    inner: Arc<RwLock<HashMap<ContentId, Vec<u8>>>>,
}

impl MemoryBlockStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BlockStore for MemoryBlockStore {
    fn put(&self, data: &[u8]) -> Result<ContentId, ContentError> {
        let id = hash_bytes(data);
        self.inner
            .write()
            .expect("memory store lock")
            .insert(id, data.to_vec());
        Ok(id)
    }

    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, ContentError> {
        Ok(self
            .inner
            .read()
            .expect("memory store lock")
            .get(id)
            .cloned())
    }

    fn verify(&self, id: &ContentId) -> Result<bool, ContentError> {
        match self.get(id)? {
            Some(data) => Ok(hash_bytes(&data) == *id),
            None => Ok(false),
        }
    }

    fn delete(&self, id: &ContentId) -> Result<(), ContentError> {
        self.inner.write().expect("memory store lock").remove(id);
        Ok(())
    }
}

/// redb-backed store sharing a node database handle.
#[derive(Clone)]
pub struct RedbBlockStore {
    db: Arc<Mutex<Database>>,
}

impl RedbBlockStore {
    pub fn from_database(db: Arc<Mutex<Database>>) -> Self {
        Self { db }
    }

    /// Open (or create) a standalone redb file and ensure the blocks table exists.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ContentError> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        let db = Database::create(path.as_ref())?;
        {
            let txn = db.begin_write()?;
            {
                let _ = txn.open_table(BLOCK_TABLE)?;
            }
            txn.commit()?;
        }
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
        })
    }

    pub fn database(&self) -> Arc<Mutex<Database>> {
        self.db.clone()
    }

    pub fn put(&self, data: &[u8]) -> Result<ContentId, ContentError> {
        let id = hash_bytes(data);
        let key = content_id_hex(&id);
        let lock = self.db.lock().expect("db lock");
        let txn = lock.begin_write()?;
        {
            let mut table = txn.open_table(BLOCK_TABLE)?;
            table.insert(key.as_str(), data)?;
        }
        txn.commit()?;
        Ok(id)
    }

    pub fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, ContentError> {
        let key = content_id_hex(id);
        let lock = self.db.lock().expect("db lock");
        let txn = lock.begin_read()?;
        let table = txn.open_table(BLOCK_TABLE)?;
        Ok(table.get(key.as_str())?.map(|v| v.value().to_vec()))
    }

    pub fn verify(&self, id: &ContentId) -> Result<bool, ContentError> {
        match self.get(id)? {
            Some(data) => Ok(hash_bytes(&data) == *id),
            None => Ok(false),
        }
    }

    pub fn delete(&self, id: &ContentId) -> Result<(), ContentError> {
        let key = content_id_hex(id);
        let lock = self.db.lock().expect("db lock");
        let txn = lock.begin_write()?;
        {
            let mut table = txn.open_table(BLOCK_TABLE)?;
            table.remove(key.as_str())?;
        }
        txn.commit()?;
        Ok(())
    }
}

impl BlockStore for RedbBlockStore {
    fn put(&self, data: &[u8]) -> Result<ContentId, ContentError> {
        RedbBlockStore::put(self, data)
    }

    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, ContentError> {
        RedbBlockStore::get(self, id)
    }

    fn verify(&self, id: &ContentId) -> Result<bool, ContentError> {
        RedbBlockStore::verify(self, id)
    }

    fn delete(&self, id: &ContentId) -> Result<(), ContentError> {
        RedbBlockStore::delete(self, id)
    }
}

/// One file per block under `{root}/{content_id_hex}`.
#[derive(Clone)]
pub struct FsBlockStore {
    root: PathBuf,
}

impl FsBlockStore {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, ContentError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path_for(&self, id: &ContentId) -> PathBuf {
        self.root.join(content_id_hex(id))
    }
}

impl BlockStore for FsBlockStore {
    fn put(&self, data: &[u8]) -> Result<ContentId, ContentError> {
        let id = hash_bytes(data);
        let dest = self.path_for(&id);
        let tmp = dest.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &dest)?;
        Ok(id)
    }

    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, ContentError> {
        let path = self.path_for(id);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn verify(&self, id: &ContentId) -> Result<bool, ContentError> {
        match self.get(id)? {
            Some(data) => Ok(hash_bytes(&data) == *id),
            None => Ok(false),
        }
    }

    fn delete(&self, id: &ContentId) -> Result<(), ContentError> {
        let path = self.path_for(id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_put_get_verify_delete() {
        let store = MemoryBlockStore::new();
        let data = b"hello memory";
        let id = store.put(data).unwrap();
        assert_eq!(store.get(&id).unwrap().unwrap(), data);
        assert!(store.verify(&id).unwrap());
        store.delete(&id).unwrap();
        assert!(store.get(&id).unwrap().is_none());
    }

    #[test]
    fn redb_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "lp2ln_content_redb_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let store = RedbBlockStore::open(dir.join("db")).unwrap();
        let data = b"hello redb";
        let id = store.put(data).unwrap();
        assert_eq!(store.get(&id).unwrap().unwrap(), data);
        assert!(store.verify(&id).unwrap());
        store.delete(&id).unwrap();
        assert!(store.get(&id).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fs_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "lp2ln_content_fs_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = FsBlockStore::new(&dir).unwrap();
        let data = b"hello fs";
        let id = store.put(data).unwrap();
        assert_eq!(store.get(&id).unwrap().unwrap(), data);
        assert!(store.verify(&id).unwrap());
        store.delete(&id).unwrap();
        assert!(store.get(&id).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
