use async_std::path::PathBuf;
use redb::{Database, Error};
use std::sync::{Arc, Mutex};

use super::tables;

#[derive(Clone, Debug)]
pub struct P2PDatabase {
    pub db: Arc<Mutex<Database>>,
    pub path: String,
}

impl P2PDatabase {
    pub fn new(path: &str) -> Result<Self, Error> {
        let db_file = PathBuf::from(path).join("db");

        let db = Database::create(db_file)?;
        {
            let write_txn = db.begin_write()?;
            {
                write_txn.open_table(tables::STORAGE_TABLE)?;
                write_txn.open_table(tables::PEER_INFO_TABLE)?;
                write_txn.open_table(tables::SECRET_KEYS_TABLE)?;
                write_txn.open_table(tables::TOKENS_TABLE)?;
                write_txn.open_table(tables::VALIDATOR_STORAGE_TABLE)?;
                write_txn.open_table(tables::PEER_STATS_TABLE)?;
                write_txn.open_table(tables::CONTRACT_METADATA_TABLE)?;
            }
            write_txn.commit()?;
        }

        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            path: path.to_string(),
        })
    }
}
