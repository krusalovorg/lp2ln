use std::sync::{Arc, Mutex};

use redb::{Database, TableDefinition};

use lp2ln_content::store::RedbBlockStore;
use lp2ln_content::tables::BLOCK_TABLE;

/// Durable job phases for the ingest journal.
pub const JOB_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("magic_folder_jobs");
/// Persists the latest DirectoryManifest ContentId so state survives restarts.
pub const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("magic_folder_meta");

pub const DIR_MANIFEST_KEY: &str = "dir_manifest_id";
/// Last remote head dir-manifest id we merged — avoids re-merging every poll.
pub const LAST_REMOTE_HEAD_KEY: &str = "last_remote_head";

/// Open (or create) the magic folder database and ensure all tables exist.
pub fn open_db(path: &str) -> anyhow::Result<(RedbBlockStore, Arc<Mutex<Database>>)> {
    let db = Database::create(path)?;
    {
        let txn = db.begin_write()?;
        {
            let _ = txn.open_table(BLOCK_TABLE)?;
            let _ = txn.open_table(JOB_TABLE)?;
            let _ = txn.open_table(META_TABLE)?;
        }
        txn.commit()?;
    }
    let db = Arc::new(Mutex::new(db));
    let store = RedbBlockStore::from_database(db.clone());
    Ok((store, db))
}
