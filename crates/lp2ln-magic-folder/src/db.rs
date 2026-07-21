use std::sync::{Arc, Mutex};

use redb::{Database, ReadableTable, TableDefinition};

use lp2ln_content::store::FsBlockStore;
use lp2ln_content::tables::BLOCK_TABLE;

/// Durable job phases for the ingest journal.
pub const JOB_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("magic_folder_jobs");
/// Persists the latest DirectoryManifest ContentId so state survives restarts.
pub const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("magic_folder_meta");

pub const DIR_MANIFEST_KEY: &str = "dir_manifest_id";
/// Last remote head dir-manifest id we merged — avoids re-merging every poll.
pub const LAST_REMOTE_HEAD_KEY: &str = "last_remote_head";

/// Open (or create) the magic folder database and block store.
///
/// Metadata (jobs, meta) lives in redb at `path`; blocks live as one file per
/// block under `{path}.blocks/` — redb never shrinks and serializes MiB-sized
/// blobs through one lock, so blobs don't belong in it.
///
/// Blocks written by older versions into redb's BLOCK_TABLE are migrated to
/// the filesystem store once, then removed from the database.
pub fn open_db(path: &str) -> anyhow::Result<(FsBlockStore, Arc<Mutex<Database>>)> {
    let db = Database::create(path)?;
    let store = FsBlockStore::new(format!("{path}.blocks"))?;
    {
        let txn = db.begin_write()?;
        {
            let mut blocks = txn.open_table(BLOCK_TABLE)?;
            let _ = txn.open_table(JOB_TABLE)?;
            let _ = txn.open_table(META_TABLE)?;

            // One-time migration: copy legacy in-db blocks to the fs store.
            let mut keys = Vec::new();
            for item in blocks.iter()? {
                let (k, v) = item?;
                store.put(v.value())?;
                keys.push(k.value().to_string());
            }
            for k in &keys {
                blocks.remove(k.as_str())?;
            }
            if !keys.is_empty() {
                println!("[magic-folder] migrated {} blocks from db to {path}.blocks", keys.len());
            }
        }
        txn.commit()?;
    }
    let db = Arc::new(Mutex::new(db));
    Ok((store, db))
}

/// Fallback for `hydrate` when a running daemon holds the exclusive redb lock
/// (redb is single-process): hydrate only needs the block folder and the
/// network, never the metadata db — so pair the real block store with a
/// throwaway scratch db in the OS temp dir.
pub fn open_store_scratch(path: &str) -> anyhow::Result<(FsBlockStore, Arc<Mutex<Database>>)> {
    let store = FsBlockStore::new(format!("{path}.blocks"))?;
    let scratch = std::env::temp_dir().join(format!("lp2ln-mf-scratch-{}.redb", std::process::id()));
    let db = Database::create(&scratch)?;
    Ok((store, Arc::new(Mutex::new(db))))
}
