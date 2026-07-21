// Magic Folder Alpha — file ingest, dehydrate/hydrate, poll-based watcher.
//
// Pipeline: detect stable change → chunk+encrypt → BlockStore → FileManifest
//           → DirectoryManifest → (future) announce to DHT
//
// Restart-safety: the job journal (JOB_TABLE) persists phases for in-flight ingests.
// The latest DirectoryManifest id is stored in META_TABLE so state survives restarts.
// `load_state()` must be called after `new()` to restore in-memory state.
//
// Stability window: a file is only ingested once its (mtime, size) has been
// stable for `stability_secs` consecutive seconds — avoids ingesting mid-write files.
//
// ponytail: DHT announce, block replication, and IPC to lp2lnd go here when P7 network lands.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use redb::ReadableTable;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use lp2ln_content::encrypt::{CHUNK_SIZE, ChunkKey, decrypt_chunk, encrypt_chunk, generate_key};
use lp2ln_content::id::{ContentId, hash_bytes, unix_now};
use lp2ln_content::manifest::{DirEntry, DirectoryManifest, FileManifest};
use lp2ln_content::store::{BlockStore, RedbBlockStore};

use crate::db::{DIR_MANIFEST_KEY, JOB_TABLE, LAST_REMOTE_HEAD_KEY, META_TABLE};
use crate::node_client::NodeClient;
use crate::placeholder::Placeholder;

// ── Namespace head ───────────────────────────────────────────────────────────

/// Mutable pointer to the latest DirectoryManifest, published in the DHT under
/// namespace_id. MAC binds it to namespace_key (the capability) so devices
/// reject heads forged by nodes that relay but don't own the namespace.
#[derive(Debug, Serialize, Deserialize)]
struct HeadRecord {
    dir_manifest_id: ContentId,
    version: u64,
    mac: [u8; 32],
}

fn head_mac(namespace_key: &[u8; 32], dir_manifest_id: &ContentId, version: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(namespace_key);
    h.update(b"lp2ln-namespace-head");
    h.update(dir_manifest_id);
    h.update(version.to_le_bytes());
    h.finalize().into()
}

/// "dir/name.ext" → "dir/name (conflict from remote).ext"
fn conflict_path(rel: &str) -> String {
    let (dir, name) = match rel.rsplit_once('/') {
        Some((d, n)) => (format!("{d}/"), n),
        None => (String::new(), rel),
    };
    match name.rsplit_once('.') {
        Some((stem, ext)) => format!("{dir}{stem} (conflict from remote).{ext}"),
        None => format!("{dir}{name} (conflict from remote)"),
    }
}

// ── Job journal ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
enum JobPhase {
    Pending,
    Published { manifest_id: ContentId },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Job {
    relative_path: String,
    file_key: ChunkKey,
    phase: JobPhase,
}

// ── File state ───────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
struct FileSnapshot {
    mtime_secs: u64,
    size: u64,
}

struct PendingEntry {
    snap: FileSnapshot,
    since: Instant,
}

// ── MagicFolder ─────────────────────────────────────────────────────────────

pub struct MagicFolder {
    pub root: PathBuf,
    pub namespace_id: [u8; 32],
    pub namespace_key: [u8; 32],
    store: RedbBlockStore,
    raw_db: Arc<StdMutex<redb::Database>>,
    file_state: Mutex<HashMap<String, FileSnapshot>>,
    pending: Mutex<HashMap<String, PendingEntry>>,
    dir_manifest: Mutex<DirectoryManifest>,
    /// Optional connection to lp2lnd for DHT announce and remote block fetch.
    pub node_client: Option<Arc<NodeClient>>,
}

impl MagicFolder {
    pub fn new(
        root: impl Into<PathBuf>,
        namespace_id: [u8; 32],
        namespace_key: [u8; 32],
        store: RedbBlockStore,
        raw_db: Arc<StdMutex<redb::Database>>,
    ) -> Self {
        Self {
            root: root.into(),
            namespace_id,
            namespace_key,
            store,
            raw_db,
            file_state: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            dir_manifest: Mutex::new(DirectoryManifest::new(namespace_id)),
            node_client: None,
        }
    }

    pub fn with_node_client(mut self, nc: NodeClient) -> Self {
        self.node_client = Some(Arc::new(nc));
        self
    }

    // ── State persistence ────────────────────────────────────────────────────

    /// Restore in-memory dir_manifest and file_state from the durable database.
    /// Call once after `new()` before using dehydrate/hydrate or starting the watcher.
    pub async fn load_state(&self) -> anyhow::Result<()> {
        let dm_id = self.load_dir_manifest_id();
        if let Some(id) = dm_id {
            if let Ok(dm) = DirectoryManifest::load(&self.store, &id) {
                // Rebuild file_state: only include files currently on disk.
                let mut fs = HashMap::new();
                for entry in &dm.entries {
                    if entry.tombstone {
                        continue;
                    }
                    let abs = self.root.join(&entry.path);
                    if let Ok(meta) = std::fs::metadata(&abs) {
                        let mtime = mtime_secs(&meta);
                        fs.insert(entry.path.clone(), FileSnapshot { mtime_secs: mtime, size: meta.len() });
                    }
                }
                *self.dir_manifest.lock().await = dm;
                *self.file_state.lock().await = fs;
            }
        }
        Ok(())
    }

    fn load_dir_manifest_id(&self) -> Option<ContentId> {
        let lock = self.raw_db.lock().expect("db");
        let txn = lock.begin_read().ok()?;
        let t = txn.open_table(META_TABLE).ok()?;
        let val = t.get(DIR_MANIFEST_KEY).ok()??;
        val.value().try_into().ok()
    }

    fn save_dir_manifest_id(&self, id: &ContentId) -> anyhow::Result<()> {
        let lock = self.raw_db.lock().expect("db");
        let txn = lock.begin_write()?;
        {
            let mut t = txn.open_table(META_TABLE)?;
            t.insert(DIR_MANIFEST_KEY, id.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    // ── Job journal ──────────────────────────────────────────────────────────

    fn save_job(&self, job: &Job) -> anyhow::Result<()> {
        let key = hex::encode(hash_bytes(job.relative_path.as_bytes()));
        let val = postcard::to_allocvec(job)?;
        let lock = self.raw_db.lock().expect("db");
        let txn = lock.begin_write()?;
        {
            let mut t = txn.open_table(JOB_TABLE)?;
            t.insert(key.as_str(), val.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    fn load_pending_jobs(&self) -> anyhow::Result<Vec<Job>> {
        let lock = self.raw_db.lock().expect("db");
        let txn = lock.begin_read()?;
        let t = txn.open_table(JOB_TABLE)?;
        let mut out = Vec::new();
        for item in t.iter()? {
            let (_, v) = item?;
            if let Ok(job) = postcard::from_bytes::<Job>(v.value()) {
                if job.phase == JobPhase::Pending {
                    out.push(job);
                }
            }
        }
        Ok(out)
    }

    // ── Core ─────────────────────────────────────────────────────────────────

    /// Ingest `relative_path` (relative to `root`).
    /// Chunks, encrypts, stores, updates the DirectoryManifest.
    /// Returns the FileManifest ContentId.
    pub async fn add_file(&self, relative_path: &str) -> anyhow::Result<ContentId> {
        let abs = self.root.join(relative_path);
        let meta = tokio::fs::metadata(&abs).await?;
        let file_key = generate_key();

        self.save_job(&Job {
            relative_path: relative_path.to_string(),
            file_key,
            phase: JobPhase::Pending,
        })?;

        let chunk_ids = chunk_file_and_encrypt(&file_key, &abs, &self.store).await?;

        let mtime = meta.modified().ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or_else(unix_now);

        let manifest = FileManifest {
            original_name: relative_path.to_string(),
            file_size: meta.len(),
            chunk_ids,
            file_key,
            created_at: unix_now(),
            modified_at: mtime,
        };
        let manifest_id = manifest.store(&self.store)?;

        let dm_id = {
            let mut dm = self.dir_manifest.lock().await;
            let prev = dm.store(&self.store).ok();
            dm.prev_manifest_id = prev;
            dm.created_at = unix_now();
            dm.apply(DirEntry {
                path: relative_path.to_string(),
                manifest_id,
                tombstone: false,
                modified_at: mtime,
            });
            dm.store(&self.store)?
        };
        self.save_dir_manifest_id(&dm_id)?;

        self.file_state.lock().await.insert(
            relative_path.to_string(),
            FileSnapshot { mtime_secs: mtime, size: meta.len() },
        );

        self.save_job(&Job {
            relative_path: relative_path.to_string(),
            file_key,
            phase: JobPhase::Published { manifest_id },
        })?;

        // Seed blocks into lp2lnd's local store (so the node can serve them),
        // announce provider records, and publish the new namespace head.
        if let Some(nc) = &self.node_client {
            let mut all_ids = manifest.chunk_ids.clone();
            all_ids.push(manifest_id);
            all_ids.push(dm_id);
            self.seed_node_store(&all_ids).await;
            nc.announce_blocks(&all_ids).await;
            self.publish_head().await.ok();
        }

        Ok(manifest_id)
    }

    /// Copy blocks from the sidecar store into lp2lnd's local block store
    /// (min_replicas = 0 → local seed only). Best-effort.
    async fn seed_node_store(&self, ids: &[ContentId]) {
        let Some(nc) = &self.node_client else { return };
        for cid in ids {
            if let Ok(Some(data)) = self.store.get(cid) {
                nc.push_block(*cid, data, 0).await.ok();
            }
        }
    }

    /// Publish the current DirectoryManifest id as the signed namespace head.
    pub async fn publish_head(&self) -> anyhow::Result<()> {
        let Some(nc) = &self.node_client else { return Ok(()) };
        let (dm_id, version) = {
            let dm = self.dir_manifest.lock().await;
            (dm.store(&self.store)?, dm.version)
        };
        let head = HeadRecord {
            dir_manifest_id: dm_id,
            version,
            mac: head_mac(&self.namespace_key, &dm_id, version),
        };
        nc.put_head(self.namespace_id, postcard::to_allocvec(&head)?, version)
            .await
    }

    /// Tombstone a file entry without touching blocks.
    pub async fn remove_file(&self, relative_path: &str) -> anyhow::Result<()> {
        let dm_id = {
            let mut dm = self.dir_manifest.lock().await;
            let prev = dm.store(&self.store).ok();
            dm.prev_manifest_id = prev;
            dm.created_at = unix_now();
            dm.apply(DirEntry {
                path: relative_path.to_string(),
                manifest_id: [0u8; 32],
                tombstone: true,
                modified_at: unix_now(),
            });
            dm.store(&self.store)?
        };
        self.save_dir_manifest_id(&dm_id)?;
        self.file_state.lock().await.remove(relative_path);
        self.pending.lock().await.remove(relative_path);
        if self.node_client.is_some() {
            self.seed_node_store(&[dm_id]).await;
            self.publish_head().await.ok();
        }
        Ok(())
    }

    // ── Dehydrate / Hydrate ──────────────────────────────────────────────────

    /// Verify all blocks are local, write `<file>.lp2ln` placeholder, then delete original.
    /// Returns the placeholder path.
    ///
    /// `require_replication`: when true, every block (chunks + manifest) must be
    /// durably acked by at least one remote peer before the original is deleted.
    /// Pass false only in explicit unsafe local-only mode.
    ///
    /// Safety: original is only deleted after the placeholder is durably written.
    /// If the process dies between writing placeholder and deleting original, the user
    /// ends up with both — the placeholder is valid and the original is intact.
    pub async fn dehydrate(&self, relative_path: &str, require_replication: bool) -> anyhow::Result<PathBuf> {
        let abs = self.root.join(relative_path);
        anyhow::ensure!(abs.exists(), "file not found: {}", abs.display());

        let mut manifest_id = {
            let dm = self.dir_manifest.lock().await;
            dm.entries.iter()
                .find(|e| e.path == relative_path && !e.tombstone)
                .map(|e| e.manifest_id)
                .ok_or_else(|| anyhow::anyhow!(
                    "'{}' is not in the folder manifest — run 'add' first",
                    relative_path
                ))?
        };

        let mut manifest = FileManifest::load(&self.store, &manifest_id)
            .map_err(|e| anyhow::anyhow!("manifest not found locally: {e}"))?;

        // Staleness guard: if the file changed since ingest, re-ingest first —
        // otherwise deleting the original would silently lose the latest edits.
        let disk_meta = tokio::fs::metadata(&abs).await?;
        let disk_mtime = mtime_secs(&disk_meta);
        if manifest.file_size != disk_meta.len() || manifest.modified_at != disk_mtime {
            manifest_id = self.add_file(relative_path).await?;
            manifest = FileManifest::load(&self.store, &manifest_id)?;
        }

        // Safety check: all blocks must be present and verified.
        for (i, cid) in manifest.chunk_ids.iter().enumerate() {
            anyhow::ensure!(
                self.store.verify(cid).unwrap_or(false),
                "chunk {} of '{}' is missing or corrupt — cannot dehydrate safely",
                i, relative_path
            );
        }
        anyhow::ensure!(
            self.store.verify(&manifest_id).unwrap_or(false),
            "manifest block missing or corrupt"
        );

        // Replication safety policy: at least one confirmed remote replica per
        // block, or the caller explicitly accepted local-only risk.
        if require_replication {
            let nc = self.node_client.as_ref().ok_or_else(|| anyhow::anyhow!(
                "replication required but no node connection — \
                 use explicit local-only mode to dehydrate with a single local copy"
            ))?;
            let mut ids = manifest.chunk_ids.clone();
            ids.push(manifest_id);
            for cid in &ids {
                let data = self.store.get(cid)?
                    .ok_or_else(|| anyhow::anyhow!("block vanished during dehydrate"))?;
                let stored_by = nc.push_block(*cid, data, 1).await?;
                anyhow::ensure!(
                    !stored_by.is_empty(),
                    "no peer confirmed a replica of block {} — dehydrate would leave a single copy \
                     (use local-only mode to override)",
                    lp2ln_content::id::content_id_hex(cid)
                );
            }
        }

        let meta = tokio::fs::metadata(&abs).await?;
        let mtime = meta.modified().ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let placeholder = Placeholder::build(
            &self.namespace_id,
            &self.namespace_key,
            manifest_id,
            relative_path,
            meta.len(),
            mtime,
        );

        let ph_name = format!("{}.lp2ln", abs.file_name().unwrap().to_string_lossy());
        let ph_path = abs.with_file_name(ph_name);
        placeholder.write_to(&ph_path)?;

        // Only delete original after placeholder is durably written.
        tokio::fs::remove_file(&abs).await?;

        self.file_state.lock().await.remove(relative_path);
        self.pending.lock().await.remove(relative_path);

        Ok(ph_path)
    }

    /// Restore a file from its `.lp2ln` placeholder. Deletes placeholder on success.
    /// Returns the restored file path.
    pub async fn hydrate(&self, placeholder_path: &Path) -> anyhow::Result<PathBuf> {
        let ph = Placeholder::read_from(placeholder_path)?;
        anyhow::ensure!(
            ph.verify_mac(&self.namespace_key),
            "placeholder MAC invalid — wrong namespace_key or tampered file"
        );

        let manifest_id = ph.manifest_content_id()
            .ok_or_else(|| anyhow::anyhow!("invalid manifest_id in placeholder"))?;

        let out_abs = self.root.join(&ph.original_name);
        if let Some(parent) = out_abs.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        // Write to temp then rename so a crash leaves no partial file.
        let tmp = out_abs.with_extension("lp2ln_hydrating.tmp");

        let fm_bytes = self.load_block(&manifest_id).await
            .map_err(|e| anyhow::anyhow!("manifest not available (was the cache cleared?): {e}"))?;
        let manifest: FileManifest = postcard::from_bytes(&fm_bytes)
            .map_err(|e| anyhow::anyhow!("manifest decode: {e}"))?;

        {
            let mut file = tokio::fs::File::create(&tmp).await?;
            for (i, &cid) in manifest.chunk_ids.iter().enumerate() {
                let ct = self.load_block(&cid).await
                    .map_err(|e| anyhow::anyhow!("chunk {} unavailable: {e}", i))?;
                let plain = decrypt_chunk(&manifest.file_key, i as u32, &ct)
                    .map_err(|e| anyhow::anyhow!("chunk {} decrypt failed: {e}", i))?;
                file.write_all(&plain).await?;
            }
            file.flush().await?;
        }

        tokio::fs::rename(&tmp, &out_abs).await?;
        tokio::fs::remove_file(placeholder_path).await?;

        // Update file_state so the watcher does not re-ingest the just-restored file.
        let new_mtime = tokio::fs::metadata(&out_abs).await.ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.file_state.lock().await.insert(
            ph.original_name.clone(),
            FileSnapshot { mtime_secs: new_mtime, size: ph.file_size },
        );

        Ok(out_abs)
    }

    // ── Block loading (local + optional network fetch) ───────────────────────

    /// Get a block: local store first; if missing and NodeClient is set, find
    /// providers via DHT and fetch via lp2lnd's block_transfer.
    async fn load_block(&self, cid: &ContentId) -> anyhow::Result<Vec<u8>> {
        if let Some(data) = self.store.get(cid)? {
            return Ok(data);
        }
        if let Some(nc) = &self.node_client {
            let providers = nc.find_providers(*cid).await?;
            anyhow::ensure!(!providers.is_empty(), "no DHT providers for {}", lp2ln_content::id::content_id_hex(cid));
            let data = nc.fetch_block(*cid, &providers).await?;
            // Verify integrity before caching.
            anyhow::ensure!(
                lp2ln_content::id::hash_bytes(&data) == *cid,
                "fetched block failed integrity check"
            );
            self.store.put(&data)?;
            return Ok(data);
        }
        anyhow::bail!("block {} not in local store (no node connection)", lp2ln_content::id::content_id_hex(cid))
    }

    // ── Multi-device head sync ───────────────────────────────────────────────

    fn load_meta(&self, key: &str) -> Option<Vec<u8>> {
        let lock = self.raw_db.lock().expect("db");
        let txn = lock.begin_read().ok()?;
        let t = txn.open_table(META_TABLE).ok()?;
        let val = t.get(key).ok()??;
        Some(val.value().to_vec())
    }

    fn save_meta(&self, key: &str, val: &[u8]) -> anyhow::Result<()> {
        let lock = self.raw_db.lock().expect("db");
        let txn = lock.begin_write()?;
        {
            let mut t = txn.open_table(META_TABLE)?;
            t.insert(key, val)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Fetch the namespace head from the DHT and merge remote changes.
    /// Returns true if anything changed locally.
    pub async fn sync_remote_head(&self) -> anyhow::Result<bool> {
        let Some(nc) = &self.node_client else { return Ok(false) };
        let (Some(bytes), _seq) = nc.get_head(self.namespace_id).await? else {
            return Ok(false);
        };
        let head: HeadRecord = postcard::from_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("head decode: {e}"))?;
        anyhow::ensure!(
            head.mac == head_mac(&self.namespace_key, &head.dir_manifest_id, head.version),
            "namespace head MAC invalid — forged or wrong namespace_key"
        );

        // Skip if it's our own current head or one we already merged.
        let local_id = { self.dir_manifest.lock().await.store(&self.store)? };
        if head.dir_manifest_id == local_id
            || self.load_meta(LAST_REMOTE_HEAD_KEY).as_deref() == Some(head.dir_manifest_id.as_slice())
        {
            return Ok(false);
        }

        let dm_bytes = self.load_block(&head.dir_manifest_id).await
            .map_err(|e| anyhow::anyhow!("remote dir manifest {}: {e}",
                lp2ln_content::id::content_id_hex(&head.dir_manifest_id)))?;
        let remote: DirectoryManifest = postcard::from_bytes(&dm_bytes)
            .map_err(|e| anyhow::anyhow!("remote dir manifest decode: {e}"))?;
        anyhow::ensure!(remote.namespace_id == self.namespace_id, "namespace_id mismatch in remote manifest");

        let changed = self.merge_remote(&remote).await?;
        self.save_meta(LAST_REMOTE_HEAD_KEY, head.dir_manifest_id.as_slice())?;
        Ok(changed)
    }

    /// Merge a remote DirectoryManifest into local state.
    ///
    /// Alpha rules (never silently overwrite local bytes):
    /// - new/updated remote file, nothing hydrated locally → adopt entry, write placeholder;
    /// - remote update but a local (possibly edited) real file exists → keep local,
    ///   write `name (conflict from remote).ext.lp2ln` conflict placeholder;
    /// - remote tombstone → delete local file only if unmodified since last ingest.
    pub async fn merge_remote(&self, remote: &DirectoryManifest) -> anyhow::Result<bool> {
        let mut changed = false;
        for rentry in &remote.entries {
            let local = {
                self.dir_manifest.lock().await.entries.iter()
                    .find(|e| e.path == rentry.path)
                    .cloned()
            };
            if let Some(l) = &local {
                if l.manifest_id == rentry.manifest_id && l.tombstone == rentry.tombstone {
                    continue;
                }
                // Same path both edited: our entry is newer or equal → keep ours,
                // remote becomes a conflict copy below.
            }
            if self.merge_entry(rentry, local.as_ref()).await? {
                changed = true;
            }
        }
        if changed {
            let dm_id = {
                let mut dm = self.dir_manifest.lock().await;
                dm.version = dm.version.max(remote.version);
                dm.store(&self.store)?
            };
            self.save_dir_manifest_id(&dm_id)?;
        }
        Ok(changed)
    }

    async fn merge_entry(&self, rentry: &DirEntry, local: Option<&DirEntry>) -> anyhow::Result<bool> {
        let abs = self.root.join(&rentry.path);
        let ph_path = self.root.join(format!("{}{}", rentry.path, crate::placeholder::EXTENSION));

        if rentry.tombstone {
            let had_active_local = local.map(|l| !l.tombstone).unwrap_or(false);
            if abs.exists() {
                // Delete only if unmodified since last ingest — else keep (conflict wins local).
                let meta = tokio::fs::metadata(&abs).await?;
                let snap = FileSnapshot { mtime_secs: mtime_secs(&meta), size: meta.len() };
                let known = self.file_state.lock().await.get(&rentry.path).cloned();
                if known != Some(snap) {
                    return Ok(false); // locally modified — do not delete
                }
                tokio::fs::remove_file(&abs).await?;
            }
            if ph_path.exists() {
                tokio::fs::remove_file(&ph_path).await.ok();
            }
            if had_active_local || local.is_none() {
                let mut dm = self.dir_manifest.lock().await;
                dm.apply(rentry.clone());
                drop(dm);
                self.file_state.lock().await.remove(&rentry.path);
                self.pending.lock().await.remove(&rentry.path);
                return Ok(true);
            }
            return Ok(false);
        }

        // Remote active entry.
        let adopt = match local {
            None => true,
            Some(l) if l.tombstone => true,
            // Local entry exists: adopt only if no real local file (dehydrated/absent).
            Some(_) => !abs.exists(),
        };

        let fm_bytes = self.load_block(&rentry.manifest_id).await
            .map_err(|e| anyhow::anyhow!("file manifest for '{}': {e}", rentry.path))?;
        let fm: FileManifest = postcard::from_bytes(&fm_bytes)
            .map_err(|e| anyhow::anyhow!("file manifest decode for '{}': {e}", rentry.path))?;

        if adopt {
            let placeholder = Placeholder::build(
                &self.namespace_id,
                &self.namespace_key,
                rentry.manifest_id,
                &rentry.path,
                fm.file_size,
                fm.modified_at,
            );
            if let Some(parent) = ph_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            placeholder.write_to(&ph_path)?;
            let mut dm = self.dir_manifest.lock().await;
            dm.apply(rentry.clone());
            Ok(true)
        } else {
            // Conflict copy: local real file wins; remote version lands next to it.
            let cpath = conflict_path(&rentry.path);
            let cph = self.root.join(format!("{}{}", cpath, crate::placeholder::EXTENSION));
            let placeholder = Placeholder::build(
                &self.namespace_id,
                &self.namespace_key,
                rentry.manifest_id,
                &cpath,
                fm.file_size,
                fm.modified_at,
            );
            if let Some(parent) = cph.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            placeholder.write_to(&cph)?;
            Ok(false) // local entry unchanged
        }
    }

    // ── Restore whole directory ──────────────────────────────────────────────

    /// Restore all non-tombstoned files from a DirectoryManifest into `target`.
    pub async fn restore_to(&self, dir_manifest_id: ContentId, target: &Path) -> anyhow::Result<()> {
        let dm_bytes = self.load_block(&dir_manifest_id).await
            .map_err(|e| anyhow::anyhow!("dir manifest: {e}"))?;
        let dm = DirectoryManifest::load(&self.store, &dir_manifest_id)
            .or_else(|_| {
                // May have been fetched via network into store — retry after load_block cached it.
                let _ = self.store.put(&dm_bytes);
                DirectoryManifest::load(&self.store, &dir_manifest_id)
            })
            .map_err(|e| anyhow::anyhow!("dir manifest decode: {e}"))?;

        tokio::fs::create_dir_all(target).await?;

        for entry in dm.entries.iter().filter(|e| !e.tombstone) {
            let fm_bytes = self.load_block(&entry.manifest_id).await
                .map_err(|e| anyhow::anyhow!("file manifest for '{}': {e}", entry.path))?;
            let manifest: FileManifest = postcard::from_bytes(&fm_bytes)
                .map_err(|e| anyhow::anyhow!("file manifest decode for '{}': {e}", entry.path))?;

            let out = target.join(&entry.path);
            if let Some(parent) = out.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let mut file = tokio::fs::File::create(&out).await?;
            for (i, &cid) in manifest.chunk_ids.iter().enumerate() {
                let ct = self.load_block(&cid).await
                    .map_err(|e| anyhow::anyhow!("chunk {} of '{}': {e}", i, entry.path))?;
                let plain = decrypt_chunk(&manifest.file_key, i as u32, &ct)
                    .map_err(|e| anyhow::anyhow!("chunk {} decrypt for '{}': {e}", i, entry.path))?;
                file.write_all(&plain).await?;
            }
        }
        Ok(())
    }

    // ── Status ───────────────────────────────────────────────────────────────

    pub async fn dir_manifest_id(&self) -> ContentId {
        self.dir_manifest.lock().await.store(&self.store).unwrap_or([0u8; 32])
    }

    /// Returns (relative_path, is_tombstone) for all entries.
    pub async fn ingested_files(&self) -> Vec<(String, bool)> {
        self.dir_manifest.lock().await.entries.iter()
            .map(|e| (e.path.clone(), e.tombstone))
            .collect()
    }

    // ── Poll / watcher ───────────────────────────────────────────────────────

    /// One poll cycle with stability window.
    /// Files whose (mtime, size) has been stable for `stability_secs` get ingested.
    /// Use `stability_secs = 0` for an immediate initial scan.
    pub async fn poll(&self, stability_secs: u64) {
        let current = match self.scan_disk().await {
            Ok(v) => v,
            Err(_) => return,
        };

        let now = Instant::now();
        let stability = Duration::from_secs(stability_secs);

        let ready = {
            let file_state = self.file_state.lock().await;
            let mut pending = self.pending.lock().await;

            for (path, snap) in &current {
                match file_state.get(path) {
                    Some(known) if known == snap => {
                        // Unchanged since last ingest — clear from pending.
                        pending.remove(path);
                    }
                    _ => {
                        pending.entry(path.clone())
                            .and_modify(|p| {
                                if &p.snap != snap {
                                    // File is still changing — reset the stability timer.
                                    p.snap = snap.clone();
                                    p.since = now;
                                }
                            })
                            .or_insert_with(|| PendingEntry { snap: snap.clone(), since: now });
                    }
                }
            }
            // Clear entries for files that disappeared from disk.
            pending.retain(|p, _| current.contains_key(p));

            pending.iter()
                .filter(|(_, p)| p.since.elapsed() >= stability)
                .map(|(path, _)| path.clone())
                .collect::<Vec<_>>()
        };

        for path in ready {
            if self.add_file(&path).await.is_ok() {
                self.pending.lock().await.remove(&path);
            }
        }

        // Deletion detection: known files gone from disk with no placeholder → tombstone.
        let deleted: Vec<String> = {
            let file_state = self.file_state.lock().await;
            file_state.keys()
                .filter(|p| !current.contains_key(*p))
                .filter(|p| !self.root.join(format!("{p}{}", crate::placeholder::EXTENSION)).exists())
                .cloned()
                .collect()
        };
        for path in deleted {
            self.remove_file(&path).await.ok();
        }
    }

    async fn scan_disk(&self) -> anyhow::Result<HashMap<String, FileSnapshot>> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            let mut out = HashMap::new();
            scan_dir(&root, &root, &mut out);
            out
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Spawn background watcher and resume any pending (interrupted) ingest jobs.
    pub fn spawn(self: Arc<Self>, poll_interval_secs: u64, stability_secs: u64, cancel: CancellationToken) {
        // Resume interrupted ingest jobs from the journal.
        let svc = Arc::clone(&self);
        tokio::spawn(async move {
            if let Ok(jobs) = svc.load_pending_jobs() {
                for job in jobs {
                    svc.add_file(&job.relative_path).await.ok();
                }
            }
        });

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(poll_interval_secs));
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = interval.tick() => {
                        self.poll(stability_secs).await;
                        if let Err(e) = self.sync_remote_head().await {
                            eprintln!("[magic-folder] head sync: {e}");
                        }
                    }
                }
            }
        });
    }
}

// ── Streaming chunk+encrypt ──────────────────────────────────────────────────

async fn chunk_file_and_encrypt(
    key: &ChunkKey,
    path: &Path,
    store: &impl BlockStore,
) -> anyhow::Result<Vec<ContentId>> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut ids = Vec::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut chunk_index = 0u32;
    loop {
        let mut read = 0;
        while read < CHUNK_SIZE {
            let n = file.read(&mut buf[read..]).await?;
            if n == 0 { break; }
            read += n;
        }
        if read == 0 { break; }
        let ct = encrypt_chunk(key, chunk_index, &buf[..read])
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let id = store.put(&ct)?;
        ids.push(id);
        chunk_index += 1;
    }
    Ok(ids)
}

// ── Directory scanner ────────────────────────────────────────────────────────

fn scan_dir(root: &Path, dir: &Path, out: &mut HashMap<String, FileSnapshot>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return; };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue; };
        if meta.is_dir() {
            scan_dir(root, &path, out);
        } else if meta.is_file() {
            let Ok(rel) = path.strip_prefix(root) else { continue; };
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            if is_ignored(&rel_str) { continue; }
            out.insert(rel_str, FileSnapshot { mtime_secs: mtime_secs(&meta), size: meta.len() });
        }
    }
}

fn is_ignored(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    name.ends_with(".lp2ln")
        || name.ends_with(".lp2ln.tmp")
        || name.ends_with(".lp2ln_hydrating.tmp")
        || name.ends_with(".tmp")
        || name.starts_with(".~")
        || name.starts_with("~$")
        || name == ".DS_Store"
        || name == "Thumbs.db"
        || name.starts_with("._")
}

fn mtime_secs(meta: &std::fs::Metadata) -> u64 {
    meta.modified().ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
