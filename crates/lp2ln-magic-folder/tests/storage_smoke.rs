// Smoke tests — local-only paths (no DHT, no network).

use std::sync::Arc;

use lp2ln_content::encrypt::CHUNK_SIZE;
use lp2ln_magic_folder::{MagicFolder, open_db};

fn make_folder(root: impl Into<std::path::PathBuf>) -> Arc<MagicFolder> {
    let dir = std::env::temp_dir().join(format!("lp2ln_mf_{}", uuid::Uuid::new_v4()));
    let (store, raw_db) = open_db(dir.to_str().unwrap()).expect("open_db");
    let ns_id: [u8; 32] = rand::random();
    let ns_key: [u8; 32] = rand::random();
    Arc::new(MagicFolder::new(root, ns_id, ns_key, store, raw_db))
}

#[tokio::test]
async fn add_and_restore_single_file() {
    let root = std::env::temp_dir().join(format!("mf_root_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&root).await.unwrap();
    tokio::fs::write(root.join("hello.txt"), b"hello magic folder world!")
        .await.unwrap();

    let folder = make_folder(&root);
    folder.add_file("hello.txt").await.unwrap();
    let dm_id = folder.dir_manifest_id().await;

    let restore = std::env::temp_dir().join(format!("mf_restore_{}", uuid::Uuid::new_v4()));
    folder.restore_to(dm_id, &restore).await.unwrap();

    assert_eq!(
        tokio::fs::read(restore.join("hello.txt")).await.unwrap(),
        b"hello magic folder world!"
    );
}

#[tokio::test]
async fn add_multiple_files() {
    let root = std::env::temp_dir().join(format!("mf_multi_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&root).await.unwrap();
    tokio::fs::write(root.join("a.txt"), b"file A").await.unwrap();
    tokio::fs::write(root.join("b.txt"), b"file B different").await.unwrap();

    let folder = make_folder(&root);
    folder.add_file("a.txt").await.unwrap();
    folder.add_file("b.txt").await.unwrap();

    let restore = std::env::temp_dir().join(format!("mf_restore_multi_{}", uuid::Uuid::new_v4()));
    folder.restore_to(folder.dir_manifest_id().await, &restore).await.unwrap();

    assert_eq!(tokio::fs::read(restore.join("a.txt")).await.unwrap(), b"file A");
    assert_eq!(tokio::fs::read(restore.join("b.txt")).await.unwrap(), b"file B different");
}

#[tokio::test]
async fn large_file_streaming() {
    let root = std::env::temp_dir().join(format!("mf_large_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&root).await.unwrap();
    let size = CHUNK_SIZE * 3 + 12345;
    let data: Vec<u8> = (0u8..=255).cycle().take(size).collect();
    tokio::fs::write(root.join("big.bin"), &data).await.unwrap();

    let folder = make_folder(&root);
    folder.add_file("big.bin").await.unwrap();

    let restore = std::env::temp_dir().join(format!("mf_large_restore_{}", uuid::Uuid::new_v4()));
    folder.restore_to(folder.dir_manifest_id().await, &restore).await.unwrap();

    let restored = tokio::fs::read(restore.join("big.bin")).await.unwrap();
    assert_eq!(restored.len(), size);
    assert_eq!(restored, data);
}

#[tokio::test]
async fn tombstone_not_restored() {
    let root = std::env::temp_dir().join(format!("mf_tomb_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&root).await.unwrap();
    tokio::fs::write(root.join("keep.txt"), b"keep me").await.unwrap();
    tokio::fs::write(root.join("del.txt"), b"delete me").await.unwrap();

    let folder = make_folder(&root);
    folder.add_file("keep.txt").await.unwrap();
    folder.add_file("del.txt").await.unwrap();
    folder.remove_file("del.txt").await.unwrap();

    let restore = std::env::temp_dir().join(format!("mf_tomb_restore_{}", uuid::Uuid::new_v4()));
    folder.restore_to(folder.dir_manifest_id().await, &restore).await.unwrap();

    assert!(restore.join("keep.txt").exists());
    assert!(!restore.join("del.txt").exists());
}

#[tokio::test]
async fn dehydrate_and_hydrate_roundtrip() {
    let root = std::env::temp_dir().join(format!("mf_dh_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&root).await.unwrap();
    let original = b"dehydrate me completely";
    tokio::fs::write(root.join("doc.txt"), original).await.unwrap();

    let folder = make_folder(&root);
    folder.add_file("doc.txt").await.unwrap();

    // Dehydrate: original is replaced by doc.txt.lp2ln
    let ph = folder.dehydrate("doc.txt", false).await.unwrap();
    assert!(ph.exists(), "placeholder must exist");
    assert!(!root.join("doc.txt").exists(), "original must be gone");

    // Hydrate: restore from placeholder
    let restored = folder.hydrate(&ph).await.unwrap();
    assert_eq!(restored, root.join("doc.txt"));
    assert!(!ph.exists(), "placeholder must be cleaned up");
    assert_eq!(tokio::fs::read(&restored).await.unwrap(), original);
}

#[tokio::test]
async fn dehydrate_safety_check_fails_on_missing_blocks() {
    let root = std::env::temp_dir().join(format!("mf_safety_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&root).await.unwrap();
    tokio::fs::write(root.join("file.txt"), b"data").await.unwrap();

    // Build a folder where we never called add_file — manifest won't be in dir_manifest.
    let folder = make_folder(&root);
    let err = folder.dehydrate("file.txt", false).await.unwrap_err();
    assert!(err.to_string().contains("not in the folder manifest"), "got: {err}");
}

#[tokio::test]
async fn dehydrate_reingest_stale_file() {
    let root = std::env::temp_dir().join(format!("mf_stale_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&root).await.unwrap();
    tokio::fs::write(root.join("doc.txt"), b"version 1").await.unwrap();

    let folder = make_folder(&root);
    folder.add_file("doc.txt").await.unwrap();

    // Modify after ingest — dehydrate must not lose the new bytes.
    tokio::fs::write(root.join("doc.txt"), b"version 2 is longer").await.unwrap();

    let ph = folder.dehydrate("doc.txt", false).await.unwrap();
    let restored = folder.hydrate(&ph).await.unwrap();
    assert_eq!(tokio::fs::read(&restored).await.unwrap(), b"version 2 is longer");
}

#[tokio::test]
async fn poll_tombstones_deleted_files() {
    let root = std::env::temp_dir().join(format!("mf_del_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&root).await.unwrap();
    tokio::fs::write(root.join("gone.txt"), b"bye").await.unwrap();

    let folder = make_folder(&root);
    folder.poll(0).await; // ingest
    assert!(folder.ingested_files().await.iter().any(|(p, t)| p == "gone.txt" && !t));

    tokio::fs::remove_file(root.join("gone.txt")).await.unwrap();
    folder.poll(0).await; // detect deletion
    assert!(folder.ingested_files().await.iter().any(|(p, t)| p == "gone.txt" && *t));
}

#[tokio::test]
async fn merge_remote_adopt_and_conflict() {
    use lp2ln_content::manifest::{DirEntry, DirectoryManifest};

    let root = std::env::temp_dir().join(format!("mf_merge_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&root).await.unwrap();
    tokio::fs::write(root.join("doc.txt"), b"local v1").await.unwrap();

    let folder = make_folder(&root);
    let id_v1 = folder.add_file("doc.txt").await.unwrap();

    // Local edit + re-ingest → local entry now points to v2.
    tokio::fs::write(root.join("doc.txt"), b"local v2 edited").await.unwrap();
    folder.add_file("doc.txt").await.unwrap();

    // Remote manifest: concurrent update of doc.txt (points back to v1)
    // and a brand-new file new.txt (reuses v1 manifest for the test).
    let mut remote = DirectoryManifest::new(folder.namespace_id);
    remote.apply(DirEntry {
        path: "doc.txt".into(),
        manifest_id: id_v1,
        tombstone: false,
        modified_at: 1,
    });
    remote.apply(DirEntry {
        path: "new.txt".into(),
        manifest_id: id_v1,
        tombstone: false,
        modified_at: 1,
    });

    let changed = folder.merge_remote(&remote).await.unwrap();
    assert!(changed);

    // Conflict: local real file kept, remote lands as conflict placeholder.
    assert_eq!(
        tokio::fs::read(root.join("doc.txt")).await.unwrap(),
        b"local v2 edited"
    );
    let conflict_ph = root.join("doc (conflict from remote).txt.lp2ln");
    assert!(conflict_ph.exists(), "conflict placeholder must exist");
    let out = folder.hydrate(&conflict_ph).await.unwrap();
    assert_eq!(tokio::fs::read(&out).await.unwrap(), b"local v1");

    // Adopt: new remote file appears as placeholder, hydrates to content.
    let new_ph = root.join("new.txt.lp2ln");
    assert!(new_ph.exists(), "adopted placeholder must exist");
    let out = folder.hydrate(&new_ph).await.unwrap();
    assert_eq!(tokio::fs::read(&out).await.unwrap(), b"local v1");
}

#[tokio::test]
async fn merge_remote_tombstone_deletes_unmodified_only() {
    use lp2ln_content::manifest::{DirEntry, DirectoryManifest};

    let root = std::env::temp_dir().join(format!("mf_mtomb_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&root).await.unwrap();
    tokio::fs::write(root.join("clean.txt"), b"clean").await.unwrap();
    tokio::fs::write(root.join("dirty.txt"), b"dirty").await.unwrap();

    let folder = make_folder(&root);
    folder.add_file("clean.txt").await.unwrap();
    folder.add_file("dirty.txt").await.unwrap();

    // Modify dirty.txt after ingest — remote tombstone must NOT delete it.
    tokio::fs::write(root.join("dirty.txt"), b"dirty but edited").await.unwrap();

    let mut remote = DirectoryManifest::new(folder.namespace_id);
    for p in ["clean.txt", "dirty.txt"] {
        remote.apply(DirEntry {
            path: p.into(),
            manifest_id: [0u8; 32],
            tombstone: true,
            modified_at: 99,
        });
    }

    folder.merge_remote(&remote).await.unwrap();
    assert!(!root.join("clean.txt").exists(), "unmodified file must be deleted");
    assert!(root.join("dirty.txt").exists(), "locally modified file must survive tombstone");
}

#[tokio::test]
async fn load_state_survives_restart() {
    let root = std::env::temp_dir().join(format!("mf_restart_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&root).await.unwrap();
    tokio::fs::write(root.join("data.txt"), b"persistent").await.unwrap();

    let db_path = std::env::temp_dir().join(format!("mf_restart_db_{}", uuid::Uuid::new_v4()));
    let ns_id: [u8; 32] = rand::random();
    let ns_key: [u8; 32] = rand::random();

    // First instance: ingest.
    {
        let (store, raw_db) = open_db(db_path.to_str().unwrap()).unwrap();
        let folder = Arc::new(MagicFolder::new(&root, ns_id, ns_key, store, raw_db));
        folder.add_file("data.txt").await.unwrap();
    }

    // Second instance (simulated restart): load_state must restore the manifest.
    {
        let (store, raw_db) = open_db(db_path.to_str().unwrap()).unwrap();
        let folder = Arc::new(MagicFolder::new(&root, ns_id, ns_key, store, raw_db));
        folder.load_state().await.unwrap();

        // dehydrate should work because the manifest is loaded from the db.
        let ph = folder.dehydrate("data.txt", false).await.unwrap();
        assert!(ph.exists());
        let out = folder.hydrate(&ph).await.unwrap();
        assert_eq!(tokio::fs::read(out).await.unwrap(), b"persistent");
    }
}
