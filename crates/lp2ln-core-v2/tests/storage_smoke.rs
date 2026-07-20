use std::sync::Arc;

use lp2ln_core_v2::db::P2PDatabase;
use lp2ln_core_v2::storage::encrypt::{CHUNK_SIZE, decrypt_chunk, encrypt_chunk, generate_key};
use lp2ln_core_v2::storage::lease::ReplicaLease;
use lp2ln_core_v2::storage::manifest::{DirEntry, DirectoryManifest, FileManifest};
use lp2ln_core_v2::storage::{ContentId, block_store_from_db, lease_store_from_db};

fn temp_db() -> Arc<P2PDatabase> {
    let dir = std::env::temp_dir().join(format!("lp2ln_storage_smoke_{}", uuid::Uuid::new_v4()));
    Arc::new(P2PDatabase::new(dir.to_str().unwrap()).expect("db"))
}

// ── encrypt ──────────────────────────────────────────────────────────────────

#[test]
fn encrypt_decrypt_roundtrip() {
    let key = generate_key();
    let plain = b"hello M5 content-encrypted world";
    let ct = encrypt_chunk(&key, 0, plain).unwrap();
    assert_ne!(&ct[24..], plain.as_slice());
    let recovered = decrypt_chunk(&key, 0, &ct).unwrap();
    assert_eq!(recovered.as_slice(), plain.as_slice());
}

#[test]
fn wrong_chunk_index_fails_auth() {
    let key = generate_key();
    let ct = encrypt_chunk(&key, 0, b"important data").unwrap();
    assert!(decrypt_chunk(&key, 1, &ct).is_err());
}

#[test]
fn wrong_key_fails_auth() {
    let key1 = generate_key();
    let key2 = generate_key();
    let ct = encrypt_chunk(&key1, 0, b"secret").unwrap();
    assert!(decrypt_chunk(&key2, 0, &ct).is_err());
}

#[test]
fn multi_chunk_encrypt() {
    let key = generate_key();
    let data: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE * 3 + 7).collect();
    let mut reconstructed = Vec::new();
    for (i, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
        let ct = encrypt_chunk(&key, i as u32, chunk).unwrap();
        let plain = decrypt_chunk(&key, i as u32, &ct).unwrap();
        reconstructed.extend_from_slice(&plain);
    }
    assert_eq!(reconstructed, data);
}

#[test]
fn reencrypt_same_index_fresh_nonce() {
    let key = generate_key();
    let a = encrypt_chunk(&key, 0, b"v1").unwrap();
    let b = encrypt_chunk(&key, 0, b"v2").unwrap();
    assert_ne!(&a[..24], &b[..24]);
    assert_eq!(decrypt_chunk(&key, 0, &a).unwrap(), b"v1");
    assert_eq!(decrypt_chunk(&key, 0, &b).unwrap(), b"v2");
}

// ── manifest ─────────────────────────────────────────────────────────────────

#[test]
fn file_manifest_store_load_roundtrip() {
    let db = temp_db();
    let store = block_store_from_db(db);
    let key = generate_key();
    let manifest = FileManifest {
        original_name: "hello.txt".to_string(),
        file_size: 42,
        chunk_ids: vec![[0u8; 32], [1u8; 32]],
        file_key: key,
        created_at: 1000,
        modified_at: 2000,
    };
    let id = manifest.store(&store).unwrap();
    let loaded = FileManifest::load(&store, &id).unwrap();
    assert_eq!(loaded.original_name, "hello.txt");
    assert_eq!(loaded.file_size, 42);
    assert_eq!(loaded.file_key, key);
    assert_eq!(loaded.chunk_ids.len(), 2);
}

#[test]
fn dir_manifest_versioning_and_tombstone() {
    let ns_id = [99u8; 32];
    let mut dm = DirectoryManifest::new(ns_id);
    assert_eq!(dm.version, 0);

    let v1 = dm.apply(DirEntry {
        path: "a.txt".to_string(),
        manifest_id: [1u8; 32],
        tombstone: false,
        modified_at: 10,
    });
    assert_eq!(v1, 1);
    assert_eq!(dm.entries.len(), 1);

    // Second file
    dm.apply(DirEntry {
        path: "b.txt".to_string(),
        manifest_id: [2u8; 32],
        tombstone: false,
        modified_at: 20,
    });
    assert_eq!(dm.version, 2);
    assert_eq!(dm.entries.len(), 2);

    // Tombstone a.txt (upsert)
    dm.apply(DirEntry {
        path: "a.txt".to_string(),
        manifest_id: [0u8; 32],
        tombstone: true,
        modified_at: 30,
    });
    assert_eq!(dm.version, 3);
    assert_eq!(dm.entries.len(), 2); // same count, upserted
    assert!(
        dm.entries
            .iter()
            .find(|e| e.path == "a.txt")
            .unwrap()
            .tombstone
    );
    assert!(
        !dm.entries
            .iter()
            .find(|e| e.path == "b.txt")
            .unwrap()
            .tombstone
    );
}

#[test]
fn dir_manifest_store_load() {
    let db = temp_db();
    let store = block_store_from_db(db);
    let mut dm = DirectoryManifest::new([5u8; 32]);
    dm.apply(DirEntry {
        path: "readme.md".to_string(),
        manifest_id: [3u8; 32],
        tombstone: false,
        modified_at: 42,
    });
    let id = dm.store(&store).unwrap();
    let loaded = DirectoryManifest::load(&store, &id).unwrap();
    assert_eq!(loaded.namespace_id, [5u8; 32]);
    assert_eq!(loaded.entries.len(), 1);
    assert_eq!(loaded.entries[0].path, "readme.md");
}

// ── lease store ──────────────────────────────────────────────────────────────

#[test]
fn lease_store_put_get_count() {
    let db = temp_db();
    let ls = lease_store_from_db(db);
    let cid: ContentId = [7u8; 32];

    let lease = ReplicaLease {
        content_id: cid,
        holder_peer_id: "peer-abc".to_string(),
        expires_at: u64::MAX,
        granted_at: 0,
    };
    ls.put(&lease).unwrap();

    let leases = ls.get_leases(&cid).unwrap();
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].holder_peer_id, "peer-abc");
    assert_eq!(ls.live_count(&cid).unwrap(), 1);

    // Second holder
    ls.put(&ReplicaLease {
        content_id: cid,
        holder_peer_id: "peer-xyz".to_string(),
        expires_at: u64::MAX,
        granted_at: 0,
    })
    .unwrap();
    assert_eq!(ls.live_count(&cid).unwrap(), 2);

    // Expired lease doesn't count
    ls.put(&ReplicaLease {
        content_id: cid,
        holder_peer_id: "peer-expired".to_string(),
        expires_at: 1, // already expired
        granted_at: 0,
    })
    .unwrap();
    assert_eq!(ls.live_count(&cid).unwrap(), 2);

    // Remove one
    ls.remove(&cid, "peer-abc").unwrap();
    assert_eq!(ls.live_count(&cid).unwrap(), 1);
}
