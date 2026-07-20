// P4 gate — two-node block transfer end-to-end.
//
// Scenario:
//   1. Node A starts, stores a block locally, announces via DHT.
//   2. Node B connects to A, finds providers via DHT, downloads block.
//   3. B verifies ContentId matches and durably stores the block.
//   4. Both nodes stop cleanly; active_tasks == 0.

use std::sync::Arc;
use std::time::Duration;

use lp2ln_core_v2::db::P2PDatabase;
use lp2ln_core_v2::event_core::prelude::{CoreEvent, TransportEvent};
use lp2ln_core_v2::node::options::{BootstrapNode, ExperimentalOptions};
use lp2ln_core_v2::node::{NodeBuilder, NodeLifecycleState, NodeOptions};
use lp2ln_core_v2::storage::{block_store_from_db, hash_bytes};
use lp2ln_core_v2::storage::dht::{ProviderRecord, sign_record, verify_record};
use lp2ln_core_v2::transport::Transport;
use lp2ln_core_v2::transport::tcp::TcpTransport;

fn temp_db() -> Arc<P2PDatabase> {
    let dir = std::env::temp_dir().join(format!("p4_e2e_{}", uuid::Uuid::new_v4()));
    Arc::new(P2PDatabase::new(dir.to_str().unwrap()).expect("temp db"))
}

fn content_opts() -> NodeOptions {
    let mut opts = NodeOptions::empty();
    opts.experimental = ExperimentalOptions {
        dht: true,
        content: true,
        ..Default::default()
    };
    opts.enable_topology_maintenance = false;
    opts
}

// ── Unit: ProviderRecord sign/verify ─────────────────────────────────────────

#[test]
fn dht_record_sign_verify_roundtrip() {
    use lp2ln_core_v2::crypto::NodeKeypair;
    let kp = NodeKeypair::generate();
    let mut record = ProviderRecord {
        content_id: [1u8; 32],
        peer_id: kp.peer_id().to_string(),
        seq: 1000,
        expires_at_secs: lp2ln_content::unix_now() + 3600,
        sig: String::new(),
    };
    sign_record(kp.signing_key(), &mut record);
    assert!(!record.sig.is_empty());
    assert!(verify_record(&record));
}

#[test]
fn dht_record_rejects_tampered_peer_id() {
    use lp2ln_core_v2::crypto::NodeKeypair;
    let kp1 = NodeKeypair::generate();
    let kp2 = NodeKeypair::generate();
    let mut record = ProviderRecord {
        content_id: [2u8; 32],
        peer_id: kp1.peer_id().to_string(),
        seq: 1,
        expires_at_secs: lp2ln_content::unix_now() + 3600,
        sig: String::new(),
    };
    sign_record(kp1.signing_key(), &mut record);
    record.peer_id = kp2.peer_id().to_string();
    assert!(!verify_record(&record));
}

#[test]
fn dht_store_rejects_expired_record() {
    use lp2ln_core_v2::crypto::NodeKeypair;
    use lp2ln_core_v2::storage::dht::DhtStore;
    let kp = NodeKeypair::generate();
    let store = DhtStore::new(100);
    let mut r = ProviderRecord {
        content_id: [3u8; 32],
        peer_id: kp.peer_id().to_string(),
        seq: 1,
        expires_at_secs: 1, // already expired
        sig: String::new(),
    };
    sign_record(kp.signing_key(), &mut r);
    assert!(!store.insert(r));
    assert!(store.get_providers(&[3u8; 32]).is_empty());
}

#[test]
fn block_transfer_max_size_constant() {
    use lp2ln_core_v2::storage::block_transfer::MAX_BLOCK_SIZE;
    assert_eq!(MAX_BLOCK_SIZE, 16 * 1024 * 1024);
}

// ── Integration: two-node e2e gate ────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p4_two_node_block_transfer_gate() {
    // Node A
    let db_a = temp_db();
    let opts_a = content_opts().with_listen("tcp", "127.0.0.1:0".parse().unwrap());
    let mut node_a = NodeBuilder::new()
        .db(db_a.clone())
        .add_transport(Arc::new(TcpTransport::new()) as Arc<dyn Transport>)
        .build(opts_a)
        .expect("build node A");

    let mut bus_rx = node_a.core_bus().subscribe_events();
    node_a.start().await.expect("start node A");

    let addr_a = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(CoreEvent::Transport(TransportEvent::Ready(r))) = bus_rx.recv().await {
                if let Some(addr) = r.listen_addr {
                    return addr;
                }
            }
        }
    })
    .await
    .expect("node A transport ready timeout");

    let peer_id_a = node_a.peer_id().to_string();

    // Node B — bootstraps to A
    let db_b = temp_db();
    let mut opts_b = content_opts().with_listen("tcp", "127.0.0.1:0".parse().unwrap());
    opts_b.bootstrap_nodes = vec![BootstrapNode {
        addr: addr_a,
        protocols: vec!["tcp".to_string()],
        peer_id_hint: None,
    }];
    let mut node_b = NodeBuilder::new()
        .db(db_b.clone())
        .add_transport(Arc::new(TcpTransport::new()) as Arc<dyn Transport>)
        .build(opts_b)
        .expect("build node B");
    node_b.start().await.expect("start node B");

    // Wait for connection
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if node_b.active_peer_count() > 0 { break; }
        assert!(std::time::Instant::now() < deadline, "B never connected to A");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // A: store block + announce
    let payload = b"hello P4 e2e content gate";
    let store_a = block_store_from_db(db_a.clone());
    let content_id = store_a.put(payload).expect("put block on A");

    let dht_a = node_a.dht_service().expect("DHT service on A");
    dht_a.announce(content_id).await.expect("announce on A");

    // Let announce propagate
    tokio::time::sleep(Duration::from_millis(200)).await;

    // B: find providers
    let dht_b = node_b.dht_service().expect("DHT service on B");
    let providers = dht_b
        .find_providers(&peer_id_a, content_id)
        .await
        .expect("find_providers");
    assert!(!providers.is_empty(), "no providers found");
    assert!(providers.iter().any(|r| r.peer_id == peer_id_a));

    // B: fetch block
    let bt_b = node_b.block_transfer_service().expect("BlockTransfer on B");
    let provider_ids: Vec<String> = providers.iter().map(|r| r.peer_id.clone()).collect();
    let downloaded = bt_b
        .fetch_from_providers(content_id, &provider_ids)
        .await
        .expect("fetch_from_providers");

    assert_eq!(hash_bytes(&downloaded), content_id, "hash mismatch");
    assert_eq!(downloaded.as_slice(), payload.as_ref());

    // B: durable store
    let store_b = block_store_from_db(db_b.clone());
    let stored_id = store_b.put(&downloaded).expect("durable store on B");
    assert_eq!(stored_id, content_id);
    assert!(store_b.verify(&stored_id).expect("verify"));

    // Clean shutdown
    node_a.stop().await.expect("stop A");
    node_b.stop().await.expect("stop B");
    assert_eq!(node_a.lifecycle_state(), NodeLifecycleState::Stopped);
    assert_eq!(node_b.lifecycle_state(), NodeLifecycleState::Stopped);
    assert_eq!(node_a.lifecycle_active_tasks(), 0, "A has lingering tasks");
    assert_eq!(node_b.lifecycle_active_tasks(), 0, "B has lingering tasks");
}
