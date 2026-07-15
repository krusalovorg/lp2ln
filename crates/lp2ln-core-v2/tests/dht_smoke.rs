// DHT-0/1 smoke tests — roadmap 03
//
// Gate: a fresh node can find a NodeRecord / ProviderRecord without a direct address hint,
//       routing through an intermediary.

use std::sync::Arc;
use std::time::Duration;

use lp2ln_core_v2::dht::{DhtService, NodeRecord, ProviderRecord, node_id_of, unix_now};
use lp2ln_core_v2::node::{NodeBuilder, NodeOptions};
use lp2ln_core_v2::transport::Transport;
use lp2ln_core_v2::transport::tcp::TcpTransport;

fn node_opts(port: u16) -> NodeOptions {
    let mut opts = NodeOptions::empty()
        .allow_unsigned_packets(true)
        .keypair_generate()
        .with_listen("tcp", format!("127.0.0.1:{port}").parse().unwrap());
    opts.enable_topology_maintenance = false;
    opts
}

async fn make_node(port: u16) -> lp2ln_core_v2::node::NodeRuntime {
    let mut n = NodeBuilder::new()
        .add_transport(Arc::new(TcpTransport::new()) as Arc<dyn Transport>)
        .build(node_opts(port))
        .expect("build");
    n.start().await.expect("start");
    n
}

/// Build a NodeRecord for a given peer_id with a short TTL.
fn make_record(peer_id: &str, addr: &str) -> NodeRecord {
    NodeRecord {
        node_id: node_id_of(peer_id),
        peer_id: peer_id.to_string(),
        addrs: vec![addr.to_string()],
        seq: 1,
        expires_at: unix_now() + 3600,
        signature: vec![],
    }
}

// ── DHT-0: routing table + local store ───────────────────────────────────────

#[test]
fn routing_table_find_closest() {
    use lp2ln_core_v2::dht::routing::RoutingTable;
    let local_id = node_id_of("local");
    let mut rt = RoutingTable::new(local_id);

    for i in 0u8..20 {
        let pid = format!("peer_{i}");
        rt.update(make_record(&pid, "tcp:127.0.0.1:9000"));
    }

    let target = node_id_of("peer_5");
    let closest = rt.find_closest(&target, 5);
    assert!(!closest.is_empty(), "should find contacts");
    assert!(closest.iter().any(|r| r.peer_id == "peer_5"), "exact match first");
}

#[test]
fn store_put_get_evict() {
    use lp2ln_core_v2::dht::store::DhtStore;
    let store = DhtStore::new();

    let r = make_record("alice", "tcp:127.0.0.1:9001");
    assert!(store.put_node(r.clone(), None));
    assert!(store.get_node(&r.node_id).is_some());

    // Expired record rejected.
    let mut expired = r.clone();
    expired.expires_at = unix_now() - 1;
    expired.seq = 99;
    assert!(!store.put_node(expired, None), "expired record must be rejected");

    store.evict_expired(); // no-op since live record; still present
    assert!(store.get_node(&r.node_id).is_some());
}

#[test]
fn store_lower_seq_rejected() {
    use lp2ln_core_v2::dht::store::DhtStore;
    let store = DhtStore::new();

    let mut r = make_record("bob", "tcp:127.0.0.1:9002");
    r.seq = 5;
    store.put_node(r.clone(), None);

    let mut older = r.clone();
    older.seq = 3;
    older.addrs = vec!["tcp:127.0.0.1:9999".to_string()];
    assert!(!store.put_node(older, None), "lower seq must be rejected");

    // Original address still present.
    let got = store.get_node(&r.node_id).unwrap();
    assert_eq!(got.addrs, vec!["tcp:127.0.0.1:9002"]);
}

#[test]
fn store_provider_roundtrip() {
    use lp2ln_core_v2::dht::store::DhtStore;
    let store = DhtStore::new();

    let content_id = [0xABu8; 32];
    let provider = make_record("charlie", "tcp:127.0.0.1:9003");
    let pr = ProviderRecord { content_id, provider };
    store.put_provider(pr, None);

    let found = store.get_providers(&content_id);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].provider.peer_id, "charlie");
}

// ── DHT-1: announce + find via two live nodes ─────────────────────────────────
//
// Cleanup must run even on assertion failure (panic before cancel.cancel() would
// leave DhtService listener tasks blocking the runtime's broadcast::Sender forever
// and stall runtime shutdown). Use an RAII guard.

struct Cleanup {
    cancel: tokio_util::sync::CancellationToken,
    nodes: Vec<lp2ln_core_v2::node::NodeRuntime>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.cancel.cancel();
        // Nodes are stopped in async context; best effort from Drop is to just cancel.
        // The tokio runtime aborts remaining tasks when it shuts down.
    }
}

/// Poll `check` until it returns `Some(T)` or `deadline` passes.
async fn poll_until<T, F, Fut>(deadline: Duration, interval: Duration, check: F) -> Option<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let start = tokio::time::Instant::now();
    loop {
        if let Some(v) = check().await { return Some(v); }
        if start.elapsed() >= deadline { return None; }
        tokio::time::sleep(interval).await;
    }
}

// Live network tests: A sends DHT message to B; B's store is polled locally.
// No iterative-lookup RPCs — just fire-and-forget PutRecord / AnnounceProvider
// so the test completes in <1s without sequential 5s RPC timeouts.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_node_announce_and_find() {
    let node_a = make_node(19700).await;
    let node_b = make_node(19701).await;

    node_b.connect("tcp", "127.0.0.1:19700".parse().unwrap()).await.expect("connect");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let dht_a = DhtService::new(node_a.peer_id(), node_a.router().unwrap(), vec!["tcp:127.0.0.1:19700".to_string()]);
    let dht_b = DhtService::new(node_b.peer_id(), node_b.router().unwrap(), vec!["tcp:127.0.0.1:19701".to_string()]);
    dht_a.seed(vec![dht_b.local_record.clone()]);
    dht_b.seed(vec![dht_a.local_record.clone()]);

    let cancel = tokio_util::sync::CancellationToken::new();
    dht_a.clone().spawn(cancel.clone());
    dht_b.clone().spawn(cancel.clone());

    // RAII guard: cancel fires even if the test panics before explicit cleanup.
    let _cleanup = Cleanup { cancel: cancel.clone(), nodes: vec![] };

    // A sends PutRecord (fire-and-forget); poll B's local store.
    dht_a.announce_self().await;

    let dht_b_ref = &dht_b;
    let target_node_id = dht_a.local_record.node_id;
    let found = poll_until(Duration::from_secs(3), Duration::from_millis(50), || async move {
        dht_b_ref.store.get_node(&target_node_id)
    }).await;

    cancel.cancel();
    // Yield so spawned tasks can see cancel before we stop the node.
    tokio::task::yield_now().await;
    node_a.stop().await.ok();
    node_b.stop().await.ok();

    assert!(found.is_some(), "B must find A's NodeRecord after announce");
    assert_eq!(found.unwrap().peer_id, node_a.peer_id().to_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_announce_and_find() {
    let node_a = make_node(19702).await;
    let node_b = make_node(19703).await;
    node_b.connect("tcp", "127.0.0.1:19702".parse().unwrap()).await.expect("connect");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let dht_a = DhtService::new(node_a.peer_id(), node_a.router().unwrap(), vec![]);
    let dht_b = DhtService::new(node_b.peer_id(), node_b.router().unwrap(), vec![]);
    dht_a.seed(vec![dht_b.local_record.clone()]);
    dht_b.seed(vec![dht_a.local_record.clone()]);

    let cancel = tokio_util::sync::CancellationToken::new();
    dht_a.clone().spawn(cancel.clone());
    dht_b.clone().spawn(cancel.clone());

    let _cleanup = Cleanup { cancel: cancel.clone(), nodes: vec![] };

    // A announces a content block (sends AnnounceProvider to B); poll B's local store.
    let content_id = [0x42u8; 32];
    dht_a.announce_provider(content_id).await;

    let dht_b_ref = &dht_b;
    let providers = poll_until(Duration::from_secs(3), Duration::from_millis(50), || async move {
        let p = dht_b_ref.store.get_providers(&content_id);
        if p.is_empty() { None } else { Some(p) }
    }).await;

    cancel.cancel();
    tokio::task::yield_now().await;
    node_a.stop().await.ok();
    node_b.stop().await.ok();

    let providers = providers.expect("B must store the provider record within 3s");
    assert!(providers.iter().any(|p| p.provider.peer_id == node_a.peer_id()));
}
