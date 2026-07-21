// NodeClient — sidecar connection to a running lp2lnd node via App Plane (P7).
//
// Responsibilities:
//   announce_blocks  — after add_file: tell DHT "I have these chunks + manifest"
//   find_providers   — before remote fetch: "who has this block?"
//   fetch_block      — ask lp2lnd to pull the block from a provider peer
//
// All operations are serialized (Mutex<AppClient>) — one in-flight at a time.
// The lock is held across async I/O; that is intentional for a sidecar that
// issues one block op at a time.
//
// ponytail: add namespace-head broadcast (dir_manifest_id → all peers) for
//           automatic multi-device sync; for now both devices share namespace_key
//           and use find_providers per-block to pull what they need.

use tokio::sync::Mutex;

use lp2ln_app_sdk::{AppCapability, AppClient, ConnectOpts};
use lp2ln_content::id::ContentId;

pub struct NodeClient {
    client: Mutex<AppClient>,
}

impl NodeClient {
    /// Connect to lp2lnd's App Plane TCP dev endpoint, perform Hello.
    /// `addr` example: `"127.0.0.1:7777"` (must match `app_plane.dev_tcp_bind` in options.json).
    pub async fn connect(addr: &str) -> anyhow::Result<Self> {
        let opts = ConnectOpts::tcp(addr);
        let mut client = AppClient::connect(opts).await
            .map_err(|e| anyhow::anyhow!("App Plane connect {addr}: {e}"))?
            // block push/fetch acks can take up to 30s node-side per peer
            .with_read_timeout(std::time::Duration::from_secs(60));
        client
            .hello(&[AppCapability::Send, AppCapability::QueryStatus], None)
            .await
            .map_err(|e| anyhow::anyhow!("App Plane hello: {e}"))?;
        Ok(Self { client: Mutex::new(client) })
    }

    /// Tell the DHT that this node holds `content_ids`. Fire-and-forget style;
    /// errors are logged but don't fail the ingest pipeline.
    pub async fn announce_blocks(&self, content_ids: &[ContentId]) {
        let raw: Vec<Vec<u8>> = content_ids.iter().map(|id| id.to_vec()).collect();
        let mut guard = self.client.lock().await;
        if let Err(e) = guard.dht_announce(raw).await {
            tracing_or_eprintln(&format!("[NodeClient] announce_blocks failed: {e}"));
        }
    }

    /// Find DHT providers for `content_id`. Returns peer_ids.
    pub async fn find_providers(&self, content_id: ContentId) -> anyhow::Result<Vec<String>> {
        let mut guard = self.client.lock().await;
        guard
            .dht_find_providers(content_id.to_vec())
            .await
            .map_err(|e| anyhow::anyhow!("find_providers: {e}"))
    }

    /// Ask lp2lnd to fetch `content_id` from `peer_ids` via block_transfer.
    pub async fn fetch_block(&self, content_id: ContentId, peer_ids: &[String]) -> anyhow::Result<Vec<u8>> {
        let mut guard = self.client.lock().await;
        guard
            .block_fetch(content_id.to_vec(), peer_ids.to_vec())
            .await
            .map_err(|e| anyhow::anyhow!("fetch_block: {e}"))
    }

    /// Seed the block into lp2lnd's local store and replicate to up to
    /// `min_replicas` peers. Returns peer_ids that durably acked.
    pub async fn push_block(
        &self,
        content_id: ContentId,
        data: Vec<u8>,
        min_replicas: u32,
    ) -> anyhow::Result<Vec<String>> {
        let mut guard = self.client.lock().await;
        guard
            .block_push(content_id.to_vec(), data, min_replicas)
            .await
            .map_err(|e| anyhow::anyhow!("push_block: {e}"))
    }

    /// Publish the namespace head record under `key` in the DHT.
    pub async fn put_head(&self, key: [u8; 32], value: Vec<u8>, seq: u64) -> anyhow::Result<()> {
        let mut guard = self.client.lock().await;
        guard
            .dht_put_value(key.to_vec(), value, seq)
            .await
            .map_err(|e| anyhow::anyhow!("put_head: {e}"))
    }

    /// Fetch the freshest known namespace head record for `key`.
    pub async fn get_head(&self, key: [u8; 32]) -> anyhow::Result<(Option<Vec<u8>>, u64)> {
        let mut guard = self.client.lock().await;
        guard
            .dht_get_value(key.to_vec())
            .await
            .map_err(|e| anyhow::anyhow!("get_head: {e}"))
    }
}

fn tracing_or_eprintln(msg: &str) {
    eprintln!("{msg}");
}
