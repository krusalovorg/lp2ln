//! Receives UpdateAnnouncement packets over LP2LN, verifies the manifest,
//! stages the candidate binary, and notifies the parent updater via IPC.
//!
//! Activated when `LP2LN_UPDATER_IPC` env var is set (i.e. running under
//! lp2ln-updater). A standalone lp2lnd skips this module entirely.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use lp2ln_core_v2::router::Router;
use lp2ln_release::{
    ReleaseVerifyKey,
    manifest::{SignedManifest, UPDATE_PROTOCOL_ID},
};
use tokio::sync::Mutex;

mod ipc {
    use anyhow::Result;
    use serde::{Deserialize, Serialize};
    use tokio::io::{AsyncWriteExt, BufWriter};
    use tokio::net::TcpStream;

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum ChildMessage {
        Ready { build_id: String },
        CandidateStaged { build_id: String, staging_path: String },
    }

    pub struct UpdaterIpc {
        writer: BufWriter<tokio::net::tcp::OwnedWriteHalf>,
    }

    impl UpdaterIpc {
        pub async fn connect(addr: &str) -> Result<Self> {
            let stream = TcpStream::connect(addr).await?;
            let (_, w) = stream.into_split();
            Ok(Self { writer: BufWriter::new(w) })
        }

        pub async fn send(&mut self, msg: &ChildMessage) -> Result<()> {
            let mut line = serde_json::to_string(msg)?;
            line.push('\n');
            self.writer.write_all(line.as_bytes()).await?;
            self.writer.flush().await?;
            Ok(())
        }
    }
}

/// Report health to the parent updater, if running under one.
/// Call this once the node has started successfully.
pub async fn report_ready(build_id: &str) {
    let addr = match std::env::var(crate::update_handler::ENV_IPC) {
        Ok(a) => a,
        Err(_) => return, // not running under updater
    };
    match ipc::UpdaterIpc::connect(&addr).await {
        Ok(mut conn) => {
            if let Err(e) = conn.send(&ipc::ChildMessage::Ready { build_id: build_id.to_string() }).await {
                lp2ln_core_v2::warn!("[UpdateHandler] failed to send ready: {e}");
            } else {
                lp2ln_core_v2::info!("[UpdateHandler] reported ready to updater");
            }
        }
        Err(e) => lp2ln_core_v2::warn!("[UpdateHandler] could not connect to updater IPC: {e}"),
    }
}

const ENV_IPC: &str = "LP2LN_UPDATER_IPC";

/// Spawn the update listener. No-op if `LP2LN_UPDATER_IPC` is not set and
/// `trusted_key_hex` is None.
pub fn spawn(
    router: Arc<Router>,
    trusted_key_hex: Option<String>,
    staging_base: PathBuf,
    node_id: String,
) -> Option<tokio::task::JoinHandle<()>> {
    let ipc_addr = std::env::var(ENV_IPC).ok();

    let Some(key_hex) = trusted_key_hex else {
        lp2ln_core_v2::info!("[UpdateHandler] no trusted_release_key configured, update handler inactive");
        return None;
    };

    let verify_key = match ReleaseVerifyKey::from_hex(&key_hex) {
        Ok(k) => k,
        Err(e) => {
            lp2ln_core_v2::error!("[UpdateHandler] invalid trusted_release_key: {e}");
            return None;
        }
    };

    let mut rx = router.subscribe();
    let ipc_addr = Arc::new(Mutex::new(ipc_addr));

    Some(tokio::spawn(async move {
        lp2ln_core_v2::info!("[UpdateHandler] listening for updates on protocol_id=0x{UPDATE_PROTOCOL_ID:04X}");

        while let Ok(pkt) = rx.recv().await {
            if pkt.packet.protocol_id != Some(UPDATE_PROTOCOL_ID) {
                continue;
            }
            let payload = pkt.packet.data.as_slice();

            let signed = match SignedManifest::decode(payload) {
                Ok(m) => m,
                Err(e) => {
                    lp2ln_core_v2::warn!("[UpdateHandler] bad manifest encoding: {e}");
                    continue;
                }
            };

            if let Err(e) = signed.verify(&verify_key) {
                lp2ln_core_v2::warn!("[UpdateHandler] manifest signature invalid: {e}");
                continue;
            }

            let m = &signed.manifest;
            lp2ln_core_v2::info!(
                "[UpdateHandler] valid update: build={} channel={} rollout={}%",
                m.build_id, m.channel, m.rollout_percent
            );

            // Stagger check — skip if this node is outside the rollout slice.
            // ponytail: rollout_window hardcoded to 3600s; make it a field in
            // NodeOptions when rollout tuning is needed.
            let (should_apply, delay_secs) = lp2ln_release_rollout(&node_id, &m.build_id, m.rollout_percent, 3600);
            if !should_apply {
                lp2ln_core_v2::info!(
                    "[UpdateHandler] not in rollout slice (rollout={}%), skipping",
                    m.rollout_percent
                );
                continue;
            }
            if delay_secs > 0 {
                lp2ln_core_v2::info!("[UpdateHandler] stagger delay={delay_secs}s");
                tokio::time::sleep(tokio::time::Duration::from_secs(delay_secs)).await;
            }

            // Stage the candidate binary.
            // ponytail: real implementation downloads from content store using
            // m.package_hash (ContentId). For MVP: operator pre-places the
            // binary in staging_source/<build_id>/lp2lnd[.exe]; we just move it.
            let staging_path = staging_base
                .join("staging")
                .join(&m.build_id);

            if staging_path.exists() {
                lp2ln_core_v2::info!("[UpdateHandler] staging dir already exists, skipping download step");
            } else {
                // Try staging_source/ fallback (operator-placed binary).
                let source = staging_base.join("staging_source").join(&m.build_id);
                if source.exists() {
                    if let Err(e) = copy_dir_all(&source, &staging_path) {
                        lp2ln_core_v2::error!("[UpdateHandler] failed to copy from staging_source: {e}");
                        continue;
                    }
                } else {
                    lp2ln_core_v2::warn!(
                        "[UpdateHandler] no staged binary for build={} — \
                         place binary at staging_source/{}/lp2lnd[.exe] or integrate DHT download",
                        m.build_id, m.build_id
                    );
                    continue;
                }
            }

            // Notify updater.
            let addr_lock = ipc_addr.lock().await;
            if let Some(addr) = addr_lock.as_ref() {
                match ipc::UpdaterIpc::connect(addr).await {
                    Ok(mut conn) => {
                        let msg = ipc::ChildMessage::CandidateStaged {
                            build_id: m.build_id.clone(),
                            staging_path: staging_path.to_string_lossy().to_string(),
                        };
                        if let Err(e) = conn.send(&msg).await {
                            lp2ln_core_v2::error!("[UpdateHandler] failed to notify updater: {e}");
                        } else {
                            lp2ln_core_v2::info!("[UpdateHandler] notified updater: candidate staged");
                        }
                    }
                    Err(e) => lp2ln_core_v2::error!("[UpdateHandler] can't reach updater IPC: {e}"),
                }
            } else {
                lp2ln_core_v2::info!(
                    "[UpdateHandler] candidate staged at {} (no parent updater — manual restart needed)",
                    staging_path.display()
                );
            }
        }
    }))
}

fn lp2ln_release_rollout(
    node_id: &str,
    build_id: &str,
    rollout_percent: u8,
    rollout_window_secs: u64,
) -> (bool, u64) {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(node_id.as_bytes());
    h.update(b"|");
    h.update(build_id.as_bytes());
    let digest: [u8; 32] = h.finalize().into();
    let v = u64::from_le_bytes(digest[0..8].try_into().unwrap());
    let slot = (v % 100) as u8;
    let should_apply = slot < rollout_percent;
    let delay = if rollout_window_secs == 0 || !should_apply { 0 } else { v % rollout_window_secs };
    (should_apply, delay)
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst).context("creating staging dir")?;
    for entry in std::fs::read_dir(src).context("reading staging source")? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst_path)?;
        } else {
            std::fs::copy(entry.path(), &dst_path)?;
        }
    }
    Ok(())
}
