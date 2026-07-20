//! lp2ln-updater — stable parent that supervises the lp2lnd child.
//!
//! Usage:
//!   lp2ln-updater [--base <dir>] [--options <path>] [--health-timeout <secs>]
//!                 [--crash-threshold <n>] [--rollout-window <secs>]
//!
//! Directory layout (all under --base, default ./lp2ln):
//!   state/active.json           — currently active build
//!   state/last-known-good.json  — last successfully health-checked build
//!   versions/<build-id>/lp2lnd  — installed binaries
//!   staging/<build-id>/lp2lnd   — candidate being staged by child

mod health;
mod layout;
mod state;

use std::{
    path::PathBuf,
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use health::{ChildMessage, HealthServer, UpdaterMessage};
use layout::Layout;
use state::StateStore;
use tokio::{process::Command, time::sleep};

#[derive(Debug)]
struct Config {
    base: PathBuf,
    options_path: Option<PathBuf>,
    /// Seconds child has to connect + send "ready". Default 30.
    health_timeout: u64,
    /// Consecutive crashes before rollback. Default 3.
    crash_threshold: u8,
}

impl Config {
    fn from_args() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let get = |flag: &str| -> Option<String> {
            args.windows(2)
                .find(|w| w[0] == flag)
                .map(|w| w[1].clone())
        };
        Self {
            base: get("--base").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("./lp2ln")),
            options_path: get("--options").map(PathBuf::from),
            health_timeout: get("--health-timeout").and_then(|s| s.parse().ok()).unwrap_or(30),
            crash_threshold: get("--crash-threshold").and_then(|s| s.parse().ok()).unwrap_or(3),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Config::from_args();
    let layout = Layout::new(&cfg.base);
    let store = StateStore::new(&layout.state_dir())?;

    eprintln!("[updater] base={} health_timeout={}s", cfg.base.display(), cfg.health_timeout);

    let mut crash_count: u8 = 0;

    loop {
        let active = store
            .load_active()
            .context("loading active state")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no active build in state/active.json — run 'lp2ln-release-tool package' \
                     and install a build first"
                )
            })?;

        eprintln!("[updater] starting build={} binary={}", active.build_id, active.binary_path.display());

        let health_server = HealthServer::bind().await.context("binding health IPC")?;
        eprintln!("[updater] health IPC listening on {}", health_server.addr);

        let start = Instant::now();
        let mut child = spawn_child(&active.binary_path, &cfg, &health_server).await?;

        // Wait for child to connect and send "ready".
        match health_server.accept_with_timeout(cfg.health_timeout).await {
            Err(e) => {
                eprintln!("[updater] health accept failed: {e}");
                child.kill().await.ok();
                crash_count += 1;
                handle_crash(crash_count, cfg.crash_threshold, &store).await?;
                continue;
            }
            Ok(mut conn) => {
                // Drain messages until "ready" or child exits.
                loop {
                    tokio::select! {
                        status = child.wait() => {
                            let code = status.map(|s| s.code()).ok().flatten();
                            eprintln!("[updater] child exited early (code={code:?}) after {}ms",
                                start.elapsed().as_millis());
                            crash_count += 1;
                            handle_crash(crash_count, cfg.crash_threshold, &store).await?;
                            break;
                        }
                        msg = conn.recv(cfg.health_timeout) => {
                            match msg {
                                Ok(Some(ChildMessage::Ready { build_id })) => {
                                    eprintln!("[updater] child healthy build={build_id}");
                                    store.promote_active_to_lkg().context("promoting to LKG")?;
                                    crash_count = 0;

                                    // Now watch for candidate_staged while child runs.
                                    loop {
                                        tokio::select! {
                                            status = child.wait() => {
                                                let elapsed = start.elapsed().as_secs();
                                                let code = status.map(|s| s.code()).ok().flatten();
                                                eprintln!(
                                                    "[updater] child exited (code={code:?}) after {elapsed}s"
                                                );
                                                // Count as crash only if it died quickly.
                                                if elapsed < 60 {
                                                    crash_count += 1;
                                                    handle_crash(crash_count, cfg.crash_threshold, &store).await?;
                                                }
                                                break;
                                            }
                                            msg = conn.recv(3600) => {
                                                match msg {
                                                    Ok(Some(ChildMessage::CandidateStaged { build_id, staging_path })) => {
                                                        eprintln!("[updater] candidate staged build={build_id} path={staging_path}");
                                                        conn.send(&UpdaterMessage::Shutdown).await.ok();
                                                        sleep(Duration::from_secs(3)).await;
                                                        child.kill().await.ok();
                                                        child.wait().await.ok();

                                                        match apply_candidate(&layout, &store, &build_id, &staging_path).await {
                                                            Ok(()) => {
                                                                eprintln!("[updater] candidate committed, restarting");
                                                                crash_count = 0;
                                                            }
                                                            Err(e) => {
                                                                eprintln!("[updater] candidate apply failed: {e:#}, rolling back");
                                                                rollback(&store).await?;
                                                            }
                                                        }
                                                        break; // outer loop → restart child
                                                    }
                                                    Ok(Some(ChildMessage::Ready { .. })) => continue, // duplicate, ignore
                                                    Ok(None) | Err(_) => {
                                                        eprintln!("[updater] IPC connection closed");
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    break;
                                }
                                Ok(Some(ChildMessage::CandidateStaged { .. })) => {
                                    eprintln!("[updater] got candidate_staged before ready — ignoring");
                                    continue;
                                }
                                Ok(None) => {
                                    eprintln!("[updater] child IPC closed before ready");
                                    child.kill().await.ok();
                                    crash_count += 1;
                                    handle_crash(crash_count, cfg.crash_threshold, &store).await?;
                                    break;
                                }
                                Err(e) => {
                                    eprintln!("[updater] IPC error before ready: {e}");
                                    child.kill().await.ok();
                                    crash_count += 1;
                                    handle_crash(crash_count, cfg.crash_threshold, &store).await?;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Brief pause before restarting to avoid tight spin on repeated crashes.
        sleep(Duration::from_secs(1)).await;
    }
}

async fn spawn_child(
    binary: &std::path::Path,
    cfg: &Config,
    health: &HealthServer,
) -> Result<tokio::process::Child> {
    let mut cmd = Command::new(binary);
    cmd.env(health::ENV_IPC_ADDR, health.addr.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(opts) = &cfg.options_path {
        cmd.args(["-o", &opts.to_string_lossy()]);
    }
    cmd.spawn().with_context(|| format!("spawning {}", binary.display()))
}

async fn apply_candidate(
    layout: &Layout,
    store: &StateStore,
    build_id: &str,
    _staging_path: &str, // child already placed files at staging/<build_id>/
) -> Result<()> {
    let binary = layout.promote_staging(build_id).context("promoting staging")?;
    store.commit_active(build_id, binary).context("committing active state")
}

async fn handle_crash(
    crash_count: u8,
    threshold: u8,
    store: &StateStore,
) -> Result<()> {
    if crash_count >= threshold {
        eprintln!("[updater] crash loop detected ({crash_count} crashes) — rolling back to LKG");
        rollback(store).await?;
    } else {
        eprintln!("[updater] crash #{crash_count}/{threshold}, retrying");
    }
    Ok(())
}

async fn rollback(store: &StateStore) -> Result<()> {
    match store.load_lkg().context("loading LKG")? {
        Some(lkg) => {
            eprintln!("[updater] rolling back to build={}", lkg.build_id);
            store.commit_active(&lkg.build_id, lkg.binary_path)
                .context("writing rollback active state")
        }
        None => {
            anyhow::bail!("rollback requested but no last-known-good state exists");
        }
    }
}
