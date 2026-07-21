// lp2ln-magic-folder — daemon and CLI for watched folder ingest/dehydrate/hydrate.
//
// Subcommands:
//   daemon    -o options.json            watch folder, ingest changes, sync remote head
//   add       <path> -o options.json     explicitly ingest a single file
//   dehydrate <path> [--local-only]      replace file with .lp2ln placeholder
//                                        (requires ≥1 confirmed remote replica unless --local-only)
//   hydrate   <path.lp2ln> -o options.json  restore file from placeholder
//   sync      -o options.json            fetch namespace head from DHT, merge remote changes
//   restore   [target] -o options.json   restore all namespace files into target (default: root)
//   status    -o options.json            show ingested file list
//
// Options JSON:
//   {
//     "root":               "/path/to/watched/folder",
//     "db_path":            "./magic-folder.db",
//     "poll_interval_secs": 5,
//     "stability_secs":     2,
//     "namespace_id":       "<64 hex chars>",   <- auto-generated on first run
//     "namespace_key":      "<64 hex chars>"    <- auto-generated on first run, keep secret
//   }

use std::path::PathBuf;
use std::sync::Arc;

use lp2ln_content::id::content_id_hex;
use lp2ln_magic_folder::{MagicFolder, NodeClient, open_db};
use tokio_util::sync::CancellationToken;

#[derive(serde::Deserialize, serde::Serialize)]
struct Options {
    root: String,
    db_path: String,
    #[serde(default = "default_poll")]
    poll_interval_secs: u64,
    #[serde(default = "default_stability")]
    stability_secs: u64,
    namespace_id: Option<String>,
    namespace_key: Option<String>,
    /// TCP address of lp2lnd's App Plane dev endpoint (e.g. "127.0.0.1:7777").
    /// Set `app_plane.dev_tcp_bind` in lp2lnd's options.json to the same address.
    /// If absent, magic folder runs local-only (no DHT / remote block fetch).
    node_addr: Option<String>,
}

fn default_poll() -> u64 { 5 }
fn default_stability() -> u64 { 2 }

fn parse_args() -> (String, Vec<String>, PathBuf) {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut opts_path = PathBuf::from("magic-folder.json");
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if (args[i] == "-o" || args[i] == "--options") && i + 1 < args.len() {
            opts_path = PathBuf::from(&args[i + 1]);
            i += 2;
        } else if args[i].starts_with('-') {
            i += 1;
        } else {
            positional.push(args[i].clone());
            i += 1;
        }
    }
    let subcmd = positional.first().cloned().unwrap_or_else(|| "daemon".to_string());
    let rest = positional.into_iter().skip(1).collect();
    (subcmd, rest, opts_path)
}

fn parse_hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    hex::decode(s)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 64 hex chars (32 bytes)"))
}

fn hex32(b: &[u8; 32]) -> String { hex::encode(b) }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (subcmd, args, opts_path) = parse_args();

    let raw = std::fs::read_to_string(&opts_path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}\nCreate it with at least {{\"root\":\"...\",\"db_path\":\"...\"}}", opts_path.display()))?;
    let mut opts: Options = serde_json::from_str(&raw)?;

    // Auto-generate namespace keys on first use; write back to options file.
    let mut dirty = false;
    if opts.namespace_id.is_none() {
        let id: [u8; 32] = rand::random();
        println!("generated namespace_id:  {}", hex32(&id));
        opts.namespace_id = Some(hex32(&id));
        dirty = true;
    }
    if opts.namespace_key.is_none() {
        let key: [u8; 32] = rand::random();
        println!("generated namespace_key: {} (keep secret — this is the decryption capability)", hex32(&key));
        opts.namespace_key = Some(hex32(&key));
        dirty = true;
    }
    if dirty {
        std::fs::write(&opts_path, serde_json::to_string_pretty(&opts)?)?;
        println!("saved to {}", opts_path.display());
    }

    let namespace_id = parse_hex32(opts.namespace_id.as_deref().unwrap())?;
    let namespace_key = parse_hex32(opts.namespace_key.as_deref().unwrap())?;

    let (store, raw_db) = open_db(&opts.db_path)?;
    let mut folder = MagicFolder::new(&opts.root, namespace_id, namespace_key, store, raw_db);

    if let Some(addr) = &opts.node_addr {
        match NodeClient::connect(addr).await {
            Ok(nc) => {
                println!("connected to lp2lnd App Plane at {addr}");
                folder = folder.with_node_client(nc);
            }
            Err(e) => eprintln!("warning: cannot connect to lp2lnd ({addr}): {e} — running local-only"),
        }
    }

    let folder = Arc::new(folder);
    folder.load_state().await?;

    match subcmd.as_str() {
        "daemon" => {
            std::fs::create_dir_all(&opts.root)?;
            println!("watching:    {}", opts.root);
            println!("db:          {}", opts.db_path);
            println!("poll:        {}s  stability: {}s", opts.poll_interval_secs, opts.stability_secs);

            // Initial scan with no stability delay so already-present files are ingested immediately.
            folder.poll(0).await;
            if let Err(e) = folder.sync_remote_head().await {
                eprintln!("warning: initial head sync: {e}");
            }
            println!("initial scan done — dir: {}", content_id_hex(&folder.dir_manifest_id().await));

            let cancel = CancellationToken::new();
            let c2 = cancel.clone();
            tokio::spawn(async move { tokio::signal::ctrl_c().await.ok(); c2.cancel(); });

            Arc::clone(&folder).spawn(opts.poll_interval_secs, opts.stability_secs, cancel.clone());
            cancel.cancelled().await;
            println!("stopped");
        }

        "add" => {
            let path = args.first().ok_or_else(|| anyhow::anyhow!("usage: add <path>"))?;
            let rel = abs_to_rel(path, &opts.root)?;
            let cid = folder.add_file(&rel).await?;
            println!("ingested '{}' → manifest {}", rel, content_id_hex(&cid));
        }

        "dehydrate" => {
            let path = args.first().ok_or_else(|| anyhow::anyhow!("usage: dehydrate <path> [--local-only]"))?;
            let rel = abs_to_rel(path, &opts.root)?;

            // Without --local-only, every block must be acked by ≥1 remote peer
            // before the original is deleted (TZ dehydrate safety policy).
            let local_only = std::env::args().any(|a| a == "--local-only");
            if local_only {
                println!("warning: --local-only — after dehydrate the local db holds the only copy");
            }

            // Ingest if not already in the manifest.
            let already_ingested = folder.ingested_files().await
                .into_iter()
                .any(|(p, tombstone)| p == rel && !tombstone);
            if !already_ingested {
                println!("ingesting '{}'…", rel);
                folder.add_file(&rel).await?;
            }

            let ph = folder.dehydrate(&rel, !local_only).await?;
            println!("dehydrated → {}", ph.display());
        }

        "sync" => {
            let changed = folder.sync_remote_head().await?;
            println!("sync: {}", if changed { "remote changes merged" } else { "up to date" });
            println!("dir manifest: {}", content_id_hex(&folder.dir_manifest_id().await));
        }

        "restore" => {
            let target = args.first().cloned().unwrap_or_else(|| opts.root.clone());
            folder.sync_remote_head().await.ok();
            let dm_id = folder.dir_manifest_id().await;
            folder.restore_to(dm_id, std::path::Path::new(&target)).await?;
            println!("restored namespace into {}", target);
        }

        "hydrate" => {
            let path = args.first().ok_or_else(|| anyhow::anyhow!("usage: hydrate <path.lp2ln>"))?;
            let out = folder.hydrate(std::path::Path::new(path)).await?;
            println!("hydrated → {}", out.display());
        }

        "status" => {
            let files = folder.ingested_files().await;
            if files.is_empty() {
                println!("no files ingested");
            } else {
                for (path, tombstone) in &files {
                    println!("  [{}] {}", if *tombstone { "deleted" } else { "active " }, path);
                }
                println!("dir manifest: {}", content_id_hex(&folder.dir_manifest_id().await));
            }
        }

        _ => {
            eprintln!("unknown subcommand '{subcmd}'");
            eprintln!("usage: lp2ln-magic-folder [daemon|add|dehydrate|hydrate|sync|restore|status] [-o options.json] [<path>]");
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Convert a path argument (absolute or relative to CWD) to a path relative to the folder root.
fn abs_to_rel(path: &str, root: &str) -> anyhow::Result<String> {
    let abs = std::fs::canonicalize(path)
        .map_err(|e| anyhow::anyhow!("cannot resolve '{path}': {e}"))?;
    let root_abs = std::fs::canonicalize(root)
        .map_err(|e| anyhow::anyhow!("cannot resolve root '{root}': {e}"))?;
    let rel = abs.strip_prefix(&root_abs)
        .map_err(|_| anyhow::anyhow!("'{}' is outside the watched folder '{}'", abs.display(), root_abs.display()))?
        .to_string_lossy()
        .replace('\\', "/");
    Ok(rel)
}
