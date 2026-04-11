use core::fmt;
mod debug_server;
use lp2ln_core_v2::db::P2PDatabase;
use lp2ln_core_v2::logger::info;
use lp2ln_core_v2::logger::LoggerOptions;
use lp2ln_core_v2::peer_score::PeerConnectionPolicy;
use lp2ln_core_v2::node::{NodeBuilder, NodeOptions};
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

struct Args {
    options_path: String,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            options_path: String::new(),
        }
    }
}

impl fmt::Display for Args {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "options_path = {}", self.options_path);
    }
}

fn parse_args() -> Args {
    let args: Vec<String> = env::args().collect();
    let mut result = Args::default();
    for (i, item) in args.iter().enumerate() {
        if i == 0 {
            continue;
        }
        let prev_arg = &args[i - 1];
        if (prev_arg == "-o" || prev_arg == "--options") && !item.starts_with("-") {
            result.options_path = item.clone();
        }
    }
    return result;
}

fn developer_options() -> NodeOptions {
    NodeOptions::empty()
        .with_listen("udp", "0.0.0.0:8080".parse().unwrap())
        .with_listen("tcp", "0.0.0.0:8080".parse().unwrap())
        .with_default_nodes(vec![])
        .with_peer_connection_policy(PeerConnectionPolicy {
            min_active_peers: 4,
            target_active_peers: 8,
            max_active_peers: 16,
        })
        .allow_unsigned_packets(true)
        .keypair_generate()
        .with_logger_options(LoggerOptions {
            log_dir: Some(PathBuf::from("./logs")),
            file_enabled: true,
            show_debug: true,
            show_info: true,
            show_warning: true,
            show_error: true,
        })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    lp2ln_core_v2::info!("[Main] Starting LP2LN-Demon");
    #[cfg(feature = "tokio-console")]
    {
        console_subscriber::init();
        lp2ln_core_v2::info!("[Main] console_subscriber inited (needs RUSTFLAGS=\"--cfg tokio_unstable\")");
    }

    let args = parse_args();

    lp2ln_core_v2::info!("[Main] Loaded args: {}", args);
    let options_path = if args.options_path.is_empty() {
        let default_path = PathBuf::from("./options.json");
        if default_path.exists() {
            Some(default_path.to_string_lossy().to_string())
        } else {
            None
        }
    } else {
        Some(args.options_path.clone())
    };

    let mut options = if let Some(path) = options_path.as_ref() {
        match NodeOptions::from_file(path) {
            Ok(opts) => {
                lp2ln_core_v2::info!("[Main] Loaded options from {}", path);
                opts
            }
            Err(err) => {
                lp2ln_core_v2::error!("[Main] Error reading options '{}': {}", path, err);
                developer_options()
            }
        }
    } else {
        developer_options()
    };

    if options.database_dir.is_none() {
        let default_db_dir = PathBuf::from("./db");
        lp2ln_core_v2::info!(
            "[Main] database_dir is not set, using default: {}",
            default_db_dir.display()
        );
        options.database_dir = Some(default_db_dir);
    }

    if let Some(path) = options_path.as_ref() {
        let _ = options.save(path);
    }

    let mut builder = NodeBuilder::new().add_default_transports_from_options(&options);
    let mut db_handle: Option<Arc<P2PDatabase>> = None;
    if let Some(ref dir) = options.database_dir {
        let dir_s = dir.to_string_lossy();
        match P2PDatabase::new(dir_s.as_ref()) {
            Ok(db) => {
                let db = Arc::new(db);
                builder = builder.db(db.clone());
                db_handle = Some(db);
                lp2ln_core_v2::info!("[Main] database_dir = {}", dir.display());
            }
            Err(e) => {
                lp2ln_core_v2::warn!(
                    "[Main] database_dir {:?} open failed (running without db): {}",
                    dir,
                    e
                );
            }
        }
    }
    let dbg_cfg = options.debug_server.clone();
    let mut node = builder.build(options)?;
    node.start().await?;
    let node = Arc::new(node);

    info("[Main] Node started");
    let eff = node.effective_peer_connection_policy();
    info(&format!(
        "[Main] peer-policy (effective): min={}, target={}, max={}; role={:?}",
        eff.min_active_peers,
        eff.target_active_peers,
        eff.max_active_peers,
        node.node_role()
    ));

    let _debug_server_task = debug_server::spawn_debug_server(
        debug_server::DebugServerConfig {
            enabled: dbg_cfg.enabled,
            bind_addr: dbg_cfg.bind_addr,
            push_interval_ms: dbg_cfg.push_interval_ms,
        },
        node.clone(),
        db_handle,
    );

    tokio::signal::ctrl_c().await?;
    node.stop().await?;
    lp2ln_core_v2::info!("[Main] LP2LN-Demon stopped");
    Ok(())
}
