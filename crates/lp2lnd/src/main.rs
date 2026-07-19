use core::fmt;
mod app_plane_server;
mod debug_server;
mod ipc_tcp;
use lp2ln_core_v2::db::P2PDatabase;
use lp2ln_core_v2::logger::LoggerOptions;
use lp2ln_core_v2::logger::info;
use lp2ln_core_v2::node::{
    ConfigAutonomy, NodeBuilder, NodeOptions, StartupConfigSource, health_server,
};
use lp2ln_core_v2::peer_score::PeerConnectionPolicy;
use std::env;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

#[derive(Default)]
struct Args {
    options_path: String,
}

impl fmt::Display for Args {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "options_path = {}", self.options_path)
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
    result
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
        lp2ln_core_v2::info!(
            "[Main] console_subscriber inited (needs RUSTFLAGS=\"--cfg tokio_unstable\")"
        );
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

    let config_engine = ConfigAutonomy::new(options_path.as_ref().map(PathBuf::from));
    let startup = config_engine.load_startup(developer_options)?;
    let mut options = startup.options;
    if let Some(reason) = startup.degraded_reason.as_ref() {
        lp2ln_core_v2::warn!("[Main] startup in degraded mode: {}", reason);
    }
    match startup.source {
        StartupConfigSource::PrimaryConfig => {
            lp2ln_core_v2::info!("[Main] Config loaded transactionally");
        }
        StartupConfigSource::LastKnownGood => {
            lp2ln_core_v2::warn!("[Main] Rolled back to last-known-good config");
        }
        StartupConfigSource::DeveloperDefaults => {
            lp2ln_core_v2::warn!("[Main] Running with developer defaults");
        }
    }

    if options.database_dir.is_none() {
        let default_db_dir = PathBuf::from("./db");
        lp2ln_core_v2::info!(
            "[Main] database_dir is not set, using default: {}",
            default_db_dir.display()
        );
        options.database_dir = Some(default_db_dir);
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
    let ipc_cfg = ipc_tcp::IpcTcpServerConfig::from(&options.ipc_tcp);
    let mut node = builder.build(options.clone())?;
    node.start().await?;
    let node = Arc::new(node);
    let applied_options = Arc::new(RwLock::new(options.clone()));

    info("[Main] Node started");
    info("[Main] Node started");
    const PEER_ID_HIGHLIGHT: &str = "\x1b[47;30m";
    const ANSI_RESET: &str = "\x1b[0m";
    println!(
        "[Main] peer_id: {}{}{}",
        PEER_ID_HIGHLIGHT,
        node.peer_id(),
        ANSI_RESET
    );
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
        db_handle.clone(),
    );
    let _ipc_tcp_task = ipc_tcp::spawn_ipc_tcp_server(ipc_cfg, node.clone(), db_handle);
    let _health_task = health_server::spawn_health_server(node.clone(), None);
    let _config_watcher_task =
        config_engine.spawn_runtime_config_watcher(node.clone(), applied_options);

    tokio::signal::ctrl_c().await?;
    node.stop().await?;
    lp2ln_core_v2::info!("[Main] LP2LN-Demon stopped");
    Ok(())
}
