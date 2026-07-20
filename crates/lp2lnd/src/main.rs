use core::fmt;
mod app_plane_server;
mod app_plane_streams;
mod debug_server;
mod ipc_tcp;
use lp2ln_core_v2::db::P2PDatabase;
use lp2ln_core_v2::logger::LoggerOptions;
use lp2ln_core_v2::logger::info;
use lp2ln_core_v2::node::{
    ConfigAutonomy, NodeBuilder, NodeOptions, StartupConfigSource, check_file, health_server,
    migrate_file, public_example_json,
};
use lp2ln_core_v2::peer_score::PeerConnectionPolicy;
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
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

fn resolve_options_path(cli: &str) -> Option<String> {
    if !cli.is_empty() {
        return Some(cli.to_string());
    }
    let default_path = PathBuf::from("./options.json");
    if default_path.exists() {
        Some(default_path.to_string_lossy().to_string())
    } else {
        None
    }
}

fn run_config_cli(args: &[String]) -> ExitCode {
    let sub = args.get(2).map(String::as_str).unwrap_or("help");
    let mut options_path = String::new();
    for (i, item) in args.iter().enumerate() {
        if i == 0 {
            continue;
        }
        let prev = &args[i - 1];
        if (prev == "-o" || prev == "--options") && !item.starts_with('-') {
            options_path = item.clone();
        }
    }

    match sub {
        "example" => {
            println!("{}", public_example_json());
            ExitCode::SUCCESS
        }
        "check" => {
            let Some(path) = resolve_options_path(&options_path) else {
                eprintln!("config check: pass -o <path> or create ./options.json");
                return ExitCode::from(2);
            };
            match check_file(&path) {
                Ok(report) => {
                    println!("{}", report.exit_message());
                    if report.validation.is_strict_ok() {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(1)
                    }
                }
                Err(e) => {
                    eprintln!("config check failed: {e}");
                    ExitCode::from(2)
                }
            }
        }
        "migrate" => {
            let Some(path) = resolve_options_path(&options_path) else {
                eprintln!("config migrate: pass -o <path> or create ./options.json");
                return ExitCode::from(2);
            };
            match migrate_file(&path) {
                Ok(_) => {
                    println!("migrated {path} to schema_version=2");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("config migrate failed: {e}");
                    ExitCode::from(2)
                }
            }
        }
        "help" | "-h" | "--help" => {
            eprintln!(
                "Usage:\n  lp2lnd config example\n  lp2lnd config check [-o path]\n  lp2lnd config migrate [-o path]"
            );
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown config subcommand '{other}'");
            eprintln!(
                "Usage:\n  lp2lnd config example\n  lp2lnd config check [-o path]\n  lp2lnd config migrate [-o path]"
            );
            ExitCode::from(2)
        }
    }
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

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();
    if argv.get(1).map(String::as_str) == Some("config") {
        return run_config_cli(&argv);
    }

    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(run_daemon())
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lp2lnd error: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn run_daemon() -> anyhow::Result<()> {
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
    let options_path = resolve_options_path(&args.options_path);

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
    lp2ln_core_v2::info!(
        "[Main] config schema_version={} topology_profile={:?}",
        options.schema_version,
        options.topology_profile
    );

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
    let ipc_cfg = ipc_tcp::IpcTcpServerConfig::from(&options.ipc_tcp)
        .with_experimental_content(options.experimental.content);
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
            experimental_content: options.experimental.content,
        },
        node.clone(),
        db_handle.clone(),
    );
    let _ipc_tcp_task = ipc_tcp::spawn_ipc_tcp_server(ipc_cfg, node.clone(), db_handle);
    let _health_task = health_server::spawn_health_server(node.clone(), None);
    let _config_watcher_task =
        config_engine.spawn_runtime_config_watcher(node.clone(), applied_options);

    lp2ln_core_v2::info!(
        "[Main] experimental flags: dht={} content={} repair={} app_plane={}",
        options.experimental.dht,
        options.experimental.content,
        options.experimental.repair,
        options.experimental.app_plane
    );
    if options.experimental.any_enabled() {
        lp2ln_core_v2::warn!(
            "[Main] experimental.* enabled — DHT/content/repair are skeletons until P4; \
             App Plane local IPC starts when experimental.app_plane=true"
        );
    }
    if options.experimental.dht || options.experimental.repair {
        lp2ln_core_v2::warn!(
            "[Main] experimental.dht/repair are opt-in flags only; \
             lp2lnd does not start those background services yet"
        );
    }

    let _app_plane_task = if options.experimental.app_plane {
        match node.router() {
            Some(router) => {
                let cfg = app_plane_server::AppPlaneServerConfig::from_options(
                    true,
                    &options.app_plane_ipc,
                );
                lp2ln_core_v2::info!(
                    "[Main] App Plane IPC enabled: path={} dev_tcp={:?}",
                    cfg.path,
                    cfg.dev_tcp_bind
                );
                Some(app_plane_server::spawn_app_plane_server(
                    cfg,
                    node.clone(),
                    router,
                ))
            }
            None => {
                lp2ln_core_v2::error!(
                    "[Main] experimental.app_plane set but router missing; IPC not started"
                );
                None
            }
        }
    } else {
        None
    };

    tokio::signal::ctrl_c().await?;
    node.stop().await?;
    lp2ln_core_v2::info!("[Main] LP2LN-Demon stopped");
    Ok(())
}
