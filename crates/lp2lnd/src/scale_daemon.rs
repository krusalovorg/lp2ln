use lp2ln_core_v2::db::P2PDatabase;
use lp2ln_core_v2::node::addressing::detect_lan_advertise_ip;
use lp2ln_core_v2::node::options::BootstrapNode;
use lp2ln_core_v2::node::{NodeBuilder, NodeOptions, NodeRuntime};
use lp2ln_core_v2::transport::{tcp::TcpTransport, udp::UdpTransport};
use std::env;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

#[path = "debug_server.rs"]
mod debug_server;

const DEFAULT_VIRTUAL_PEERS: usize = 10;
const TEMP_DB_DIR: &str = "temp_db";
const TEMP_CONFIGS_DIR: &str = "temp_configs";
const DEFAULT_SCALE_TCP_BASE: u32 = 22_000;
const DEFAULT_SCALE_UDP_BASE: u32 = 24_000;
const DEFAULT_SCALE_DEBUG_BASE: u32 = 9_100;

struct Args {
    options_path: String,
    virtual_peers: usize,
    from: usize,
    debug_base: u32,
    debug_enabled: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            options_path: String::new(),
            virtual_peers: DEFAULT_VIRTUAL_PEERS,
            from: 0,
            debug_base: DEFAULT_SCALE_DEBUG_BASE,
            debug_enabled: true,
        }
    }
}

fn parse_args() -> Args {
    let args: Vec<String> = env::args().collect();
    let mut result = Args::default();
    if let Ok(n) = env::var("LP2LND_VIRTUAL_PEERS").map(|s| s.parse().unwrap_or(0)) {
        if n > 0 {
            result.virtual_peers = n;
        }
    }
    if let Ok(s) = env::var("LP2LND_VIRTUAL_PEER_FROM") {
        if let Ok(n) = s.parse::<usize>() {
            result.from = n;
        }
    }
    let mut i = 1;
    while i < args.len() {
        let item = &args[i];
        if item == "-o" || item == "--options" {
            if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                result.options_path = args[i + 1].clone();
                i += 2;
                continue;
            }
        } else if item == "--virtual-peers" || item == "--scale-peers" {
            if i + 1 < args.len() {
                if let Ok(n) = args[i + 1].parse::<usize>() {
                    result.virtual_peers = n.max(1);
                }
                i += 2;
                continue;
            }
        } else if item == "--from" {
            if i + 1 < args.len() {
                if let Ok(n) = args[i + 1].parse::<usize>() {
                    result.from = n;
                }
                i += 2;
                continue;
            }
        } else if item == "--debug-base" || item == "--scale-debug-base" {
            if i + 1 < args.len() {
                if let Ok(n) = args[i + 1].parse::<u32>() {
                    result.debug_base = n.clamp(1, u16::MAX as u32);
                }
                i += 2;
                continue;
            }
        } else if item == "--no-debug" {
            result.debug_enabled = false;
            i += 1;
            continue;
        } else if item == "--debug" {
            result.debug_enabled = true;
            i += 1;
            continue;
        }
        i += 1;
    }
    result
}

/// Ищет шаблон options: как передан, относительно cwd, от корня репозитория
/// (`…/crates/lp2lnd` → два уровня вверх), затем рядом с `Cargo.toml` крейта.
fn resolve_options_template_path(raw: &str) -> PathBuf {
    let p = PathBuf::from(raw);
    if p.is_file() {
        return p;
    }
    if let Ok(cwd) = env::current_dir() {
        let q = cwd.join(raw);
        if q.is_file() {
            return q;
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(repo_root) = manifest_dir.ancestors().nth(2) {
        let q = repo_root.join(raw);
        if q.is_file() {
            return q;
        }
    }
    let q = manifest_dir.join(raw);
    if q.is_file() {
        return q;
    }
    p
}

fn scale_bind_ip(
    bootstrap_targets: &[BootstrapNode],
    default_nodes: &[SocketAddr],
) -> String {
    if let Ok(v) = env::var("LP2LND_SCALE_BIND_IP") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    // Авто-детект LAN-IP: даёт advertise == listen, чтобы p2p-mesh
    // был физически достижим (без этого peers бы биндились на 127.0.0.1,
    // но advertise'или LAN-IP из detect_lan_advertise_ip → ConnectionRefused).
    if let Some(ip) = detect_lan_advertise_ip(bootstrap_targets, default_nodes) {
        return ip.to_string();
    }
    "127.0.0.1".to_string()
}

fn scale_tcp_base_port() -> u32 {
    env::var("LP2LND_SCALE_TCP_BASE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SCALE_TCP_BASE)
}

fn scale_udp_base_port() -> u32 {
    env::var("LP2LND_SCALE_UDP_BASE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SCALE_UDP_BASE)
}

fn write_peer_options_from_template(
    template_path: &Path,
    peer_idx: usize,
    bind_ip: &str,
    debug_enabled: bool,
    debug_base: u32,
) -> anyhow::Result<PathBuf> {
    let raw = fs::read_to_string(template_path)?;
    let mut v: serde_json::Value = serde_json::from_str(&raw)?;

    // Универсальный adaptive-профиль: если в шаблоне нет части полей,
    // дополняем guardrails автоматически (без «магических» фиксированных target).
    let mut topology_defaults = serde_json::Map::new();
    topology_defaults.insert("regular_auto_target_min".into(), serde_json::json!(3));
    topology_defaults.insert("regular_auto_target_max".into(), serde_json::json!(12));
    topology_defaults.insert("regular_bootstrap_min_keep".into(), serde_json::json!(0));
    topology_defaults.insert(
        "regular_bootstrap_rejoin_interval_ms".into(),
        serde_json::json!(30000),
    );
    topology_defaults.insert(
        "regular_exploration_interval_ms".into(),
        serde_json::json!(20000),
    );
    topology_defaults.insert("dial_retry_cooldown_ms".into(), serde_json::json!(45000));
    topology_defaults.insert("prune_redial_cooldown_ms".into(), serde_json::json!(60000));
    topology_defaults.insert("bootstrap_stable_peer_threshold".into(), serde_json::json!(6));
    topology_defaults.insert(
        "avoid_reseed_when_stable_bootstrap".into(),
        serde_json::json!(true),
    );
    topology_defaults.insert("adaptive_topology_enabled".into(), serde_json::json!(true));
    topology_defaults.insert("adaptive_profile".into(), serde_json::json!("balanced"));
    topology_defaults.insert("adaptive_target_min_floor".into(), serde_json::json!(3));
    topology_defaults.insert("adaptive_target_max_ceil".into(), serde_json::json!(14));
    topology_defaults.insert("adaptive_bootstrap_hard_max".into(), serde_json::json!(8));
    topology_defaults.insert("adaptive_bootstrap_top_k".into(), serde_json::json!(2));
    topology_defaults.insert(
        "adaptive_exploration_interval_min_ms".into(),
        serde_json::json!(8000),
    );
    topology_defaults.insert(
        "adaptive_exploration_interval_max_ms".into(),
        serde_json::json!(120000),
    );
    topology_defaults.insert(
        "adaptive_rejoin_cooldown_min_ms".into(),
        serde_json::json!(20000),
    );
    topology_defaults.insert(
        "adaptive_rejoin_cooldown_max_ms".into(),
        serde_json::json!(180000),
    );
    topology_defaults.insert("adaptive_redirect_memory_ms".into(), serde_json::json!(12000));

    if !v.get("topology_tuning").is_some_and(|x| x.is_object()) {
        v["topology_tuning"] = serde_json::Value::Object(serde_json::Map::new());
    }
    if let Some(tt) = v.get_mut("topology_tuning").and_then(|x| x.as_object_mut()) {
        for (k, val) in topology_defaults {
            tt.entry(k).or_insert(val);
        }
    }

    let db_dir = format!("{TEMP_DB_DIR}/peer_{peer_idx}");
    let config_peer_dir = format!("{TEMP_CONFIGS_DIR}/peer_{peer_idx}");
    let log_dir = format!("{config_peer_dir}/logs");

    v["database_dir"] = serde_json::Value::String(db_dir.clone());
    if IpAddr::from_str(bind_ip.trim()).is_err() {
        anyhow::bail!(
            "lp2lnd-scale: bind_ip={bind_ip:?} не является валидным IP"
        );
    }
    let tcp_base = scale_tcp_base_port();
    let udp_base = scale_udp_base_port();
    let idx = peer_idx as u32;
    let tcp_port = tcp_base.checked_add(idx).ok_or_else(|| {
        anyhow::anyhow!("lp2lnd-scale: переполнение порта TCP (peer_idx={peer_idx})")
    })?;
    let udp_port = udp_base.checked_add(idx).ok_or_else(|| {
        anyhow::anyhow!("lp2lnd-scale: переполнение порта UDP (peer_idx={peer_idx})")
    })?;
    if tcp_port > u16::MAX as u32 || udp_port > u16::MAX as u32 {
        anyhow::bail!(
            "lp2lnd-scale: слишком большой peer_idx={peer_idx} для выделения порта (TCP/UDP > 65535)"
        );
    }

    let listens = v
        .get_mut("listens")
        .filter(|x| x.is_object())
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let mut listens_obj = listens
        .as_object()
        .cloned()
        .unwrap_or_default();
    listens_obj.insert(
        "tcp".to_string(),
        serde_json::Value::String(format!("{bind_ip}:{tcp_port}")),
    );
    listens_obj.insert(
        "udp".to_string(),
        serde_json::Value::String(format!("{bind_ip}:{udp_port}")),
    );
    v["listens"] = serde_json::Value::Object(listens_obj);

    if debug_enabled {
        let debug_port = debug_base.checked_add(idx).ok_or_else(|| {
            anyhow::anyhow!("lp2lnd-scale: переполнение порта debug_server (peer_idx={peer_idx})")
        })?;
        if debug_port > u16::MAX as u32 {
            anyhow::bail!(
                "lp2lnd-scale: слишком большой peer_idx={peer_idx} для debug_server (> 65535)"
            );
        }
        let push_ms = v
            .get("debug_server")
            .and_then(|d| d.get("push_interval_ms"))
            .and_then(|x| x.as_u64())
            .unwrap_or(1000);
        v["debug_server"] = serde_json::json!({
            "enabled": true,
            "bind_addr": format!("{bind_ip}:{debug_port}"),
            "push_interval_ms": push_ms
        });
    }

    // Ключ из БД этого пира (как у обычного демона), а не общий из шаблона.
    if let Some(obj) = v.as_object_mut() {
        obj.remove("private_key_hex");
    }

    match v.get_mut("logger_options") {
        Some(serde_json::Value::Object(lo)) => {
            lo.insert(
                "log_dir".to_string(),
                serde_json::Value::String(log_dir.clone()),
            );
        }
        _ => {
            v["logger_options"] = serde_json::json!({
                "log_dir": log_dir,
                "file_enabled": true,
                "show_debug": true,
                "show_info": true,
                "show_warning": true,
                "show_error": true
            });
        }
    }

    let out_dir = PathBuf::from(&config_peer_dir);
    fs::create_dir_all(out_dir.join("logs"))?;
    fs::create_dir_all(PathBuf::from(&db_dir))?;

    let out_path = out_dir.join("options.json");
    fs::write(
        &out_path,
        serde_json::to_string_pretty(&v).map_err(|e| anyhow::anyhow!(e))?,
    )?;
    Ok(out_path)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = parse_args();

    let path = if !args.options_path.is_empty() {
        resolve_options_template_path(&args.options_path)
    } else {
        resolve_options_template_path("./options.json")
    };

    if !path.exists() {
        anyhow::bail!(
            "lp2lnd-scale: укажите существующий конфиг: -o path/to/options.json (не найден {:?})",
            path
        );
    }

    let template = NodeOptions::from_file(&path).map_err(|e| {
        anyhow::anyhow!(
            "lp2lnd-scale: шаблон {:?} должен быть валидным NodeOptions: {}",
            path,
            e
        )
    })?;

    if template.bootstrap_nodes.is_empty() && template.default_nodes.is_empty() {
        anyhow::bail!(
            "lp2lnd-scale: в options нужны bootstrap_nodes или default_nodes"
        );
    }

    let peer_end = args.from.checked_add(args.virtual_peers).ok_or_else(|| {
        anyhow::anyhow!(
            "lp2lnd-scale: переполнение --from + --virtual-peers (слишком большие значения)"
        )
    })?;

    let bootstrap_targets: Vec<BootstrapNode> = if template.bootstrap_nodes.is_empty() {
        template
            .default_nodes
            .iter()
            .copied()
            .map(|addr| BootstrapNode {
                addr,
                protocols: vec!["tcp".to_string(), "udp".to_string()],
                peer_id_hint: template.bootstrap_peer_hints.get(&addr).cloned(),
            })
            .collect()
    } else {
        template.bootstrap_nodes.clone()
    };
    let bind_ip = scale_bind_ip(&bootstrap_targets, &template.default_nodes);

    lp2ln_core_v2::info!(
        "[lp2lnd-scale] шаблон {:?}, виртуальных пиров: {} (глобальные индексы {}..{}), БД: {}, конфиги: {}, bind_ip: {}, debug_ws: {} (base {}, выкл: --no-debug)",
        path,
        args.virtual_peers,
        args.from,
        peer_end.saturating_sub(1),
        TEMP_DB_DIR,
        TEMP_CONFIGS_DIR,
        bind_ip,
        if args.debug_enabled { "on" } else { "off" },
        args.debug_base,
    );

    let mut nodes: Vec<Arc<NodeRuntime>> = Vec::with_capacity(args.virtual_peers);
    for peer_idx in args.from..peer_end {
        let opts_path =
            write_peer_options_from_template(&path, peer_idx, &bind_ip, args.debug_enabled, args.debug_base)?;
        let path_s = opts_path.to_string_lossy().to_string();
        let options = NodeOptions::from_file(&path_s).map_err(|e| {
            anyhow::anyhow!("lp2lnd-scale: не удалось прочитать {}: {}", path_s, e)
        })?;

        let mut builder = NodeBuilder::new()
            .add_transport(Arc::new(TcpTransport::new()))
            .add_transport(Arc::new(UdpTransport::new()));

        let db_for_debug = if let Some(ref dir) = options.database_dir {
            let dir_s = dir.to_string_lossy();
            match P2PDatabase::new(dir_s.as_ref()) {
                Ok(db) => {
                    let db = Arc::new(db);
                    builder = builder.db(db.clone());
                    let n_in_run = peer_idx - args.from + 1;
                    lp2ln_core_v2::info!(
                        "[lp2lnd-scale] пир {} ({} / {} в этом запуске): database_dir = {}",
                        peer_idx,
                        n_in_run,
                        args.virtual_peers,
                        dir.display()
                    );
                    Some(db)
                }
                Err(e) => {
                    anyhow::bail!(
                        "lp2lnd-scale: пир {}: не удалось открыть БД {:?}: {}",
                        peer_idx,
                        dir,
                        e
                    );
                }
            }
        } else {
            anyhow::bail!(
                "lp2lnd-scale: пир {}: в сгенерированном конфиге нет database_dir",
                peer_idx
            );
        };

        let dbg_cfg = options.debug_server.clone();
        let mut node = builder.build(options)?;
        node.start().await?;
        let node = Arc::new(node);

        let _debug_server_task = debug_server::spawn_debug_server(
            debug_server::DebugServerConfig {
                enabled: dbg_cfg.enabled,
                bind_addr: dbg_cfg.bind_addr,
                push_interval_ms: dbg_cfg.push_interval_ms,
            },
            node.clone(),
            db_for_debug,
        );

        let n_in_run = peer_idx - args.from + 1;
        let debug_ws_note = if args.debug_enabled {
            match args.debug_base.checked_add(peer_idx as u32) {
                Some(port) => format!(", debug_ws=ws://{bind_ip}:{port}"),
                None => String::new(),
            }
        } else {
            String::new()
        };
        lp2ln_core_v2::info!(
            "[lp2lnd-scale] пир {} ({} / {} в этом запуске): {} (конфиг {}){}",
            peer_idx,
            n_in_run,
            args.virtual_peers,
            node.peer_id(),
            path_s,
            debug_ws_note
        );
        nodes.push(node);
    }

    lp2ln_core_v2::info!(
        "[lp2lnd-scale] все {} пиров запущены, Ctrl+C для остановки",
        args.virtual_peers
    );

    tokio::signal::ctrl_c().await?;
    for node in &nodes {
        let _ = node.stop().await;
    }
    lp2ln_core_v2::info!("[lp2lnd-scale] остановлено");
    Ok(())
}
