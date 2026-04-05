use lp2ln_core_v2::db::P2PDatabase;
use lp2ln_core_v2::node::{NodeBuilder, NodeOptions};
use lp2ln_core_v2::transport::{tcp::TcpTransport, udp::UdpTransport};
use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

const DEFAULT_VIRTUAL_PEERS: usize = 10;
const TEMP_DB_DIR: &str = "temp_db";
const TEMP_CONFIGS_DIR: &str = "temp_configs";
const DEFAULT_SCALE_TCP_BASE: u32 = 22_000;
const DEFAULT_SCALE_UDP_BASE: u32 = 24_000;

struct Args {
    options_path: String,
    virtual_peers: usize,
    from: usize,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            options_path: String::new(),
            virtual_peers: DEFAULT_VIRTUAL_PEERS,
            from: 0,
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
        }
        i += 1;
    }
    result
}

fn scale_bind_ip() -> String {
    env::var("LP2LND_SCALE_BIND_IP").unwrap_or_else(|_| "127.0.0.1".to_string())
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
) -> anyhow::Result<PathBuf> {
    let raw = fs::read_to_string(template_path)?;
    let mut v: serde_json::Value = serde_json::from_str(&raw)?;

    let db_dir = format!("{TEMP_DB_DIR}/peer_{peer_idx}");
    let config_peer_dir = format!("{TEMP_CONFIGS_DIR}/peer_{peer_idx}");
    let log_dir = format!("{config_peer_dir}/logs");

    v["database_dir"] = serde_json::Value::String(db_dir.clone());

    let bind_ip = scale_bind_ip();
    if IpAddr::from_str(bind_ip.trim()).is_err() {
        anyhow::bail!(
            "lp2lnd-scale: LP2LND_SCALE_BIND_IP={bind_ip:?} не является валидным IP"
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
        PathBuf::from(&args.options_path)
    } else {
        PathBuf::from("./options.json")
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

    lp2ln_core_v2::info!(
        "[lp2lnd-scale] шаблон {:?}, виртуальных пиров: {} (глобальные индексы {}..{}), БД: {}, конфиги: {}",
        path,
        args.virtual_peers,
        args.from,
        peer_end.saturating_sub(1),
        TEMP_DB_DIR,
        TEMP_CONFIGS_DIR
    );

    let mut nodes = Vec::with_capacity(args.virtual_peers);
    for peer_idx in args.from..peer_end {
        let opts_path = write_peer_options_from_template(&path, peer_idx)?;
        let path_s = opts_path.to_string_lossy().to_string();
        let options = NodeOptions::from_file(&path_s).map_err(|e| {
            anyhow::anyhow!("lp2lnd-scale: не удалось прочитать {}: {}", path_s, e)
        })?;

        let mut builder = NodeBuilder::new()
            .add_transport(Arc::new(TcpTransport::new()))
            .add_transport(Arc::new(UdpTransport::new()));

        if let Some(ref dir) = options.database_dir {
            let dir_s = dir.to_string_lossy();
            match P2PDatabase::new(dir_s.as_ref()) {
                Ok(db) => {
                    builder = builder.db(Arc::new(db));
                    let n_in_run = peer_idx - args.from + 1;
                    lp2ln_core_v2::info!(
                        "[lp2lnd-scale] пир {} ({} / {} в этом запуске): database_dir = {}",
                        peer_idx,
                        n_in_run,
                        args.virtual_peers,
                        dir.display()
                    );
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
        }

        let mut node = builder.build(options)?;
        node.start().await?;
        let n_in_run = peer_idx - args.from + 1;
        lp2ln_core_v2::info!(
            "[lp2lnd-scale] пир {} ({} / {} в этом запуске): {} (конфиг {})",
            peer_idx,
            n_in_run,
            args.virtual_peers,
            node.peer_id(),
            path_s
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
