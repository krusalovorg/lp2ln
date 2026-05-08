use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use lp2ln_core_v2::db::P2PDatabase;
use lp2ln_core_v2::node::NodeRuntime;
use lp2ln_core_v2::peer_score::total_score;
use lp2ln_core_v2::types::{PeerId, SessionId};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::MissedTickBehavior;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug, Clone)]
pub struct DebugServerConfig {
    pub enabled: bool,
    pub bind_addr: String,
    pub push_interval_ms: u64,
}

pub fn spawn_debug_server(
    cfg: DebugServerConfig,
    node: Arc<NodeRuntime>,
    db: Option<Arc<P2PDatabase>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if !cfg.enabled {
            return;
        }
        let bind_addr: SocketAddr = match cfg.bind_addr.parse() {
            Ok(v) => v,
            Err(e) => {
                lp2ln_core_v2::error!("[DebugServer] invalid bind_addr '{}': {}", cfg.bind_addr, e);
                return;
            }
        };

        let listener = match TcpListener::bind(bind_addr).await {
            Ok(v) => v,
            Err(e) => {
                lp2ln_core_v2::error!("[DebugServer] bind {} failed: {}", bind_addr, e);
                return;
            }
        };

        lp2ln_core_v2::info!(
            "[DebugServer] listening on ws://{} (push_interval_ms={})",
            bind_addr,
            cfg.push_interval_ms
        );

        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let node = node.clone();
                    let db = db.clone();
                    let push_interval_ms = cfg.push_interval_ms.max(250);
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_ws_client(stream, peer, node, db, push_interval_ms).await
                        {
                            lp2ln_core_v2::warn!("[DebugServer] client {} dropped: {}", peer, e);
                        }
                    });
                }
                Err(e) => {
                    lp2ln_core_v2::warn!("[DebugServer] accept failed: {}", e);
                }
            }
        }
    })
}

async fn handle_ws_client(
    stream: TcpStream,
    peer: SocketAddr,
    node: Arc<NodeRuntime>,
    db: Option<Arc<P2PDatabase>>,
    push_interval_ms: u64,
) -> anyhow::Result<()> {
    let ws = accept_async(stream).await?;
    let (mut ws_tx, mut ws_rx) = ws.split();
    lp2ln_core_v2::info!("[DebugServer] ws connected: {}", peer);

    let hello = json!({
        "event": "hello",
        "ts_ms": now_ms(),
        "peer_id": node.peer_id(),
        "push_interval_ms": push_interval_ms,
        "commands": [
            "get_db_tables",
            "connect_peer",
            "disconnect_peer",
            "close_session",
            "send_to_peer",
            "send_packet",
            "send_to_session",
            "get_peer_rankings",
            "get_peer_rollup",
            "set_peer_connection_policy",
            "get_file_by_hash",
            "remove_file",
            "register_known_peer_addr",
            "connect_batch",
            "disconnect_peer_batch",
            "refresh_snapshot",
            "stop_node",
        ],
    });
    ws_tx.send(Message::Text(hello.to_string())).await?;

    let mut interval = tokio::time::interval(Duration::from_millis(push_interval_ms));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let snapshot = collect_snapshot(node.clone(), db.clone()).await;
                ws_tx.send(Message::Text(snapshot.to_string())).await?;
            }
            maybe_msg = ws_rx.next() => {
                let Some(msg) = maybe_msg else {
                    break;
                };
                let msg = msg?;
                match msg {
                    Message::Text(text) => {
                        if let Some(reply) = handle_client_command(&text, node.clone(), db.clone()).await {
                            ws_tx.send(Message::Text(reply.to_string())).await?;
                        }
                    }
                    Message::Close(_) => break,
                    Message::Ping(payload) => {
                        ws_tx.send(Message::Pong(payload)).await?;
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

async fn handle_client_command(
    text: &str,
    node: Arc<NodeRuntime>,
    db: Option<Arc<P2PDatabase>>,
) -> Option<Value> {
    let value: Value = serde_json::from_str(text).ok()?;
    let cmd = value.get("cmd")?.as_str()?;
    match cmd {
        "get_db_tables" => Some(collect_db_tables(db).await),
        "connect_peer" => {
            let transport = value
                .get("transport")
                .and_then(|v| v.as_str())
                .unwrap_or("tcp");
            let addr = value
                .get("addr")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let parsed = addr.parse::<SocketAddr>();
            match parsed {
                Ok(addr) => match node.connect(transport, addr).await {
                    Ok(session_id) => Some(json!({
                        "event": "command_result",
                        "ts_ms": now_ms(),
                        "ok": true,
                        "cmd": cmd,
                        "session_id": session_id.to_string(),
                    })),
                    Err(e) => Some(json!({
                        "event": "command_result",
                        "ts_ms": now_ms(),
                        "ok": false,
                        "cmd": cmd,
                        "error": e.to_string(),
                    })),
                },
                Err(e) => Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": false,
                    "cmd": cmd,
                    "error": format!("invalid addr '{}': {}", addr, e),
                })),
            }
        }
        "disconnect_peer" => {
            let peer_id = value
                .get("peer_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if peer_id.is_empty() {
                return Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": false,
                    "cmd": cmd,
                    "error": "peer_id is required",
                }));
            }
            match node.disconnect_peer(peer_id).await {
                Ok(_) => Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": true,
                    "cmd": cmd,
                    "peer_id": peer_id,
                })),
                Err(e) => Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": false,
                    "cmd": cmd,
                    "peer_id": peer_id,
                    "error": e.to_string(),
                })),
            }
        }
        "close_session" => {
            let session_id = value
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if session_id.is_empty() {
                return Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": false,
                    "cmd": cmd,
                    "error": "session_id is required",
                }));
            }
            match node.disconnect_session(session_id).await {
                Ok(_) => Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": true,
                    "cmd": cmd,
                    "session_id": session_id,
                })),
                Err(e) => Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": false,
                    "cmd": cmd,
                    "session_id": session_id,
                    "error": e.to_string(),
                })),
            }
        }
        "send_to_peer" => {
            let peer_id = value
                .get("peer_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if peer_id.is_empty() {
                return Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": false,
                    "cmd": cmd,
                    "error": "peer_id is required",
                }));
            }
            let data = value
                .get("data")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let encoding = value
                .get("encoding")
                .and_then(|v| v.as_str())
                .unwrap_or("utf8");
            let bytes = payload_to_bytes(data, encoding);
            match bytes {
                Ok(bytes) => match node.send(PeerId::from(peer_id), bytes).await {
                    Ok(request_id) => Some(json!({
                        "event": "command_result",
                        "ts_ms": now_ms(),
                        "ok": true,
                        "cmd": cmd,
                        "peer_id": peer_id,
                        "encoding": encoding,
                        "request_id": request_id,
                    })),
                    Err(e) => Some(json!({
                        "event": "command_result",
                        "ts_ms": now_ms(),
                        "ok": false,
                        "cmd": cmd,
                        "peer_id": peer_id,
                        "error": e.to_string(),
                    })),
                },
                Err(e) => Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": false,
                    "cmd": cmd,
                    "peer_id": peer_id,
                    "error": e,
                })),
            }
        }
        "send_packet" => {
            let peer_id = value
                .get("peer_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if peer_id.is_empty() {
                return Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": false,
                    "cmd": cmd,
                    "error": "peer_id is required",
                }));
            }
            let data = value
                .get("data")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let encoding = value
                .get("encoding")
                .and_then(|v| v.as_str())
                .unwrap_or("utf8");
            let wait_reply = value
                .get("wait_reply")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let timeout_ms = value
                .get("timeout_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(10_000)
                .clamp(100, 300_000);
            let max_hops = value
                .get("max_hops")
                .and_then(|v| v.as_u64())
                .map(|v| v.min(u8::MAX as u64) as u8);
            let receiver = value
                .get("receiver")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let bytes = payload_to_bytes(data, encoding);
            match bytes {
                Ok(bytes) => {
                    let route = PeerId::from(peer_id);
                    if wait_reply {
                        match node
                            .send_with_options_and_wait_reply(
                                route,
                                bytes,
                                receiver,
                                max_hops,
                                None,
                                Duration::from_millis(timeout_ms),
                            )
                            .await
                        {
                            Ok((request_id, reply)) => {
                                let b64 = STANDARD.encode(&reply);
                                let reply_text =
                                    std::str::from_utf8(&reply).ok().map(|s| s.to_string());
                                Some(json!({
                                    "event": "command_result",
                                    "ts_ms": now_ms(),
                                    "ok": true,
                                    "cmd": cmd,
                                    "peer_id": peer_id,
                                    "encoding": encoding,
                                    "request_id": request_id,
                                    "wait_reply": true,
                                    "reply_base64": b64,
                                    "reply_text": reply_text,
                                }))
                            }
                            Err(e) => Some(json!({
                                "event": "command_result",
                                "ts_ms": now_ms(),
                                "ok": false,
                                "cmd": cmd,
                                "peer_id": peer_id,
                                "wait_reply": true,
                                "error": e.to_string(),
                            })),
                        }
                    } else {
                        match node
                            .send_with_options(route, bytes, receiver, max_hops, None)
                            .await
                        {
                            Ok(request_id) => Some(json!({
                                "event": "command_result",
                                "ts_ms": now_ms(),
                                "ok": true,
                                "cmd": cmd,
                                "peer_id": peer_id,
                                "encoding": encoding,
                                "request_id": request_id,
                                "wait_reply": false,
                            })),
                            Err(e) => Some(json!({
                                "event": "command_result",
                                "ts_ms": now_ms(),
                                "ok": false,
                                "cmd": cmd,
                                "peer_id": peer_id,
                                "error": e.to_string(),
                            })),
                        }
                    }
                }
                Err(e) => Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": false,
                    "cmd": cmd,
                    "peer_id": peer_id,
                    "error": e,
                })),
            }
        }
        "send_to_session" => {
            let session_id = value
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if session_id.is_empty() {
                return Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": false,
                    "cmd": cmd,
                    "error": "session_id is required",
                }));
            }
            let data = value
                .get("data")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let encoding = value
                .get("encoding")
                .and_then(|v| v.as_str())
                .unwrap_or("utf8");
            let bytes = payload_to_bytes(data, encoding);
            match bytes {
                Ok(bytes) => match node
                    .send_to_session(SessionId::from(session_id), bytes)
                    .await
                {
                    Ok(_) => Some(json!({
                        "event": "command_result",
                        "ts_ms": now_ms(),
                        "ok": true,
                        "cmd": cmd,
                        "session_id": session_id,
                        "encoding": encoding,
                    })),
                    Err(e) => Some(json!({
                        "event": "command_result",
                        "ts_ms": now_ms(),
                        "ok": false,
                        "cmd": cmd,
                        "session_id": session_id,
                        "error": e.to_string(),
                    })),
                },
                Err(e) => Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": false,
                    "cmd": cmd,
                    "session_id": session_id,
                    "error": e,
                })),
            }
        }
        "get_peer_rankings" => Some(collect_peer_rankings(node.clone()).await),
        "get_peer_rollup" => Some(collect_peer_rollup(node.clone()).await),
        "set_peer_connection_policy" => {
            let mut cur = node.peer_connection_policy();
            if let Some(v) = value.get("min_active_peers").and_then(|x| x.as_u64()) {
                cur.min_active_peers = v as usize;
            }
            if let Some(v) = value.get("target_active_peers").and_then(|x| x.as_u64()) {
                cur.target_active_peers = v as usize;
            }
            if let Some(v) = value.get("max_active_peers").and_then(|x| x.as_u64()) {
                cur.max_active_peers = v as usize;
            }
            let base = node.set_peer_connection_policy(cur);
            let eff = node.effective_peer_connection_policy();
            Some(json!({
                "event": "command_result",
                "ts_ms": now_ms(),
                "ok": true,
                "cmd": cmd,
                "policy_base": {
                    "min_active_peers": base.min_active_peers,
                    "target_active_peers": base.target_active_peers,
                    "max_active_peers": base.max_active_peers,
                },
                "policy_effective": {
                    "min_active_peers": eff.min_active_peers,
                    "target_active_peers": eff.target_active_peers,
                    "max_active_peers": eff.max_active_peers,
                },
            }))
        }
        "get_file_by_hash" => {
            let file_hash = value
                .get("file_hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .trim()
                .to_string();
            if file_hash.is_empty() {
                return Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": false,
                    "cmd": cmd,
                    "error": "file_hash is required",
                }));
            }
            Some(get_file_by_hash(db, &file_hash).await)
        }
        "remove_file" => {
            let file_hash = value
                .get("file_hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .trim()
                .to_string();
            if file_hash.is_empty() {
                return Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": false,
                    "cmd": cmd,
                    "error": "file_hash is required",
                }));
            }
            Some(remove_file_by_hash(db, &file_hash).await)
        }
        "register_known_peer_addr" => {
            let peer_id = value
                .get("peer_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .trim()
                .to_string();
            let transport = value
                .get("transport")
                .and_then(|v| v.as_str())
                .unwrap_or("tcp")
                .trim()
                .to_string();
            let addr_s = value
                .get("addr")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .trim()
                .to_string();
            if peer_id.is_empty() || addr_s.is_empty() {
                return Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": false,
                    "cmd": cmd,
                    "error": "peer_id and addr are required",
                }));
            }
            match addr_s.parse::<SocketAddr>() {
                Ok(addr) => {
                    node.register_known_peer_addr(
                        PeerId::from(peer_id.as_str()),
                        transport.clone(),
                        addr,
                    );
                    Some(json!({
                        "event": "command_result",
                        "ts_ms": now_ms(),
                        "ok": true,
                        "cmd": cmd,
                        "peer_id": peer_id,
                        "transport": transport,
                        "addr": addr_s,
                    }))
                }
                Err(e) => Some(json!({
                    "event": "command_result",
                    "ts_ms": now_ms(),
                    "ok": false,
                    "cmd": cmd,
                    "error": format!("invalid addr '{}': {}", addr_s, e),
                })),
            }
        }
        "connect_batch" => Some(connect_batch(node, &value).await),
        "disconnect_peer_batch" => Some(disconnect_peer_batch(node, &value).await),
        "refresh_snapshot" => Some(collect_snapshot(node.clone(), db.clone()).await),
        "stop_node" => match node.stop().await {
            Ok(_) => Some(json!({
                "event": "command_result",
                "ts_ms": now_ms(),
                "ok": true,
                "cmd": cmd,
            })),
            Err(e) => Some(json!({
                "event": "command_result",
                "ts_ms": now_ms(),
                "ok": false,
                "cmd": cmd,
                "error": e.to_string(),
            })),
        },
        _ => Some(json!({
            "event": "error",
            "ts_ms": now_ms(),
            "message": format!("unknown command: {}", cmd),
        })),
    }
}

async fn connect_batch(node: Arc<NodeRuntime>, value: &Value) -> Value {
    let transport = value
        .get("transport")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp")
        .trim()
        .to_string();
    let addrs = value
        .get("addrs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if addrs.is_empty() {
        return json!({
            "event": "command_result",
            "ts_ms": now_ms(),
            "ok": false,
            "cmd": "connect_batch",
            "error": "addrs[] is required",
        });
    }
    let mut ok = 0usize;
    let mut fail = 0usize;
    let mut rows = Vec::with_capacity(addrs.len());
    for v in addrs {
        let s = v.as_str().unwrap_or_default().trim().to_string();
        if s.is_empty() {
            fail += 1;
            rows.push(json!({"addr": s, "ok": false, "error": "empty addr"}));
            continue;
        }
        match s.parse::<SocketAddr>() {
            Ok(addr) => match node.connect(&transport, addr).await {
                Ok(session_id) => {
                    ok += 1;
                    rows.push(json!({"addr": s, "ok": true, "session_id": session_id.to_string()}));
                }
                Err(e) => {
                    fail += 1;
                    rows.push(json!({"addr": s, "ok": false, "error": e.to_string()}));
                }
            },
            Err(e) => {
                fail += 1;
                rows.push(json!({"addr": s, "ok": false, "error": e.to_string()}));
            }
        }
    }
    json!({
        "event": "command_result",
        "ts_ms": now_ms(),
        "ok": fail == 0,
        "cmd": "connect_batch",
        "transport": transport,
        "ok_count": ok,
        "fail_count": fail,
        "rows": rows,
    })
}

async fn disconnect_peer_batch(node: Arc<NodeRuntime>, value: &Value) -> Value {
    let peers = value
        .get("peer_ids")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if peers.is_empty() {
        return json!({
            "event": "command_result",
            "ts_ms": now_ms(),
            "ok": false,
            "cmd": "disconnect_peer_batch",
            "error": "peer_ids[] is required",
        });
    }
    let mut ok = 0usize;
    let mut fail = 0usize;
    let mut rows = Vec::with_capacity(peers.len());
    for v in peers {
        let peer_id = v.as_str().unwrap_or_default().trim().to_string();
        if peer_id.is_empty() {
            fail += 1;
            rows.push(json!({"peer_id": peer_id, "ok": false, "error": "empty peer_id"}));
            continue;
        }
        match node.disconnect_peer(&peer_id).await {
            Ok(_) => {
                ok += 1;
                rows.push(json!({"peer_id": peer_id, "ok": true}));
            }
            Err(e) => {
                fail += 1;
                rows.push(json!({"peer_id": peer_id, "ok": false, "error": e.to_string()}));
            }
        }
    }
    json!({
        "event": "command_result",
        "ts_ms": now_ms(),
        "ok": fail == 0,
        "cmd": "disconnect_peer_batch",
        "ok_count": ok,
        "fail_count": fail,
        "rows": rows,
    })
}

async fn collect_peer_rankings(node: Arc<NodeRuntime>) -> Value {
    let weights = node.peer_score_weights().clone();
    let scores = node.peer_score_store().snapshot();
    let mut rows = scores
        .into_iter()
        .map(|(peer_id, score)| {
            let total = total_score(&score, &weights);
            json!({
                "peer_id": peer_id.as_str(),
                "total_score": total,
                "latency_ms": score.latency_ms,
                "success_rate": score.success_rate,
                "uptime_score": score.uptime_score,
                "bandwidth_score": score.bandwidth_score,
                "relay_score": score.relay_score,
                "trust_score": score.trust_score,
                "geo_score": score.geo_score,
                "nat_compat_score": score.nat_compat_score,
                "load_penalty": score.load_penalty,
            })
        })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        let av = a
            .get("total_score")
            .and_then(|v| v.as_f64())
            .unwrap_or(f64::MIN);
        let bv = b
            .get("total_score")
            .and_then(|v| v.as_f64())
            .unwrap_or(f64::MIN);
        bv.partial_cmp(&av).unwrap_or(std::cmp::Ordering::Equal)
    });
    json!({
        "event": "peer_rankings",
        "ts_ms": now_ms(),
        "rows": rows,
    })
}

async fn collect_peer_rollup(node: Arc<NodeRuntime>) -> Value {
    let mut by_peer: std::collections::BTreeMap<String, (u64, u64, u64, u64, u64, u64, usize)> =
        std::collections::BTreeMap::new();
    for s in node.debug_sessions() {
        let peer = s.peer_id.unwrap_or_else(|| "unknown".to_string());
        let e = by_peer.entry(peer).or_insert((0, 0, 0, 0, 0, 0, 0));
        e.0 += s.packets_sent;
        e.1 += s.packets_received;
        e.2 += s.bytes_sent;
        e.3 += s.bytes_received;
        e.4 += s.send_errors;
        e.5 += s.receive_errors;
        e.6 += 1;
    }
    let rows: Vec<Value> = by_peer
        .into_iter()
        .map(
            |(
                peer_id,
                (
                    packets_sent,
                    packets_received,
                    bytes_sent,
                    bytes_received,
                    send_errors,
                    receive_errors,
                    sessions,
                ),
            )| {
                json!({
                    "peer_id": peer_id,
                    "sessions": sessions,
                    "packets_sent": packets_sent,
                    "packets_received": packets_received,
                    "bytes_sent": bytes_sent,
                    "bytes_received": bytes_received,
                    "send_errors": send_errors,
                    "receive_errors": receive_errors,
                })
            },
        )
        .collect();
    json!({
        "event": "peer_rollup",
        "ts_ms": now_ms(),
        "rows": rows,
    })
}

async fn get_file_by_hash(db: Option<Arc<P2PDatabase>>, file_hash: &str) -> Value {
    let Some(db) = db else {
        return json!({
            "event": "file_lookup",
            "ts_ms": now_ms(),
            "ok": false,
            "error": "database is disabled",
        });
    };
    let hash = file_hash.to_string();
    let result = tokio::task::spawn_blocking(move || db.get_file_by_hash(&hash))
        .await
        .ok()
        .and_then(|r| r.ok());
    match result {
        Some(Some(file)) => json!({
            "event": "file_lookup",
            "ts_ms": now_ms(),
            "ok": true,
            "found": true,
            "file": {
                "file_hash": file.file_hash,
                "size": file.size,
                "storage_peer_key": file.storage_peer_key,
                "fragment_count": file.fragment_hashes.len(),
                "fragment_hashes": file.fragment_hashes,
            }
        }),
        Some(None) => json!({
            "event": "file_lookup",
            "ts_ms": now_ms(),
            "ok": true,
            "found": false,
        }),
        None => json!({
            "event": "file_lookup",
            "ts_ms": now_ms(),
            "ok": false,
            "error": "db query failed",
        }),
    }
}

async fn remove_file_by_hash(db: Option<Arc<P2PDatabase>>, file_hash: &str) -> Value {
    let Some(db) = db else {
        return json!({
            "event": "command_result",
            "ts_ms": now_ms(),
            "ok": false,
            "cmd": "remove_file",
            "error": "database is disabled",
        });
    };
    let hash = file_hash.to_string();
    let result = tokio::task::spawn_blocking(move || db.remove_file(&hash)).await;
    match result {
        Ok(Ok(())) => json!({
            "event": "command_result",
            "ts_ms": now_ms(),
            "ok": true,
            "cmd": "remove_file",
            "file_hash": file_hash,
        }),
        Ok(Err(e)) => json!({
            "event": "command_result",
            "ts_ms": now_ms(),
            "ok": false,
            "cmd": "remove_file",
            "file_hash": file_hash,
            "error": e.to_string(),
        }),
        Err(e) => json!({
            "event": "command_result",
            "ts_ms": now_ms(),
            "ok": false,
            "cmd": "remove_file",
            "file_hash": file_hash,
            "error": e.to_string(),
        }),
    }
}

fn payload_to_bytes(data: &str, encoding: &str) -> Result<Vec<u8>, String> {
    match encoding.to_lowercase().as_str() {
        "utf8" | "text" => Ok(data.as_bytes().to_vec()),
        "hex" => decode_hex(data),
        "base64" => STANDARD
            .decode(data.trim())
            .map_err(|e| format!("invalid base64: {e}")),
        other => Err(format!(
            "unsupported encoding '{}', use utf8|hex|base64",
            other
        )),
    }
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let mut clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() >= 2 && (clean.starts_with("0x") || clean.starts_with("0X")) {
        clean = clean[2..].to_string();
    }
    if clean.is_empty() {
        return Ok(vec![]);
    }
    if clean.len() % 2 != 0 {
        return Err("hex payload length must be even".to_string());
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    let bytes = clean.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let pair = std::str::from_utf8(&bytes[i..i + 2]).map_err(|_| "invalid hex utf8")?;
        let b = u8::from_str_radix(pair, 16).map_err(|_| format!("invalid hex byte '{}'", pair))?;
        out.push(b);
        i += 2;
    }
    Ok(out)
}

async fn collect_snapshot(node: Arc<NodeRuntime>, db: Option<Arc<P2PDatabase>>) -> Value {
    let peer_catalog = node.peer_catalog();
    let descriptors = peer_catalog.descriptors();
    let known_peers = peer_catalog.known_peer_ids().len();
    let active_peers = node.active_peer_count();
    let role = format!("{:?}", node.node_role());
    let policy = node.effective_peer_connection_policy();
    let weights = node.peer_score_weights().clone();

    let by_protocol = node
        .get_metrics_by_protocol()
        .into_iter()
        .map(|(kind, rows)| {
            let sessions = rows.len();
            let bytes_sent: u64 = rows.iter().map(|m| m.bytes_sent).sum();
            let bytes_received: u64 = rows.iter().map(|m| m.bytes_received).sum();
            let packets_sent: u64 = rows.iter().map(|m| m.packets_sent).sum();
            let packets_received: u64 = rows.iter().map(|m| m.packets_received).sum();
            let send_errors: u64 = rows.iter().map(|m| m.send_errors).sum();
            let receive_errors: u64 = rows.iter().map(|m| m.receive_errors).sum();
            json!({
                "kind": kind.to_string(),
                "sessions": sessions,
                "packets_sent": packets_sent,
                "packets_received": packets_received,
                "bytes_sent": bytes_sent,
                "bytes_received": bytes_received,
                "send_errors": send_errors,
                "receive_errors": receive_errors,
            })
        })
        .collect::<Vec<_>>();

    let db_json = collect_db_metrics(db).await;

    let sessions = node
        .debug_sessions()
        .into_iter()
        .map(|s| {
            json!({
                "session_id": s.session_id,
                "peer_id": s.peer_id,
                "protocol": s.protocol,
                "is_active": s.is_active,
                "packets_sent": s.packets_sent,
                "packets_received": s.packets_received,
                "bytes_sent": s.bytes_sent,
                "bytes_received": s.bytes_received,
                "send_errors": s.send_errors,
                "receive_errors": s.receive_errors,
                "reconnections": s.reconnections,
                "uptime_secs": s.uptime_secs,
                "last_activity_secs_ago": s.last_activity_secs_ago,
            })
        })
        .collect::<Vec<_>>();
    let connected: std::collections::HashSet<String> = node
        .connected_peers()
        .into_iter()
        .map(|p| p.as_str().to_string())
        .collect();
    let neighbors = descriptors
        .iter()
        .map(|d| {
            json!({
                "peer_id": d.peer_id,
                "observed_addrs": d.observed_addrs,
                "active_connections": d.dynamic_status.active_connections,
                "accepts_new_sessions": d.dynamic_status.accepts_new_sessions,
                "bootstrap_entry": d.capabilities.bootstrap_entry,
                "is_connected": connected.contains(&d.peer_id),
            })
        })
        .collect::<Vec<_>>();
    let edges = neighbors
        .iter()
        .map(|n| {
            let peer_id = n
                .get("peer_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let is_connected = n
                .get("is_connected")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            json!({
                "source": node.peer_id(),
                "target": peer_id,
                "connected": is_connected,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "event": "snapshot",
        "ts_ms": now_ms(),
        "node": {
            "peer_id": node.peer_id(),
            "role": role,
            "active_peers": active_peers,
            "known_peers": known_peers,
            "descriptor_count": descriptors.len(),
            "policy": {
                "min_active_peers": policy.min_active_peers,
                "target_active_peers": policy.target_active_peers,
                "max_active_peers": policy.max_active_peers,
            },
            "score_weights": {
                "w_uptime": weights.w_uptime,
                "w_success": weights.w_success,
                "w_bandwidth": weights.w_bandwidth,
                "w_relay": weights.w_relay,
                "w_nat": weights.w_nat,
                "w_trust": weights.w_trust,
                "w_geo": weights.w_geo,
                "w_load": weights.w_load,
                "w_latency": weights.w_latency,
                "latency_norm_ms": weights.latency_norm_ms,
            },
        },
        "sessions_by_protocol": by_protocol,
        "sessions": sessions,
        "topology": {
            "self_peer_id": node.peer_id(),
            "neighbors": neighbors,
            "edges": edges,
        },
        "db": db_json,
    })
}

async fn collect_db_metrics(db: Option<Arc<P2PDatabase>>) -> Value {
    let Some(db) = db else {
        return json!({
            "enabled": false,
        });
    };

    let path = db.path.clone();
    let db_file_size = std::fs::metadata(format!("{}/db", path))
        .map(|m| m.len())
        .ok()
        .unwrap_or(0);

    let blobs_size = db.get_storage_size().await.ok().unwrap_or(0);

    let db_for_files = db.clone();
    let files_count =
        tokio::task::spawn_blocking(move || db_for_files.get_all_files().map(|v| v.len()))
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or(0);

    let db_for_desc = db.clone();
    let descriptor_count =
        tokio::task::spawn_blocking(move || db_for_desc.load_peer_descriptors().map(|v| v.len()))
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or(0);

    let db_for_scores = db.clone();
    let peer_score_count = tokio::task::spawn_blocking(move || {
        db_for_scores.load_peer_score_snapshot().map(|v| v.len())
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or(0);

    json!({
        "enabled": true,
        "path": path,
        "db_file_bytes": db_file_size,
        "blobs_bytes": blobs_size,
        "stored_files_count": files_count,
        "cached_descriptors_count": descriptor_count,
        "cached_peer_scores_count": peer_score_count,
    })
}

async fn collect_db_tables(db: Option<Arc<P2PDatabase>>) -> Value {
    let Some(db) = db else {
        return json!({
            "event": "db_tables",
            "ts_ms": now_ms(),
            "db": { "enabled": false },
            "tables": {},
        });
    };

    let db_for_files = db.clone();
    let files = tokio::task::spawn_blocking(move || db_for_files.get_all_files())
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();

    let db_for_desc = db.clone();
    let descriptors = tokio::task::spawn_blocking(move || db_for_desc.load_peer_descriptors())
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();

    let db_for_scores = db.clone();
    let scores = tokio::task::spawn_blocking(move || db_for_scores.load_peer_score_snapshot())
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();

    let files_json: Vec<Value> = files
        .into_iter()
        .map(|f| {
            json!({
                "file_hash": f.file_hash,
                "size": f.size,
                "storage_peer_key": f.storage_peer_key,
                "fragment_count": f.fragment_hashes.len(),
                "fragment_hashes": f.fragment_hashes,
            })
        })
        .collect();
    let descriptors_json: Vec<Value> = descriptors
        .into_iter()
        .map(|d| {
            json!({
                "peer_id": d.peer_id,
                "version": d.version,
                "ttl_secs": d.ttl_secs,
                "observed_addrs": d.observed_addrs,
            })
        })
        .collect();
    let scores_json: Vec<Value> = scores
        .into_iter()
        .map(|(pid, s)| {
            json!({
                "peer_id": pid.as_str(),
                "latency_ms": s.latency_ms,
                "success_rate": s.success_rate,
                "uptime_score": s.uptime_score,
                "bandwidth_score": s.bandwidth_score,
                "relay_score": s.relay_score,
                "trust_score": s.trust_score,
                "geo_score": s.geo_score,
                "nat_compat_score": s.nat_compat_score,
                "load_penalty": s.load_penalty,
            })
        })
        .collect();

    json!({
        "event": "db_tables",
        "ts_ms": now_ms(),
        "db": {
            "enabled": true,
            "path": db.path,
        },
        "tables": {
            "storage_files": files_json,
            "peer_descriptors": descriptors_json,
            "peer_scores": scores_json,
        },
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
