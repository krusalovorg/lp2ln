

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use lp2ln_core_v2::app_plane::{
    AppCapability, AppCmd, AppErrorCode, AppEvent, AppPlaneRouter, MAX_FRAME_BYTES, PROTOCOL_VERSION,
    QUEUE_CAP, decode_cmd, encode_event,
};
use lp2ln_core_v2::node::{AppPlaneIpcOptions, NodeRuntime};
use lp2ln_core_v2::packet::Packet;
use lp2ln_core_v2::types::PeerId;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;

use crate::app_plane_streams::StreamTable;

#[derive(Debug, Clone)]
pub struct AppPlaneServerConfig {
    pub enabled: bool,
    pub path: String,
    pub dev_tcp_bind: Option<String>,
    pub app_token: Option<String>,
    pub allowed_protocol_ids: Vec<u16>,
    pub stream_auto_refill: bool,
}

impl AppPlaneServerConfig {
    pub fn from_options(experimental_enabled: bool, ipc: &AppPlaneIpcOptions) -> Self {
        Self {
            enabled: experimental_enabled,
            path: ipc.path.clone(),
            dev_tcp_bind: ipc
                .dev_tcp_bind
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            app_token: ipc
                .app_token
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            allowed_protocol_ids: ipc.allowed_protocol_ids.clone(),
            stream_auto_refill: true,
        }
    }

    fn protocol_allowed(&self, protocol_id: u16) -> bool {
        self.allowed_protocol_ids.is_empty()
            || self.allowed_protocol_ids.contains(&protocol_id)
    }
}

/// Capabilities the host is willing to grant (P3-04/P3-05).
fn grantable_capabilities() -> &'static [AppCapability] {
    &[
        AppCapability::Subscribe,
        AppCapability::Send,
        AppCapability::QueryStatus,
        AppCapability::OpenStream,
    ]
}

pub fn spawn_app_plane_server(
    cfg: AppPlaneServerConfig,
    node: Arc<NodeRuntime>,
    router: Arc<lp2ln_core_v2::router::Router>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if !cfg.enabled {
            return;
        }
        if let Err(e) = run(cfg, node, router).await {
            lp2ln_core_v2::error!("[AppPlane] server stopped: {}", e);
        }
    })
}

pub async fn run(
    cfg: AppPlaneServerConfig,
    node: Arc<NodeRuntime>,
    router: Arc<lp2ln_core_v2::router::Router>,
) -> anyhow::Result<()> {
    let app_router = Arc::new(AppPlaneRouter::new());
    spawn_router_bridge(app_router.clone(), router);

    let mut tasks = Vec::new();

    let local_path = cfg.path.clone();
    let node_l = node.clone();
    let app_l = app_router.clone();
    let cfg_l = cfg.clone();
    tasks.push(tokio::spawn(async move {
        if let Err(e) = run_local_listener(&local_path, node_l, app_l, cfg_l).await {
            lp2ln_core_v2::error!("[AppPlane] local listener error: {}", e);
        }
    }));

    if let Some(bind) = cfg.dev_tcp_bind.clone() {
        let node_t = node.clone();
        let app_t = app_router.clone();
        let cfg_t = cfg.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = run_dev_tcp_listener(&bind, node_t, app_t, cfg_t).await {
                lp2ln_core_v2::error!("[AppPlane] dev TCP listener error: {}", e);
            }
        }));
    }

    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}

fn spawn_router_bridge(app_router: Arc<AppPlaneRouter>, router: Arc<lp2ln_core_v2::router::Router>) {
    tokio::spawn(async move {
        let mut sub = router.subscribe();
        loop {
            match sub.recv().await {
                Ok(inc) => {
                    if let Some(pid) = inc.packet.protocol_id {
                        let ev = AppEvent::Incoming {
                            from: inc.packet.sender.clone(),
                            protocol_id: pid,
                            payload: inc.packet.data.clone(),
                        };
                        app_router.dispatch(pid, ev);
                    }
                }
                Err(RecvError::Lagged(_)) => {}
                Err(_) => break,
            }
        }
    });
}

async fn run_dev_tcp_listener(
    bind: &str,
    node: Arc<NodeRuntime>,
    app_router: Arc<AppPlaneRouter>,
    cfg: AppPlaneServerConfig,
) -> anyhow::Result<()> {
    let addr: SocketAddr = bind.parse()?;
    if !addr.ip().is_loopback() {
        anyhow::bail!("dev_tcp_bind must be loopback (got {addr})");
    }
    let listener = TcpListener::bind(addr).await?;
    lp2ln_core_v2::info!(
        "[AppPlane] listening on tcp://{} (dev only)",
        listener.local_addr()?
    );
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let node = node.clone();
        let app_router = app_router.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            handle_connection(stream, node, app_router, cfg).await;
        });
    }
}

#[cfg(unix)]
async fn run_local_listener(
    path: &str,
    node: Arc<NodeRuntime>,
    app_router: Arc<AppPlaneRouter>,
    cfg: AppPlaneServerConfig,
) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use tokio::net::UnixListener;

    let path = PathBuf::from(path);
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let listener = UnixListener::bind(&path)?;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    lp2ln_core_v2::info!(
        "[AppPlane] listening on unix:{} (mode=0600)",
        path.display()
    );
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let node = node.clone();
        let app_router = app_router.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            handle_connection(stream, node, app_router, cfg).await;
        });
    }
}

#[cfg(windows)]
async fn run_local_listener(
    path: &str,
    node: Arc<NodeRuntime>,
    app_router: Arc<AppPlaneRouter>,
    cfg: AppPlaneServerConfig,
) -> anyhow::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe_name = normalize_windows_pipe_name(path);
    lp2ln_core_v2::info!("[AppPlane] listening on named pipe {}", pipe_name);

    loop {
        let server = ServerOptions::new()
            .first_pipe_instance(false)
            .create(&pipe_name)?;
        server.connect().await?;
        let node = node.clone();
        let app_router = app_router.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            handle_connection(server, node, app_router, cfg).await;
        });
    }
}

fn normalize_windows_pipe_name(path: &str) -> String {
    if path.starts_with(r"\\.\pipe\") || path.starts_with(r"//./pipe/") {
        path.to_string()
    } else if path.contains('\\') || path.contains('/') {
        path.to_string()
    } else {
        format!(r"\\.\pipe\{path}")
    }
}

async fn handle_connection<S>(
    stream: S,
    node: Arc<NodeRuntime>,
    app_router: Arc<AppPlaneRouter>,
    cfg: AppPlaneServerConfig,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, writer) = tokio::io::split(stream);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(QUEUE_CAP);

    let writer_task = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(frame) = out_rx.recv().await {
            if writer.write_all(&frame).await.is_err() {
                break;
            }
        }
    });

    let my_peer_id = node.peer_id().to_string();
    let mut forwarders: HashMap<u16, tokio::task::JoinHandle<()>> = HashMap::new();
    let mut streams = StreamTable::new().with_auto_refill(cfg.stream_auto_refill);
    let mut handshake_ok = false;
    let mut granted: HashSet<AppCapability> = HashSet::new();

    loop {
        let mut len_buf = [0u8; 4];
        if reader.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let frame_len = u32::from_le_bytes(len_buf);
        if frame_len == 0 || frame_len > MAX_FRAME_BYTES {
            break;
        }

        let mut body = vec![0u8; frame_len as usize];
        if reader.read_exact(&mut body).await.is_err() {
            break;
        }

        let cmd = match decode_cmd(&body) {
            Ok(c) => c,
            Err(_) => {
                let ev = encode_event(&AppEvent::Error {
                    code: AppErrorCode::BadFrame,
                    message: Some("bad frame".into()),
                });
                let _ = out_tx.send(ev).await;
                continue;
            }
        };

        if !handshake_ok {
            match cmd {
                AppCmd::Hello {
                    version,
                    capabilities,
                    token,
                } => {
                    let (ok, caps, err, msg) =
                        negotiate_hello(&cfg, version, &capabilities, token.as_deref());
                    if ok {
                        handshake_ok = true;
                        granted = caps.iter().copied().collect();
                    }
                    let ack = encode_event(&AppEvent::HelloAck {
                        version: PROTOCOL_VERSION,
                        capabilities: caps,
                        error: err,
                        message: msg,
                    });
                    if out_tx.send(ack).await.is_err() || !handshake_ok {
                        break;
                    }
                    continue;
                }
                _ => {
                    let ev = encode_event(&AppEvent::Error {
                        code: AppErrorCode::Unauthorized,
                        message: Some("Hello required before other commands".into()),
                    });
                    let _ = out_tx.send(ev).await;
                    break;
                }
            }
        }

        match cmd {
            AppCmd::Hello { .. } => {
                let ack = encode_event(&AppEvent::HelloAck {
                    version: PROTOCOL_VERSION,
                    capabilities: granted.iter().copied().collect(),
                    error: None,
                    message: Some("already handshaken".into()),
                });
                if out_tx.send(ack).await.is_err() {
                    break;
                }
            }
            AppCmd::Subscribe { protocol_id } => {
                let reply = if !granted.contains(&AppCapability::Subscribe) {
                    encode_event(&AppEvent::Ack {
                        ok: false,
                        error: Some("capability Subscribe not granted".into()),
                    })
                } else if !cfg.protocol_allowed(protocol_id) {
                    encode_event(&AppEvent::Error {
                        code: AppErrorCode::UnknownProtocol,
                        message: Some(format!("protocol_id {protocol_id} not allowed")),
                    })
                } else {
                    if let std::collections::hash_map::Entry::Vacant(e) =
                        forwarders.entry(protocol_id)
                    {
                        let mut rx = app_router.subscribe(protocol_id);
                        let out = out_tx.clone();
                        e.insert(tokio::spawn(async move {
                            while let Some(ev) = rx.recv().await {
                                let frame = encode_event(&ev);
                                if out.send(frame).await.is_err() {
                                    break;
                                }
                            }
                        }));
                    }
                    encode_event(&AppEvent::Ack {
                        ok: true,
                        error: None,
                    })
                };
                if out_tx.send(reply).await.is_err() {
                    break;
                }
            }
            AppCmd::Unsubscribe { protocol_id } => {
                if let Some(h) = forwarders.remove(&protocol_id) {
                    h.abort();
                }
                app_router.prune(protocol_id);
                let ack = encode_event(&AppEvent::Ack {
                    ok: true,
                    error: None,
                });
                if out_tx.send(ack).await.is_err() {
                    break;
                }
            }
            AppCmd::Send {
                peer_id,
                protocol_id,
                payload,
            } => {
                let reply = if !granted.contains(&AppCapability::Send) {
                    encode_event(&AppEvent::Ack {
                        ok: false,
                        error: Some("capability Send not granted".into()),
                    })
                } else if !cfg.protocol_allowed(protocol_id) {
                    encode_event(&AppEvent::Error {
                        code: AppErrorCode::UnknownProtocol,
                        message: Some(format!("protocol_id {protocol_id} not allowed")),
                    })
                } else {
                    match send_app_packet(&node, &my_peer_id, &peer_id, protocol_id, payload).await
                    {
                        Ok(_) => encode_event(&AppEvent::Ack {
                            ok: true,
                            error: None,
                        }),
                        Err(e) => encode_event(&AppEvent::Ack {
                            ok: false,
                            error: Some(e.to_string()),
                        }),
                    }
                };
                if out_tx.send(reply).await.is_err() {
                    break;
                }
            }
            AppCmd::OpenStream {
                stream_id,
                protocol_id,
                peer_id,
            } => {
                let replies = if !granted.contains(&AppCapability::OpenStream) {
                    vec![encode_event(&AppEvent::Ack {
                        ok: false,
                        error: Some("capability OpenStream not granted".into()),
                    })]
                } else if !cfg.protocol_allowed(protocol_id) {
                    vec![encode_event(&AppEvent::Error {
                        code: AppErrorCode::UnknownProtocol,
                        message: Some(format!("protocol_id {protocol_id} not allowed")),
                    })]
                } else {
                    match streams.open(stream_id, protocol_id, peer_id) {
                        Ok(evs) => {
                            let mut frames = vec![encode_event(&AppEvent::Ack {
                                ok: true,
                                error: None,
                            })];
                            for ev in evs {
                                frames.push(encode_event(&ev));
                            }
                            frames
                        }
                        Err(code) => vec![encode_event(&AppEvent::Error {
                            code,
                            message: Some(format!("OpenStream failed: {code}")),
                        })],
                    }
                };
                let mut dead = false;
                for frame in replies {
                    if out_tx.send(frame).await.is_err() {
                        dead = true;
                        break;
                    }
                }
                if dead {
                    break;
                }
            }
            AppCmd::StreamChunk {
                stream_id,
                seq,
                payload,
            } => {
                let replies = if !granted.contains(&AppCapability::OpenStream) {
                    vec![encode_event(&AppEvent::Error {
                        code: AppErrorCode::Unauthorized,
                        message: Some("capability OpenStream not granted".into()),
                    })]
                } else {
                    match streams.on_chunk(stream_id, seq, payload) {
                        Ok(evs) => evs.into_iter().map(|ev| encode_event(&ev)).collect(),
                        Err(code) => vec![encode_event(&AppEvent::Error {
                            code,
                            message: Some(format!("StreamChunk failed: {code}")),
                        })],
                    }
                };
                let mut dead = false;
                for frame in replies {
                    if out_tx.send(frame).await.is_err() {
                        dead = true;
                        break;
                    }
                }
                if dead {
                    break;
                }
            }
            AppCmd::StreamWindow {
                stream_id,
                credits,
            } => {
                if granted.contains(&AppCapability::OpenStream) {
                    let _ = streams.on_window(stream_id, credits);
                }
            }
            AppCmd::StreamCancel { stream_id } => {
                let replies = if !granted.contains(&AppCapability::OpenStream) {
                    vec![encode_event(&AppEvent::Error {
                        code: AppErrorCode::Unauthorized,
                        message: Some("capability OpenStream not granted".into()),
                    })]
                } else {
                    match streams.cancel(stream_id) {
                        Ok(evs) => evs.into_iter().map(|ev| encode_event(&ev)).collect(),
                        Err(code) => vec![encode_event(&AppEvent::Error {
                            code,
                            message: Some(format!("StreamCancel failed: {code}")),
                        })],
                    }
                };
                let mut dead = false;
                for frame in replies {
                    if out_tx.send(frame).await.is_err() {
                        dead = true;
                        break;
                    }
                }
                if dead {
                    break;
                }
            }

            AppCmd::DhtAnnounce { content_ids } => {
                let reply = if !granted.contains(&AppCapability::Send) {
                    encode_event(&AppEvent::Ack {
                        ok: false,
                        error: Some("capability Send not granted".into()),
                    })
                } else if let Some(dht) = node.dht_service() {
                    for id_bytes in &content_ids {
                        if let Ok(arr) = id_bytes.as_slice().try_into() {
                            let _ = dht.announce(arr).await;
                        }
                    }
                    encode_event(&AppEvent::Ack { ok: true, error: None })
                } else {
                    encode_event(&AppEvent::Ack {
                        ok: false,
                        error: Some("DHT not enabled (set experimental.dht=true)".into()),
                    })
                };
                if out_tx.send(reply).await.is_err() {
                    break;
                }
            }

            AppCmd::DhtFindProviders { content_id } => {
                let reply = if !granted.contains(&AppCapability::QueryStatus) {
                    Some(encode_event(&AppEvent::Ack {
                        ok: false,
                        error: Some("capability QueryStatus not granted".into()),
                    }))
                } else if node.dht_service().is_none() {
                    Some(encode_event(&AppEvent::Ack {
                        ok: false,
                        error: Some("DHT not enabled".into()),
                    }))
                } else {
                    None // handled in spawned task below
                };
                if let Some(frame) = reply {
                    if out_tx.send(frame).await.is_err() {
                        break;
                    }
                } else if let Some(dht) = node.dht_service() {
                    let tx = out_tx.clone();
                    let cid_bytes = content_id.clone();
                    let node2 = Arc::clone(&node);
                    tokio::spawn(async move {
                        let arr: [u8; 32] = match cid_bytes.as_slice().try_into() {
                            Ok(a) => a,
                            Err(_) => {
                                let _ = tx.send(encode_event(&AppEvent::Ack {
                                    ok: false,
                                    error: Some("invalid content_id length".into()),
                                })).await;
                                return;
                            }
                        };
                        // Pick any connected peer; find_providers checks local store first.
                        let connected: Vec<String> = node2
                            .connected_peers()
                            .into_iter()
                            .map(|p| p.into_string())
                            .collect();
                        let query_peer = connected.first().cloned().unwrap_or_default();
                        let mut providers: Vec<String> = dht
                            .find_providers(&query_peer, arr)
                            .await
                            .unwrap_or_default()
                            .into_iter()
                            .map(|p| p.peer_id)
                            .collect();
                        // DHT provider records are in-memory and die on lp2lnd restart.
                        // If the record is gone but a peer still holds the block, fall back
                        // to connected peers (and self, if the local block store has it).
                        if providers.is_empty() {
                            if let Some(bt) = node2.block_transfer_service() {
                                if bt.store.get(&arr).ok().flatten().is_some() {
                                    providers.push(node2.peer_id().to_string());
                                }
                            }
                            for p in connected {
                                if !providers.iter().any(|x| x == &p) {
                                    providers.push(p);
                                }
                            }
                        }
                        let _ = tx.send(encode_event(&AppEvent::DhtProviders {
                            content_id: cid_bytes,
                            providers,
                        })).await;
                    });
                }
            }

            AppCmd::BlockFetch { content_id, peer_ids } => {
                let reply = if !granted.contains(&AppCapability::Send) {
                    Some(encode_event(&AppEvent::Ack {
                        ok: false,
                        error: Some("capability Send not granted".into()),
                    }))
                } else if node.block_transfer_service().is_none() {
                    Some(encode_event(&AppEvent::Ack {
                        ok: false,
                        error: Some("block_transfer not enabled (set experimental.block_transfer=true)".into()),
                    }))
                } else {
                    None
                };
                if let Some(frame) = reply {
                    if out_tx.send(frame).await.is_err() {
                        break;
                    }
                } else if let Some(bt) = node.block_transfer_service() {
                    let tx = out_tx.clone();
                    let cid_bytes = content_id.clone();
                    tokio::spawn(async move {
                        let arr: [u8; 32] = match cid_bytes.as_slice().try_into() {
                            Ok(a) => a,
                            Err(_) => {
                                let _ = tx.send(encode_event(&AppEvent::Ack {
                                    ok: false,
                                    error: Some("invalid content_id length".into()),
                                })).await;
                                return;
                            }
                        };
                        match bt.fetch_from_providers(arr, &peer_ids).await {
                            Ok(data) => {
                                let _ = tx.send(encode_event(&AppEvent::BlockData {
                                    content_id: cid_bytes,
                                    data,
                                })).await;
                            }
                            Err(e) => {
                                let _ = tx.send(encode_event(&AppEvent::Ack {
                                    ok: false,
                                    error: Some(format!("block fetch failed: {e}")),
                                })).await;
                            }
                        }
                    });
                }
            }

            AppCmd::BlockPush { content_id, data, min_replicas } => {
                let reply = if !granted.contains(&AppCapability::Send) {
                    Some(encode_event(&AppEvent::Ack {
                        ok: false,
                        error: Some("capability Send not granted".into()),
                    }))
                } else if node.block_transfer_service().is_none() {
                    Some(encode_event(&AppEvent::Ack {
                        ok: false,
                        error: Some("block_transfer not enabled (set experimental.block_transfer=true)".into()),
                    }))
                } else {
                    None
                };
                if let Some(frame) = reply {
                    if out_tx.send(frame).await.is_err() {
                        break;
                    }
                } else if let Some(bt) = node.block_transfer_service() {
                    let tx = out_tx.clone();
                    let cid_bytes = content_id.clone();
                    let node2 = Arc::clone(&node);
                    tokio::spawn(async move {
                        let arr: [u8; 32] = match cid_bytes.as_slice().try_into() {
                            Ok(a) => a,
                            Err(_) => {
                                let _ = tx.send(encode_event(&AppEvent::Ack {
                                    ok: false,
                                    error: Some("invalid content_id length".into()),
                                })).await;
                                return;
                            }
                        };
                        if lp2ln_core_v2::storage::hash_bytes(&data) != arr {
                            let _ = tx.send(encode_event(&AppEvent::Ack {
                                ok: false,
                                error: Some("data does not hash to content_id".into()),
                            })).await;
                            return;
                        }
                        // Always seed the node's local store so this node can serve the block.
                        if let Err(e) = lp2ln_core_v2::storage::BlockStoreTrait::put(&bt.store, &data) {
                            let _ = tx.send(encode_event(&AppEvent::Ack {
                                ok: false,
                                error: Some(format!("local store failed: {e}")),
                            })).await;
                            return;
                        }
                        // ponytail: naive replica selection = connected peers in order;
                        // P8 replaces this with scored/diverse selection.
                        let mut stored_by = Vec::new();
                        if min_replicas > 0 {
                            for peer in node2.connected_peers() {
                                if stored_by.len() >= min_replicas as usize {
                                    break;
                                }
                                let peer = peer.into_string();
                                if bt.push_to(&peer, arr, data.clone()).await.is_ok() {
                                    stored_by.push(peer);
                                }
                            }
                        }
                        let _ = tx.send(encode_event(&AppEvent::BlockPushed {
                            content_id: cid_bytes,
                            stored_by,
                        })).await;
                    });
                }
            }

            AppCmd::DhtPutValue { key, value, seq } => {
                let reply = if !granted.contains(&AppCapability::Send) {
                    encode_event(&AppEvent::Ack {
                        ok: false,
                        error: Some("capability Send not granted".into()),
                    })
                } else if let Some(dht) = node.dht_service() {
                    match key.as_slice().try_into() {
                        Ok(k) => {
                            let _ = dht.put_value(k, value, seq).await;
                            encode_event(&AppEvent::Ack { ok: true, error: None })
                        }
                        Err(_) => encode_event(&AppEvent::Ack {
                            ok: false,
                            error: Some("invalid key length".into()),
                        }),
                    }
                } else {
                    encode_event(&AppEvent::Ack {
                        ok: false,
                        error: Some("DHT not enabled (set experimental.dht=true)".into()),
                    })
                };
                if out_tx.send(reply).await.is_err() {
                    break;
                }
            }

            AppCmd::DhtGetValue { key } => {
                let reply = if !granted.contains(&AppCapability::QueryStatus) {
                    Some(encode_event(&AppEvent::Ack {
                        ok: false,
                        error: Some("capability QueryStatus not granted".into()),
                    }))
                } else if node.dht_service().is_none() {
                    Some(encode_event(&AppEvent::Ack {
                        ok: false,
                        error: Some("DHT not enabled".into()),
                    }))
                } else {
                    None
                };
                if let Some(frame) = reply {
                    if out_tx.send(frame).await.is_err() {
                        break;
                    }
                } else if let Some(dht) = node.dht_service() {
                    let tx = out_tx.clone();
                    let key_bytes = key.clone();
                    let node2 = Arc::clone(&node);
                    tokio::spawn(async move {
                        let k: [u8; 32] = match key_bytes.as_slice().try_into() {
                            Ok(a) => a,
                            Err(_) => {
                                let _ = tx.send(encode_event(&AppEvent::Ack {
                                    ok: false,
                                    error: Some("invalid key length".into()),
                                })).await;
                                return;
                            }
                        };
                        let query_peer = node2.connected_peers()
                            .into_iter()
                            .next()
                            .map(|p| p.into_string())
                            .unwrap_or_default();
                        let record = dht.get_value(&query_peer, k).await.ok().flatten();
                        let (value, seq) = match record {
                            Some(r) => (Some(r.value), r.seq),
                            None => (None, 0),
                        };
                        let _ = tx.send(encode_event(&AppEvent::DhtValue {
                            key: key_bytes,
                            value,
                            seq,
                        })).await;
                    });
                }
            }
        }
    }

    streams.clear();
    for (_, h) in forwarders {
        h.abort();
    }
    drop(out_tx);
    let _ = writer_task.await;
}

fn negotiate_hello(
    cfg: &AppPlaneServerConfig,
    version: u16,
    requested: &[AppCapability],
    token: Option<&str>,
) -> (bool, Vec<AppCapability>, Option<AppErrorCode>, Option<String>) {
    if version != PROTOCOL_VERSION {
        return (
            false,
            vec![],
            Some(AppErrorCode::UnsupportedVersion),
            Some(format!("need version {PROTOCOL_VERSION}")),
        );
    }
    if let Some(expected) = cfg.app_token.as_deref() {
        if token != Some(expected) {
            return (
                false,
                vec![],
                Some(AppErrorCode::Unauthorized),
                Some("invalid or missing app token".into()),
            );
        }
    }
    let grant: Vec<AppCapability> = requested
        .iter()
        .copied()
        .filter(|c| grantable_capabilities().contains(c))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    (true, grant, None, None)
}

async fn send_app_packet(
    node: &NodeRuntime,
    sender: &str,
    peer_id: &str,
    protocol_id: u16,
    payload: Vec<u8>,
) -> anyhow::Result<()> {
    let router = node
        .router()
        .ok_or_else(|| anyhow::anyhow!("node not started"))?;
    let pkt = Packet {
        signature: None,
        data: payload,
        nodes: vec![],
        sender: sender.to_string(),
        receiver: peer_id.to_string(),
        max_hops: 16,
        request_id: None,
        protocol_id: Some(protocol_id),
        chunk_stream_id: None,
        chunk_index: None,
        total_chunks: None,
    };
    router
        .send_to_peer(PeerId::from(peer_id), pkt, None)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lp2ln_core_v2::app_plane::{PROTOCOL_VERSION, decode_event, encode_cmd};
    use lp2ln_core_v2::node::{NodeBuilder, NodeOptions};
    use tokio::net::TcpStream;
    use tokio::time::{Duration, timeout};

    fn test_cfg() -> AppPlaneServerConfig {
        AppPlaneServerConfig {
            enabled: true,
            path: String::new(),
            dev_tcp_bind: None,
            app_token: None,
            allowed_protocol_ids: vec![],
            stream_auto_refill: true,
        }
    }

    async fn read_event(client: &mut TcpStream) -> AppEvent {
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let n = u32::from_le_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        client.read_exact(&mut body).await.unwrap();
        decode_event(&body).unwrap()
    }

    async fn handshake(client: &mut TcpStream, token: Option<&str>) {
        handshake_caps(
            client,
            token,
            &[AppCapability::Subscribe, AppCapability::Send],
        )
        .await;
    }

    async fn handshake_caps(
        client: &mut TcpStream,
        token: Option<&str>,
        caps: &[AppCapability],
    ) {
        client
            .write_all(&encode_cmd(&AppCmd::Hello {
                version: PROTOCOL_VERSION,
                capabilities: caps.to_vec(),
                token: token.map(str::to_string),
            }))
            .await
            .unwrap();
        match read_event(client).await {
            AppEvent::HelloAck { error: None, .. } => {}
            other => panic!("handshake failed: {other:?}"),
        }
    }

    async fn boot_node() -> Arc<NodeRuntime> {
        let mut options = NodeOptions::empty()
            .with_listen("tcp", "127.0.0.1:0".parse().unwrap())
            .keypair_generate();
        options.enable_topology_maintenance = false;
        let mut node = NodeBuilder::new()
            .add_default_transports_from_options(&options)
            .build(options)
            .unwrap();
        node.start().await.unwrap();
        Arc::new(node)
    }

    #[tokio::test]
    async fn subscribe_before_hello_rejected() {
        let node = boot_node().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app_router = Arc::new(AppPlaneRouter::new());
        let cfg = test_cfg();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, node, app_router, cfg).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&encode_cmd(&AppCmd::Subscribe { protocol_id: 1 }))
            .await
            .unwrap();
        match read_event(&mut client).await {
            AppEvent::Error {
                code: AppErrorCode::Unauthorized,
                ..
            } => {}
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn hello_rejects_bad_version_and_token() {
        let node = boot_node().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app_router = Arc::new(AppPlaneRouter::new());
        let mut cfg = test_cfg();
        cfg.app_token = Some("secret".into());
        let node_c = node.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, node_c, app_router, cfg).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&encode_cmd(&AppCmd::Hello {
                version: 99,
                capabilities: vec![],
                token: Some("secret".into()),
            }))
            .await
            .unwrap();
        match read_event(&mut client).await {
            AppEvent::HelloAck {
                error: Some(AppErrorCode::UnsupportedVersion),
                ..
            } => {}
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
        // connection closed after failed hello — open new
        drop(client);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app_router = Arc::new(AppPlaneRouter::new());
        let mut cfg = test_cfg();
        cfg.app_token = Some("secret".into());
        let node_c = node.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, node_c, app_router, cfg).await;
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&encode_cmd(&AppCmd::Hello {
                version: PROTOCOL_VERSION,
                capabilities: vec![AppCapability::Subscribe],
                token: Some("wrong".into()),
            }))
            .await
            .unwrap();
        match read_event(&mut client).await {
            AppEvent::HelloAck {
                error: Some(AppErrorCode::Unauthorized),
                ..
            } => {}
            other => panic!("expected Unauthorized token, got {other:?}"),
        }

        node.stop().await.unwrap();
    }

    #[tokio::test]
    async fn subscribe_receives_dispatched_incoming() {
        let node = boot_node().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app_router = Arc::new(AppPlaneRouter::new());
        let node_c = node.clone();
        let app_c = app_router.clone();
        let cfg = test_cfg();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, node_c, app_c, cfg).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        handshake(&mut client, None).await;
        client
            .write_all(&encode_cmd(&AppCmd::Subscribe { protocol_id: 42 }))
            .await
            .unwrap();
        assert!(matches!(
            read_event(&mut client).await,
            AppEvent::Ack { ok: true, .. }
        ));

        tokio::time::sleep(Duration::from_millis(20)).await;
        app_router.dispatch(
            42,
            AppEvent::Incoming {
                from: "peer-x".into(),
                protocol_id: 42,
                payload: b"hello-app".to_vec(),
            },
        );

        let ev = timeout(Duration::from_secs(2), read_event(&mut client))
            .await
            .expect("Incoming timeout");
        match ev {
            AppEvent::Incoming {
                from,
                protocol_id,
                payload,
            } => {
                assert_eq!(from, "peer-x");
                assert_eq!(protocol_id, 42);
                assert_eq!(payload, b"hello-app");
            }
            other => panic!("expected Incoming, got {other:?}"),
        }

        client
            .write_all(&encode_cmd(&AppCmd::Unsubscribe { protocol_id: 42 }))
            .await
            .unwrap();
        assert!(matches!(
            read_event(&mut client).await,
            AppEvent::Ack { ok: true, .. }
        ));

        node.stop().await.unwrap();
    }

    #[tokio::test]
    async fn protocol_registry_rejects_unknown() {
        let node = boot_node().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app_router = Arc::new(AppPlaneRouter::new());
        let mut cfg = test_cfg();
        cfg.allowed_protocol_ids = vec![42];
        let node_c = node.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, node_c, app_router, cfg).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        handshake(&mut client, None).await;
        client
            .write_all(&encode_cmd(&AppCmd::Subscribe { protocol_id: 99 }))
            .await
            .unwrap();
        match read_event(&mut client).await {
            AppEvent::Error {
                code: AppErrorCode::UnknownProtocol,
                ..
            } => {}
            other => panic!("expected UnknownProtocol, got {other:?}"),
        }
        node.stop().await.unwrap();
    }

    #[tokio::test]
    async fn flood_does_not_kill_fast_subscriber() {
        let node = boot_node().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app_router = Arc::new(AppPlaneRouter::new());
        let node_c = node.clone();
        let app_c = app_router.clone();
        let cfg = test_cfg();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let node = node_c.clone();
                let app = app_c.clone();
                let cfg = cfg.clone();
                tokio::spawn(handle_connection(stream, node, app, cfg));
            }
        });

        let mut slow = TcpStream::connect(addr).await.unwrap();
        let mut fast = TcpStream::connect(addr).await.unwrap();
        for c in [&mut slow, &mut fast] {
            handshake(c, None).await;
            c.write_all(&encode_cmd(&AppCmd::Subscribe { protocol_id: 11 }))
                .await
                .unwrap();
            assert!(matches!(
                read_event(c).await,
                AppEvent::Ack { ok: true, .. }
            ));
        }
        tokio::time::sleep(Duration::from_millis(30)).await;

        for i in 0..(QUEUE_CAP + 8) {
            app_router.dispatch(
                11,
                AppEvent::Incoming {
                    from: "flood".into(),
                    protocol_id: 11,
                    payload: vec![i as u8],
                },
            );
        }

        let ev = timeout(Duration::from_secs(2), read_event(&mut fast))
            .await
            .expect("fast client stalled");
        assert!(matches!(ev, AppEvent::Incoming { .. }));
        assert!(app_router.subscriber_count(11) >= 1);

        node.stop().await.unwrap();
    }

    #[tokio::test]
    async fn dev_tcp_subscribe_ack() {
        let node = boot_node().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app_router = Arc::new(AppPlaneRouter::new());
        let node_c = node.clone();
        let app_c = app_router.clone();
        let cfg = test_cfg();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, node_c, app_c, cfg).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        handshake(&mut client, None).await;
        client
            .write_all(&encode_cmd(&AppCmd::Subscribe { protocol_id: 42 }))
            .await
            .unwrap();
        assert!(matches!(
            read_event(&mut client).await,
            AppEvent::Ack { ok: true, .. }
        ));
        node.stop().await.unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn named_pipe_subscribe_ack() {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

        let node = boot_node().await;
        let pipe = format!(r"\\.\pipe\lp2ln-app-test-{}", std::process::id());
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe)
            .unwrap();
        let app_router = Arc::new(AppPlaneRouter::new());
        let node_c = node.clone();
        let app_c = app_router.clone();
        let cfg = test_cfg();
        let accept = tokio::spawn(async move {
            server.connect().await.unwrap();
            handle_connection(server, node_c, app_c, cfg).await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut client = ClientOptions::new().open(&pipe).unwrap();
        client
            .write_all(&encode_cmd(&AppCmd::Hello {
                version: PROTOCOL_VERSION,
                capabilities: vec![AppCapability::Subscribe],
                token: None,
            }))
            .await
            .unwrap();
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let n = u32::from_le_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        client.read_exact(&mut body).await.unwrap();
        assert!(matches!(
            decode_event(&body).unwrap(),
            AppEvent::HelloAck { error: None, .. }
        ));

        client
            .write_all(&encode_cmd(&AppCmd::Subscribe { protocol_id: 7 }))
            .await
            .unwrap();
        client.read_exact(&mut len_buf).await.unwrap();
        let n = u32::from_le_bytes(len_buf) as usize;
        body.resize(n, 0);
        client.read_exact(&mut body).await.unwrap();
        assert!(matches!(
            decode_event(&body).unwrap(),
            AppEvent::Ack { ok: true, .. }
        ));

        drop(client);
        let _ = accept.await;
        node.stop().await.unwrap();
    }

    #[test]
    fn normalize_pipe_name() {
        assert_eq!(
            normalize_windows_pipe_name("lp2ln-app"),
            r"\\.\pipe\lp2ln-app"
        );
        assert_eq!(
            normalize_windows_pipe_name(r"\\.\pipe\custom"),
            r"\\.\pipe\custom"
        );
    }

    #[test]
    fn negotiate_hello_unit() {
        let mut cfg = test_cfg();
        let (ok, caps, err, _) = negotiate_hello(
            &cfg,
            PROTOCOL_VERSION,
            &[AppCapability::Subscribe, AppCapability::OpenStream],
            None,
        );
        assert!(ok);
        assert!(err.is_none());
        assert!(caps.contains(&AppCapability::Subscribe));
        assert!(caps.contains(&AppCapability::OpenStream));

        cfg.app_token = Some("t".into());
        let (ok, _, err, _) = negotiate_hello(&cfg, PROTOCOL_VERSION, &[], Some("t"));
        assert!(ok);
        assert!(err.is_none());
        let (ok, _, err, _) = negotiate_hello(&cfg, PROTOCOL_VERSION, &[], None);
        assert!(!ok);
        assert_eq!(err, Some(AppErrorCode::Unauthorized));
    }

    #[tokio::test]
    async fn open_stream_window_and_cancel() {
        use lp2ln_core_v2::app_plane::DEFAULT_STREAM_CREDITS;

        let node = boot_node().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app_router = Arc::new(AppPlaneRouter::new());
        let cfg = test_cfg();
        let node_c = node.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, node_c, app_router, cfg).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        handshake_caps(
            &mut client,
            None,
            &[AppCapability::OpenStream, AppCapability::Subscribe],
        )
        .await;

        client
            .write_all(&encode_cmd(&AppCmd::OpenStream {
                stream_id: 9,
                protocol_id: 1,
                peer_id: "peer-z".into(),
            }))
            .await
            .unwrap();
        assert!(matches!(
            read_event(&mut client).await,
            AppEvent::Ack { ok: true, .. }
        ));
        match read_event(&mut client).await {
            AppEvent::StreamWindow {
                stream_id: 9,
                credits,
            } => assert_eq!(credits, DEFAULT_STREAM_CREDITS),
            other => panic!("expected StreamWindow, got {other:?}"),
        }

        client
            .write_all(&encode_cmd(&AppCmd::StreamCancel { stream_id: 9 }))
            .await
            .unwrap();
        match read_event(&mut client).await {
            AppEvent::StreamClosed {
                stream_id: 9,
                error: Some(AppErrorCode::Canceled),
            } => {}
            other => panic!("expected StreamClosed Canceled, got {other:?}"),
        }

        node.stop().await.unwrap();
    }

    #[tokio::test]
    async fn stream_backpressure_without_refill() {
        use lp2ln_core_v2::app_plane::DEFAULT_STREAM_CREDITS;

        let node = boot_node().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app_router = Arc::new(AppPlaneRouter::new());
        let mut cfg = test_cfg();
        cfg.stream_auto_refill = false;
        let node_c = node.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, node_c, app_router, cfg).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        handshake_caps(&mut client, None, &[AppCapability::OpenStream]).await;

        client
            .write_all(&encode_cmd(&AppCmd::OpenStream {
                stream_id: 1,
                protocol_id: 1,
                peer_id: "p".into(),
            }))
            .await
            .unwrap();
        assert!(matches!(
            read_event(&mut client).await,
            AppEvent::Ack { ok: true, .. }
        ));
        assert!(matches!(
            read_event(&mut client).await,
            AppEvent::StreamWindow { .. }
        ));

        for i in 0..DEFAULT_STREAM_CREDITS {
            client
                .write_all(&encode_cmd(&AppCmd::StreamChunk {
                    stream_id: 1,
                    seq: i as u64,
                    payload: vec![i as u8],
                }))
                .await
                .unwrap();
        }
        // No events expected for accepted chunks without echo/refill.
        client
            .write_all(&encode_cmd(&AppCmd::StreamChunk {
                stream_id: 1,
                seq: DEFAULT_STREAM_CREDITS as u64,
                payload: vec![0xff],
            }))
            .await
            .unwrap();
        match timeout(Duration::from_secs(2), read_event(&mut client))
            .await
            .expect("overflow timeout")
        {
            AppEvent::Error {
                code: AppErrorCode::QueueOverflow,
                ..
            } => {}
            other => panic!("expected QueueOverflow, got {other:?}"),
        }

        node.stop().await.unwrap();
    }

    #[tokio::test]
    async fn sdk_client_against_host() {
        use lp2ln_app_sdk::{AppClient, ConnectOpts, OpenStreamOpts};
        use lp2ln_core_v2::app_plane::DEFAULT_STREAM_CREDITS;

        let node = boot_node().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app_router = Arc::new(AppPlaneRouter::new());
        let cfg = test_cfg();
        let node_c = node.clone();
        let app_c = app_router.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, node_c, app_c, cfg).await;
        });

        let mut client = AppClient::connect(ConnectOpts::tcp(addr.to_string()))
            .await
            .unwrap();
        client
            .hello(
                &[
                    AppCapability::Subscribe,
                    AppCapability::OpenStream,
                    AppCapability::Send,
                ],
                None,
            )
            .await
            .unwrap();
        client.subscribe(55).await.unwrap();

        tokio::time::sleep(Duration::from_millis(20)).await;
        app_router.dispatch(
            55,
            AppEvent::Incoming {
                from: "sdk-peer".into(),
                protocol_id: 55,
                payload: b"via-sdk".to_vec(),
            },
        );
        match timeout(Duration::from_secs(2), client.next_event())
            .await
            .expect("Incoming timeout")
            .unwrap()
        {
            AppEvent::Incoming {
                from,
                protocol_id,
                payload,
            } => {
                assert_eq!(from, "sdk-peer");
                assert_eq!(protocol_id, 55);
                assert_eq!(payload, b"via-sdk");
            }
            other => panic!("expected Incoming, got {other:?}"),
        }

        let credits = client
            .open_stream(OpenStreamOpts {
                stream_id: 3,
                protocol_id: 55,
                peer_id: "x".into(),
            })
            .await
            .unwrap();
        assert_eq!(credits, DEFAULT_STREAM_CREDITS);
        client.stream_cancel(3).await.unwrap();

        node.stop().await.unwrap();
    }

    #[tokio::test]
    async fn sdk_reconnect_and_resubscribe() {
        use lp2ln_app_sdk::{AppClient, ConnectOpts};

        let node = boot_node().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app_router = Arc::new(AppPlaneRouter::new());
        let cfg = test_cfg();
        let node_c = node.clone();
        let app_c = app_router.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let node = node_c.clone();
                let app = app_c.clone();
                let cfg = cfg.clone();
                tokio::spawn(handle_connection(stream, node, app, cfg));
            }
        });

        let opts = ConnectOpts::tcp(addr.to_string());
        let mut client = AppClient::connect(opts.clone()).await.unwrap();
        let caps = [
            AppCapability::Subscribe,
            AppCapability::OpenStream,
            AppCapability::Send,
        ];
        client.hello(&caps, None).await.unwrap();
        client.subscribe(77).await.unwrap();

        // Drop connection side by reconnecting (new TCP) and resubscribe.
        client
            .reconnect(opts, &caps, None, 3)
            .await
            .unwrap();
        client.subscribe(77).await.unwrap();

        tokio::time::sleep(Duration::from_millis(30)).await;
        app_router.dispatch(
            77,
            AppEvent::Incoming {
                from: "re".into(),
                protocol_id: 77,
                payload: b"after-reconnect".to_vec(),
            },
        );
        match timeout(Duration::from_secs(2), client.next_event())
            .await
            .expect("timeout")
            .unwrap()
        {
            AppEvent::Incoming { payload, .. } => assert_eq!(payload, b"after-reconnect"),
            other => panic!("expected Incoming after reconnect, got {other:?}"),
        }

        node.stop().await.unwrap();
    }
}
