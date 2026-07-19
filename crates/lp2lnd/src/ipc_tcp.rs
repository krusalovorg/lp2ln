use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use lp2ln_core_v2::db::P2PDatabase;
use lp2ln_core_v2::node::IpcTcpOptions;
use lp2ln_core_v2::node::NodeRuntime;
use lp2ln_core_v2::sessions::IncomingPacket;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;

use crate::debug_server;

/// Outbound frames queued for the IPC TCP writer (`command_result`, `incoming_packet`, …).
/// Larger than default `mpsc(256)` so bursts from the router broadcast do not block
/// the push task while the client/kernel drains the socket.
const IPC_TCP_OUTBOUND_QUEUE_CAP: usize = 4096;

/// Short summary of an incoming IPC JSON frame (no full payload).
fn ipc_recv_summary(frame_len: usize, value: &Value) -> String {
    let cmd = value
        .get("cmd")
        .and_then(|c| c.as_str())
        .unwrap_or("<missing cmd>");
    let mut out = format!("frame={}B cmd={}", frame_len, cmd);
    match cmd {
        "send_packet" | "send_to_peer" => {
            if let Some(p) = value.get("peer_id").and_then(|v| v.as_str()) {
                out.push_str(&format!(" route_peer={}", p));
            }
            if let Some(d) = value.get("data").and_then(|v| v.as_str()) {
                out.push_str(&format!(" data_field_len={}", d.len()));
            }
            if let Some(w) = value.get("wait_reply").and_then(|v| v.as_bool()) {
                out.push_str(&format!(" wait_reply={}", w));
            }
        }
        "connect_peer" | "disconnect_peer" => {
            if let Some(p) = value.get("peer_id").and_then(|v| v.as_str()) {
                out.push_str(&format!(" peer_id={}", p));
            }
        }
        _ => {}
    }
    if value.get("client_request_id").is_some() {
        out.push_str(" client_request_id=…");
    }
    out
}

fn ipc_reply_summary(reply: &Value) -> String {
    let ev = reply.get("event").and_then(|e| e.as_str()).unwrap_or("?");
    let mut s = format!("event={}", ev);
    if let Some(cmd) = reply.get("cmd").and_then(|c| c.as_str()) {
        s.push_str(&format!(" cmd={}", cmd));
    }
    if let Some(ok) = reply.get("ok").and_then(|v| v.as_bool()) {
        s.push_str(&format!(" ok={}", ok));
    }
    if let Some(err) = reply.get("error").and_then(|e| e.as_str()) {
        let short: String = err.chars().take(160).collect();
        s.push_str(&format!(" error=\"{}\"", short));
    }
    if let Some(rid) = reply.get("request_id") {
        s.push_str(&format!(" request_id={}", rid));
    }
    s
}

#[derive(Debug, Clone)]
pub struct IpcTcpServerConfig {
    pub enabled: bool,
    pub bind_addr: String,
    pub push_incoming_packets: bool,
    pub max_frame_bytes: u32,
    pub experimental_content: bool,
}

impl From<&IpcTcpOptions> for IpcTcpServerConfig {
    fn from(o: &IpcTcpOptions) -> Self {
        Self {
            enabled: o.enabled,
            bind_addr: o.bind_addr.clone(),
            push_incoming_packets: o.push_incoming_packets,
            max_frame_bytes: o.max_frame_bytes.clamp(4096, 64 * 1024 * 1024),
            experimental_content: false,
        }
    }
}

impl IpcTcpServerConfig {
    pub fn with_experimental_content(mut self, enabled: bool) -> Self {
        self.experimental_content = enabled;
        self
    }
}

pub fn spawn_ipc_tcp_server(
    cfg: IpcTcpServerConfig,
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
                lp2ln_core_v2::error!("[IpcTcp] invalid bind_addr '{}': {}", cfg.bind_addr, e);
                return;
            }
        };

        let listener = match TcpListener::bind(bind_addr).await {
            Ok(v) => v,
            Err(e) => {
                lp2ln_core_v2::error!("[IpcTcp] bind {} failed: {}", bind_addr, e);
                return;
            }
        };

        lp2ln_core_v2::info!(
            "[IpcTcp] listening on tcp://{} (push_incoming_packets={}, max_frame_bytes={}, experimental.content={})",
            bind_addr,
            cfg.push_incoming_packets,
            cfg.max_frame_bytes,
            cfg.experimental_content
        );

        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let node = node.clone();
                    let db = db.clone();
                    let max_frame = cfg.max_frame_bytes;
                    let push = cfg.push_incoming_packets;
                    let experimental_content = cfg.experimental_content;
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_client(
                            stream,
                            peer,
                            node,
                            db,
                            max_frame,
                            push,
                            experimental_content,
                        )
                        .await
                        {
                            lp2ln_core_v2::warn!("[IpcTcp] client {} disconnected: {}", peer, e);
                        }
                    });
                }
                Err(e) => {
                    lp2ln_core_v2::warn!("[IpcTcp] accept failed: {}", e);
                }
            }
        }
    })
}

async fn handle_tcp_client(
    stream: TcpStream,
    peer: SocketAddr,
    node: Arc<NodeRuntime>,
    db: Option<Arc<P2PDatabase>>,
    max_frame_bytes: u32,
    push_incoming_packets: bool,
    experimental_content: bool,
) -> anyhow::Result<()> {
    let (mut read_half, write_half) = stream.into_split();
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(IPC_TCP_OUTBOUND_QUEUE_CAP);
    let peer_w = peer;

    let writer = tokio::spawn(async move {
        let mut wr = write_half;
        while let Some(buf) = out_rx.recv().await {
            if write_frame(&mut wr, &buf).await.is_err() {
                lp2ln_core_v2::warn!(
                    "[IpcTcp] {} write failed (client likely closed or network error)",
                    peer_w
                );
                break;
            }
        }
    });

    let hello = json!({
        "event": "hello",
        "protocol": "lp2lnd_ipc_tcp_v1",
        "ts_ms": now_ms(),
        "peer_id": node.peer_id(),
        "push_incoming_packets": push_incoming_packets,
        "max_frame_bytes": max_frame_bytes,
    });
    if out_tx.send(hello.to_string().into_bytes()).await.is_err() {
        writer.abort();
        return Ok(());
    }

    lp2ln_core_v2::info!("[IpcTcp] tcp connected: {}", peer);

    let mut push_task = None;
    if push_incoming_packets {
        if let Some(router) = node.router() {
            lp2ln_core_v2::info!("[IpcTcp] {} subscribed to incoming_packet push", peer);
            let mut sub = router.subscribe();
            let out_push = out_tx.clone();
            let peer_push = peer;
            push_task = Some(tokio::spawn(async move {
                loop {
                    match sub.recv().await {
                        Ok(ip) => {
                            lp2ln_core_v2::debug!(
                                "[IpcTcp] {:#?} push incoming_packet session_id={:#?} from_node={:#?} request_id={:#?} payload_bytes={:#?}",
                                peer_push,
                                ip.session_id,
                                ip.from_node,
                                ip.packet.request_id,
                                ip.packet.data.len(),
                            );
                            let msg = incoming_packet_json(&ip);
                            let bytes = msg.to_string().into_bytes();
                            if bytes.len() > max_frame_bytes as usize {
                                lp2ln_core_v2::warn!(
                                    "[IpcTcp] {} incoming_packet JSON exceeds max_frame_bytes, skipping",
                                    peer_push
                                );
                                continue;
                            }
                            if out_push.send(bytes).await.is_err() {
                                lp2ln_core_v2::warn!(
                                    "[IpcTcp] {} push task: out channel closed, stopping",
                                    peer_push
                                );
                                break;
                            }
                        }
                        Err(RecvError::Lagged(skipped)) => {
                            lp2ln_core_v2::warn!(
                                "[IpcTcp] {} incoming subscriber lagged, skipped {} messages",
                                peer_push,
                                skipped
                            );
                        }
                        Err(RecvError::Closed) => {
                            lp2ln_core_v2::debug!(
                                "[IpcTcp] {} incoming_packet broadcast closed",
                                peer_push
                            );
                            break;
                        }
                    }
                }
            }));
        } else {
            lp2ln_core_v2::warn!(
                "[IpcTcp] {} push_incoming_packets=true but node has no router; incoming_packet push disabled",
                peer
            );
        }
    }

    loop {
        let body = match read_frame(&mut read_half, max_frame_bytes).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                lp2ln_core_v2::info!("[IpcTcp] {} client closed TCP write side (clean EOF)", peer);
                break;
            }
            Err(e) => return Err(e.into()),
        };

        let text = std::str::from_utf8(&body).map_err(|e| anyhow::anyhow!("utf8: {}", e))?;
        let value: Value =
            serde_json::from_str(text).map_err(|e| anyhow::anyhow!("invalid json frame: {}", e))?;

        lp2ln_core_v2::info!(
            "[IpcTcp] {} recv {}",
            peer,
            ipc_recv_summary(body.len(), &value)
        );

        if value.get("cmd").and_then(|c| c.as_str()) == Some("ping") {
            let mut reply = json!({
                "event": "pong",
                "ts_ms": now_ms(),
            });
            attach_client_request_id(&mut reply, &value);
            lp2ln_core_v2::info!("[IpcTcp] {} reply {}", peer, ipc_reply_summary(&reply));
            if out_tx.send(reply.to_string().into_bytes()).await.is_err() {
                lp2ln_core_v2::warn!("[IpcTcp] {} out channel closed while sending pong", peer);
                break;
            }
            continue;
        }

        let reply = match debug_server::handle_client_command(
            text,
            node.clone(),
            db.clone(),
            experimental_content,
        )
        .await
        {
            Some(mut r) => {
                attach_client_request_id(&mut r, &value);
                r
            }
            None => {
                let mut err = json!({
                    "event": "error",
                    "ts_ms": now_ms(),
                    "message": "expected JSON object with string field cmd",
                });
                attach_client_request_id(&mut err, &value);
                err
            }
        };

        lp2ln_core_v2::info!("[IpcTcp] {} reply {}", peer, ipc_reply_summary(&reply));

        let bytes = reply.to_string().into_bytes();
        if bytes.len() > max_frame_bytes as usize {
            lp2ln_core_v2::warn!(
                "[IpcTcp] {} reply_json_len={} exceeds max_frame_bytes={}, sending trimmed error",
                peer,
                bytes.len(),
                max_frame_bytes
            );
            let mut err = json!({
                "event": "error",
                "ts_ms": now_ms(),
                "message": "reply exceeds max_frame_bytes",
            });
            attach_client_request_id(&mut err, &value);
            if out_tx.send(err.to_string().into_bytes()).await.is_err() {
                lp2ln_core_v2::warn!(
                    "[IpcTcp] {} out channel closed while sending oversize error",
                    peer
                );
                break;
            }
            continue;
        }
        if out_tx.send(bytes).await.is_err() {
            lp2ln_core_v2::warn!("[IpcTcp] {} out channel closed while sending reply", peer);
            break;
        }
    }

    lp2ln_core_v2::info!("[IpcTcp] {} session ended", peer);
    drop(out_tx);
    let _ = writer.await;
    if let Some(t) = push_task {
        t.abort();
    }
    Ok(())
}

fn attach_client_request_id(reply: &mut Value, request: &Value) {
    let Some(id) = request.get("client_request_id") else {
        return;
    };
    if let Some(obj) = reply.as_object_mut() {
        obj.insert("client_request_id".to_string(), id.clone());
    }
}

fn incoming_packet_json(ip: &IncomingPacket) -> Value {
    let data_b64 = STANDARD.encode(&ip.packet.data);
    let data_utf8 = std::str::from_utf8(&ip.packet.data)
        .ok()
        .map(|s| s.to_string());
    json!({
        "event": "incoming_packet",
        "ts_ms": now_ms(),
        "session_id": ip.session_id,
        "from_node": ip.from_node,
        "packet": {
            "sender": ip.packet.sender,
            "receiver": ip.packet.receiver,
            "request_id": ip.packet.request_id,
            "max_hops": ip.packet.max_hops,
            "signature": ip.packet.signature,
            "nodes": ip.packet.nodes,
            "chunk_stream_id": ip.packet.chunk_stream_id,
            "chunk_index": ip.packet.chunk_index,
            "total_chunks": ip.packet.total_chunks,
            "data_base64": data_b64,
            "data_utf8": data_utf8,
        },
    })
}

async fn read_frame(
    r: &mut tokio::net::tcp::OwnedReadHalf,
    max_frame_bytes: u32,
) -> std::io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).await?;
    let n = u32::from_be_bytes(hdr);
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "zero-length frame",
        ));
    }
    if n > max_frame_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "frame length {} exceeds max_frame_bytes {}",
                n, max_frame_bytes
            ),
        ));
    }
    let mut body = vec![0u8; n as usize];
    r.read_exact(&mut body).await?;
    Ok(body)
}

async fn write_frame(w: &mut tokio::net::tcp::OwnedWriteHalf, body: &[u8]) -> std::io::Result<()> {
    let n: u32 = body
        .len()
        .try_into()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large"))?;
    w.write_all(&n.to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
