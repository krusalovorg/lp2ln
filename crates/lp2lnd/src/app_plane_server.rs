// M2 — App Plane v2 binary IPC server (slice 09)
//
// EXPERIMENTAL (P0-04): not started by default `lp2lnd`. Reserved behind
// `options.experimental.app_plane` until P3/P4 lifecycle wiring.
//
// Listens on a separate TCP port. Each connection can subscribe to protocol_ids
// and send raw payloads without base64 encoding.
//
// Wire: 4-byte LE length prefix + postcard-encoded AppCmd / AppEvent.
// Slow consumers: try_send drops frames rather than blocking the router.

use std::net::SocketAddr;
use std::sync::Arc;

use lp2ln_core_v2::app_plane::{AppCmd, AppEvent, AppPlaneRouter, decode_cmd, encode_event};
use lp2ln_core_v2::node::NodeRuntime;
use lp2ln_core_v2::packet::Packet;
use lp2ln_core_v2::types::PeerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;

#[allow(dead_code)]
const MAX_FRAME: u32 = 16 * 1024 * 1024; // 16 MiB

#[allow(dead_code)]
pub async fn run(
    bind: SocketAddr,
    node: Arc<NodeRuntime>,
    router: Arc<lp2ln_core_v2::router::Router>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    let app_router = Arc::new(AppPlaneRouter::new());

    // Push task: broadcast → per-protocol routing
    {
        let app_router = app_router.clone();
        let mut sub = router.subscribe();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    msg = sub.recv() => match msg {
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
            }
        });
    }

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((stream, _peer)) = accepted else { continue };
                let node = node.clone();
                let app_router = app_router.clone();
                tokio::spawn(handle_connection(stream, node, app_router));
            }
        }
    }
    Ok(())
}

#[allow(dead_code)]
async fn handle_connection(
    mut stream: TcpStream,
    node: Arc<NodeRuntime>,
    app_router: Arc<AppPlaneRouter>,
) {
    let my_peer_id = node.peer_id().to_string();
    let mut subscriptions: Vec<u16> = Vec::new();

    loop {
        // Read 4-byte LE length prefix.
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let frame_len = u32::from_le_bytes(len_buf);
        if frame_len == 0 || frame_len > MAX_FRAME {
            break;
        }

        let mut body = vec![0u8; frame_len as usize];
        if stream.read_exact(&mut body).await.is_err() {
            break;
        }

        let cmd = match decode_cmd(&body) {
            Ok(c) => c,
            Err(_) => {
                let ack = encode_event(&AppEvent::Ack {
                    ok: false,
                    error: Some("bad frame".into()),
                });
                let _ = stream.write_all(&ack).await;
                continue;
            }
        };

        match cmd {
            AppCmd::Subscribe { protocol_id } => {
                if !subscriptions.contains(&protocol_id) {
                    subscriptions.push(protocol_id);
                    // ponytail: push to socket deferred — needs stream split (OwnedWriteHalf).
                    // Tracked in subscriptions; wired up when split is added in slice 09+.
                }
                let ack = encode_event(&AppEvent::Ack {
                    ok: true,
                    error: None,
                });
                if stream.write_all(&ack).await.is_err() {
                    break;
                }
            }
            AppCmd::Unsubscribe { protocol_id } => {
                subscriptions.retain(|&p| p != protocol_id);
                app_router.prune(protocol_id);
                let ack = encode_event(&AppEvent::Ack {
                    ok: true,
                    error: None,
                });
                if stream.write_all(&ack).await.is_err() {
                    break;
                }
            }
            AppCmd::Send {
                peer_id,
                protocol_id,
                payload,
            } => {
                let result =
                    send_app_packet(&node, &my_peer_id, &peer_id, protocol_id, payload).await;
                let ack = match result {
                    Ok(_) => encode_event(&AppEvent::Ack {
                        ok: true,
                        error: None,
                    }),
                    Err(e) => encode_event(&AppEvent::Ack {
                        ok: false,
                        error: Some(e.to_string()),
                    }),
                };
                if stream.write_all(&ack).await.is_err() {
                    break;
                }
            }
        }
    }

    // Cleanup: prune all subscriptions for this connection.
    for pid in subscriptions {
        app_router.prune(pid);
    }
}

#[allow(dead_code)]
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
