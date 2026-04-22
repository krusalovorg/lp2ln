use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::{NodeRuntime, RuntimeMode};

pub fn spawn_health_server(
    node: Arc<NodeRuntime>,
    requested_addr: Option<SocketAddr>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let start_addr = requested_addr.unwrap_or_else(|| {
            std::env::var("LP2LND_HEALTH_ADDR")
                .ok()
                .and_then(|v| v.parse::<SocketAddr>().ok())
                .unwrap_or_else(|| "127.0.0.1:9088".parse().expect("valid default health addr"))
        });

        let mut bind_addr = start_addr;
        let listener = loop {
            match TcpListener::bind(bind_addr).await {
                Ok(v) => break v,
                Err(err) => {
                    let next_port = bind_addr.port().saturating_add(1);
                    if next_port == bind_addr.port() || next_port > start_addr.port().saturating_add(20)
                    {
                        crate::error!(
                            "[HealthServer] bind {} failed and no fallback ports left: {}",
                            bind_addr,
                            err
                        );
                        return;
                    }
                    crate::warn!(
                        "[HealthServer] bind {} failed: {}. Retrying on {}:{}",
                        bind_addr,
                        err,
                        bind_addr.ip(),
                        next_port
                    );
                    bind_addr = SocketAddr::new(bind_addr.ip(), next_port);
                }
            }
        };
        crate::info!("[HealthServer] listening on http://{}", bind_addr);

        loop {
            let (mut socket, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(err) => {
                    crate::warn!("[HealthServer] accept failed: {}", err);
                    continue;
                }
            };
            let node = node.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let read = match socket.read(&mut buf).await {
                    Ok(v) => v,
                    Err(err) => {
                        crate::warn!("[HealthServer] read from {} failed: {}", peer, err);
                        return;
                    }
                };
                if read == 0 {
                    return;
                }
                let req = String::from_utf8_lossy(&buf[..read]);
                let first_line = req.lines().next().unwrap_or_default();
                let path = first_line.split_whitespace().nth(1).unwrap_or("/");
                let snap = node.health_snapshot();
                let body = match path {
                    "/livez" => json!({"status": "alive", "peer_id": node.peer_id()}),
                    "/readyz" => json!({
                        "status": if snap.mode == RuntimeMode::Normal { "ready" } else { "degraded" },
                        "peer_id": node.peer_id(),
                        "mode": format!("{:?}", snap.mode),
                        "last_error": snap.last_error,
                    }),
                    _ => json!({
                        "peer_id": node.peer_id(),
                        "mode": format!("{:?}", snap.mode),
                        "router_restarts": snap.router_restarts,
                        "transport_restarts": snap.transport_restarts,
                        "incoming_restarts": snap.incoming_restarts,
                        "topology_restarts": snap.topology_restarts,
                        "last_error": snap.last_error,
                    }),
                };
                let body = body.to_string();
                let status = if path == "/readyz" && snap.mode == RuntimeMode::Degraded {
                    "503 Service Unavailable"
                } else {
                    "200 OK"
                };
                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    })
}
