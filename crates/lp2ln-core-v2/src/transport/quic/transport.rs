use std::net::SocketAddr;
use std::sync::Arc;

use crate::sessions::Session;
use crate::sessions::session::LinkKind;
use crate::transport::quic::config::{QuicTransportOptions, build_client_config, build_server_config};
use crate::transport::quic::session::QuicSession;
use crate::transport::transport::TransportContext;
use crate::transport::{
    ACCEPT_TASK_JOIN_TIMEOUT, Transport, join_accept_task,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use quinn::Endpoint;
use tokio::sync::Mutex;

pub struct QuicTransport {
    listen_addr: SocketAddr,
    options: QuicTransportOptions,
    accept_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    endpoint: Arc<Mutex<Option<Arc<Endpoint>>>>,
    client_endpoint: Arc<Mutex<Option<Arc<Endpoint>>>>,
    is_listener: bool,
    client_config: quinn::ClientConfig,
}

impl QuicTransport {
    pub fn new_listener(listen_addr: Option<SocketAddr>, options: QuicTransportOptions) -> Self {
        let client_config = build_client_config(&options).expect("valid QUIC client config");
        Self {
            listen_addr: listen_addr.unwrap_or_else(|| "0.0.0.0:443".parse().expect("valid addr")),
            options,
            accept_task: Arc::new(Mutex::new(None)),
            endpoint: Arc::new(Mutex::new(None)),
            client_endpoint: Arc::new(Mutex::new(None)),
            is_listener: true,
            client_config,
        }
    }

    pub fn new_dial(options: QuicTransportOptions) -> Self {
        let client_config = build_client_config(&options).expect("valid QUIC client config");
        Self {
            listen_addr: "0.0.0.0:0".parse().expect("valid addr"),
            options,
            accept_task: Arc::new(Mutex::new(None)),
            endpoint: Arc::new(Mutex::new(None)),
            client_endpoint: Arc::new(Mutex::new(None)),
            is_listener: false,
            client_config,
        }
    }

    async fn get_or_create_client_endpoint(&self) -> Result<Arc<Endpoint>> {
        if let Some(endpoint) = self.client_endpoint.lock().await.clone() {
            return Ok(endpoint);
        }
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().expect("valid addr"))
            .context("create QUIC client endpoint")?;
        endpoint.set_default_client_config(self.client_config.clone());
        let endpoint = Arc::new(endpoint);
        *self.client_endpoint.lock().await = Some(endpoint.clone());
        Ok(endpoint)
    }
}

async fn handle_incoming_connection(
    endpoint: Arc<Endpoint>,
    connection: quinn::Connection,
    incoming_sessions_tx: tokio::sync::mpsc::Sender<Arc<dyn Session>>,
) {
    let remote = connection.remote_address();
    crate::info!("[QuicTransport] New incoming connection from {}", remote);

    let (send, recv) = match connection.accept_bi().await {
        Ok(streams) => {
            crate::info!("[QuicTransport] Accepted bidi stream from {}", remote);
            streams
        }
        Err(e) => {
            crate::error!(
                "[QuicTransport] Failed to accept bidi stream from {}: {}",
                remote,
                e
            );
            return;
        }
    };

    match QuicSession::new_from_streams(
        endpoint,
        connection,
        send,
        recv,
        None,
        LinkKind::DirectQuic,
    ) {
        Ok(session) => {
            if incoming_sessions_tx
                .send(session.clone() as Arc<dyn Session>)
                .await
                .is_ok()
            {
                crate::session!(
                    "[QuicTransport] Session registered: {} (peer_id: {:?})",
                    session.id(),
                    session.peer_id()
                );
            } else {
                crate::error!("[QuicTransport] Failed to send incoming session: channel closed");
            }
        }
        Err(e) => {
            crate::error!(
                "[QuicTransport] Failed to create session from {}: {}",
                remote,
                e
            );
        }
    }
}

#[async_trait]
impl Transport for QuicTransport {
    fn name(&self) -> &'static str {
        "quic"
    }

    fn is_listener(&self) -> bool {
        self.is_listener
    }

    async fn start(&self, ctx: TransportContext) -> Result<Option<SocketAddr>> {
        if !self.is_listener {
            return Ok(None);
        }
        {
            let accept_task_guard = self.accept_task.lock().await;
            if accept_task_guard.is_some() {
                return Err(anyhow::anyhow!("QuicTransport is already started"));
            }
        }

        let server_config = build_server_config(&self.options)
            .map_err(|e| anyhow::anyhow!("failed to build QUIC server config: {e}"))?;

        let bind_addr = ctx.listen_addr.unwrap_or(self.listen_addr);
        let endpoint = Arc::new(
            Endpoint::server(server_config, bind_addr)
                .map_err(|e| anyhow::anyhow!("Failed to bind QUIC on {bind_addr}: {e}"))?,
        );
        let actual_addr = endpoint.local_addr()?;
        {
            let mut endpoint_guard = self.endpoint.lock().await;
            *endpoint_guard = Some(endpoint.clone());
        }

        let incoming_sessions_tx = ctx.incoming_sessions_tx.clone();
        let endpoint_for_accept = endpoint.clone();
        let accept_handle = tokio::spawn(async move {
            loop {
                let Some(incoming) = endpoint_for_accept.accept().await else {
                    break;
                };
                let incoming_sessions_tx = incoming_sessions_tx.clone();
                let endpoint = endpoint_for_accept.clone();
                tokio::spawn(async move {
                    let connection = match incoming.await {
                        Ok(conn) => conn,
                        Err(e) => {
                            crate::error!("[QuicTransport] Incoming connection failed: {}", e);
                            return;
                        }
                    };
                    handle_incoming_connection(endpoint, connection, incoming_sessions_tx).await;
                });
            }
        });

        {
            let mut accept_task_guard = self.accept_task.lock().await;
            *accept_task_guard = Some(accept_handle);
        }

        Ok(Some(actual_addr))
    }

    async fn stop(&self) -> Result<()> {
        if let Some(endpoint) = self.endpoint.lock().await.take() {
            endpoint.close(0u32.into(), b"transport stopped");
        }
        self.client_endpoint.lock().await.take();

        let accept_handle = {
            let mut accept_task_guard = self.accept_task.lock().await;
            accept_task_guard.take()
        };
        join_accept_task("QuicTransport", accept_handle, ACCEPT_TASK_JOIN_TIMEOUT).await;
        crate::info!("[QuicTransport] Stopped");
        Ok(())
    }

    async fn dial(&self, addr: SocketAddr) -> Result<Arc<dyn Session>> {
        crate::info!("[QuicTransport] Dialing {}", addr);
        let endpoint = self.get_or_create_client_endpoint().await?;
        let connecting = endpoint
            .connect(addr, "lp2ln.local")
            .context(format!("quic connect {}", addr))?;
        let connection = connecting
            .await
            .with_context(|| format!("quic handshake {}", addr))?;
        let (send, recv) = connection
            .open_bi()
            .await
            .context("open QUIC bidi stream")?;
        let session = QuicSession::new_from_streams(
            endpoint,
            connection,
            send,
            recv,
            None,
            LinkKind::DirectQuic,
        )?;
        crate::info!("[QuicTransport] Session created for {}", addr);
        Ok(session as Arc<dyn Session>)
    }
}
