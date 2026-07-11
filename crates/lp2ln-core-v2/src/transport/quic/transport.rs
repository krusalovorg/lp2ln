use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::crypto::NodeKeypair;
use crate::event_core::prelude::CoreEvent;
use crate::sessions::Session;
use crate::sessions::session::LinkKind;
use crate::topology::PeerCatalog;
use crate::transport::quic::adaptive::AdaptiveLossConfig;
use crate::transport::quic::config::{
    MasqueradeConfig, QuicTransportOptions, build_client_config, build_server_config,
};
use crate::transport::quic::masquerade;
use crate::transport::quic::obfs::{QuicObfsMode, XorObfsSocket, derive_obfs_key_from_ecdh};
use crate::transport::quic::session::QuicSession;
use crate::transport::transport::TransportContext;
use crate::transport::{ACCEPT_TASK_JOIN_TIMEOUT, Transport, join_accept_task};
use crate::types::PeerId;
use anyhow::{Context, Result};
use async_trait::async_trait;
use quinn::Endpoint;
use tokio::sync::Mutex;
use tokio::sync::mpsc;

pub struct QuicTransport {
    listen_addr: SocketAddr,
    options: QuicTransportOptions,
    accept_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    endpoint: Arc<Mutex<Option<Arc<Endpoint>>>>,
    client_endpoint: Arc<Mutex<Option<Arc<Endpoint>>>>,
    is_listener: bool,
    client_config: quinn::ClientConfig,
    /// Set during start(); used by dial() to attach loss monitoring on outbound sessions.
    event_tx: Arc<Mutex<Option<mpsc::Sender<CoreEvent>>>>,
    /// Set during start(); used by dial_with_peer() to derive ECDH obfs key for Auto mode.
    keypair: Arc<Mutex<Option<Arc<NodeKeypair>>>>,
    catalog: Arc<Mutex<Option<Arc<PeerCatalog>>>>,
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
            event_tx: Arc::new(Mutex::new(None)),
            keypair: Arc::new(Mutex::new(None)),
            catalog: Arc::new(Mutex::new(None)),
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
            event_tx: Arc::new(Mutex::new(None)),
            keypair: Arc::new(Mutex::new(None)),
            catalog: Arc::new(Mutex::new(None)),
        }
    }

    async fn get_or_create_client_endpoint(&self) -> Result<Arc<Endpoint>> {
        if let Some(endpoint) = self.client_endpoint.lock().await.clone() {
            return Ok(endpoint);
        }
        let mut endpoint = if self.options.obfs.is_active() {
            let password = self.options.obfs.password.as_deref().unwrap();
            let runtime = quinn::default_runtime()
                .ok_or_else(|| anyhow::anyhow!("no async runtime for QUIC obfs client"))?;
            let std_sock = std::net::UdpSocket::bind("0.0.0.0:0")
                .context("bind QUIC obfs client socket")?;
            let inner = runtime
                .wrap_udp_socket(std_sock)
                .context("wrap QUIC obfs client socket")?;
            let obfs = Arc::new(XorObfsSocket::new(inner, password));
            Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                obfs,
                runtime,
            )
            .context("create QUIC obfs client endpoint")?
        } else {
            Endpoint::client("0.0.0.0:0".parse().expect("valid addr"))
                .context("create QUIC client endpoint")?
        };
        endpoint.set_default_client_config(self.client_config.clone());
        let endpoint = Arc::new(endpoint);
        *self.client_endpoint.lock().await = Some(endpoint.clone());
        Ok(endpoint)
    }
}

async fn register_session(
    endpoint: Arc<Endpoint>,
    connection: quinn::Connection,
    streams: (quinn::SendStream, quinn::RecvStream),
    remote: std::net::SocketAddr,
    incoming_sessions_tx: tokio::sync::mpsc::Sender<Arc<dyn Session>>,
    event_tx: Option<mpsc::Sender<CoreEvent>>,
    adaptive: Option<AdaptiveLossConfig>,
) {
    let (send, recv) = streams;
    match QuicSession::new_from_streams(
        endpoint,
        connection,
        send,
        recv,
        None,
        LinkKind::DirectQuic,
        event_tx,
        adaptive,
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

fn connection_alpn(conn: &quinn::Connection) -> Option<Vec<u8>> {
    use quinn::crypto::rustls::HandshakeData;
    conn.handshake_data()?
        .downcast::<HandshakeData>()
        .ok()
        .and_then(|d| d.protocol.clone())
}

async fn handle_incoming_connection(
    endpoint: Arc<Endpoint>,
    connection: quinn::Connection,
    incoming_sessions_tx: tokio::sync::mpsc::Sender<Arc<dyn Session>>,
    masquerade_config: Option<MasqueradeConfig>,
    event_tx: Option<mpsc::Sender<CoreEvent>>,
    adaptive: Option<AdaptiveLossConfig>,
) {
    let remote = connection.remote_address();
    let alpn = connection_alpn(&connection);

    // h3 ALPN: could be a DPI active probe or an LP2LN client using masquerade ALPN.
    // LP2LN always opens a bidi stream immediately; real h3 probes don't.
    if alpn.as_deref() == Some(b"h3") {
        match masquerade_config {
            Some(cfg) if cfg.enabled => {
                match tokio::time::timeout(Duration::from_millis(500), connection.accept_bi()).await {
                    Ok(Ok(streams)) => {
                        // LP2LN client — fall through to session creation with these streams
                        crate::info!("[QuicTransport] LP2LN client via h3 ALPN from {}", remote);
                        return register_session(
                            endpoint,
                            connection,
                            streams,
                            remote,
                            incoming_sessions_tx,
                            event_tx,
                            adaptive,
                        )
                        .await;
                    }
                    _ => {
                        crate::info!("[QuicTransport] h3 probe from {}, serving masquerade", remote);
                        masquerade::serve(connection, cfg).await;
                    }
                }
            }
            _ => {
                crate::warn!(
                    "[QuicTransport] h3 probe from {} but masquerade disabled, dropping",
                    remote
                );
                connection.close(0u32.into(), b"");
            }
        }
        return;
    }

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

    register_session(endpoint, connection, (send, recv), remote, incoming_sessions_tx, event_tx, adaptive).await;
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

        // Store context provided at startup for use by dial_with_peer().
        if let Some(ref tx) = ctx.event_tx {
            *self.event_tx.lock().await = Some(tx.clone());
        }
        if let Some(kp) = ctx.keypair {
            *self.keypair.lock().await = Some(kp);
        }
        if let Some(cat) = ctx.catalog {
            *self.catalog.lock().await = Some(cat);
        }

        let bind_addr = ctx.listen_addr.unwrap_or(self.listen_addr);
        let endpoint = Arc::new(if self.options.obfs.is_active() {
            let password = self.options.obfs.password.as_deref().unwrap();
            let runtime = quinn::default_runtime()
                .ok_or_else(|| anyhow::anyhow!("no async runtime for QUIC obfs listener"))?;
            let std_sock = std::net::UdpSocket::bind(bind_addr)
                .map_err(|e| anyhow::anyhow!("Failed to bind QUIC obfs on {bind_addr}: {e}"))?;
            let inner = runtime
                .wrap_udp_socket(std_sock)
                .context("wrap QUIC obfs server socket")?;
            let obfs = Arc::new(XorObfsSocket::new(inner, password));
            crate::info!("[QuicTransport] Starting with quic_initial_obfs on {}", bind_addr);
            Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                Some(server_config),
                obfs,
                runtime,
            )
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC obfs endpoint: {e}"))?
        } else {
            Endpoint::server(server_config, bind_addr)
                .map_err(|e| anyhow::anyhow!("Failed to bind QUIC on {bind_addr}: {e}"))?
        });
        let actual_addr = endpoint.local_addr()?;
        {
            let mut endpoint_guard = self.endpoint.lock().await;
            *endpoint_guard = Some(endpoint.clone());
        }

        let incoming_sessions_tx = ctx.incoming_sessions_tx.clone();
        let endpoint_for_accept = endpoint.clone();
        let masquerade_cfg = if self.options.masquerade.enabled {
            Some(self.options.masquerade.clone())
        } else {
            None
        };
        let adaptive = if self.options.adaptive_loss.enabled {
            Some(self.options.adaptive_loss.clone())
        } else {
            None
        };
        let event_tx = ctx.event_tx.clone();

        let accept_handle = tokio::spawn(async move {
            loop {
                let Some(incoming) = endpoint_for_accept.accept().await else {
                    break;
                };
                let incoming_sessions_tx = incoming_sessions_tx.clone();
                let endpoint = endpoint_for_accept.clone();
                let masquerade_cfg = masquerade_cfg.clone();
                let event_tx = event_tx.clone();
                let adaptive = adaptive.clone();
                tokio::spawn(async move {
                    let connection = match incoming.await {
                        Ok(conn) => conn,
                        Err(e) => {
                            crate::error!("[QuicTransport] Incoming connection failed: {}", e);
                            return;
                        }
                    };
                    handle_incoming_connection(
                        endpoint,
                        connection,
                        incoming_sessions_tx,
                        masquerade_cfg,
                        event_tx,
                        adaptive,
                    )
                    .await;
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
        self.event_tx.lock().await.take();

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
        let event_tx = self.event_tx.lock().await.clone();
        let adaptive = if self.options.adaptive_loss.enabled {
            Some(self.options.adaptive_loss.clone())
        } else {
            None
        };
        let session = QuicSession::new_from_streams(
            endpoint,
            connection,
            send,
            recv,
            None,
            LinkKind::DirectQuic,
            event_tx,
            adaptive,
        )?;
        crate::info!("[QuicTransport] Session created for {}", addr);
        Ok(session as Arc<dyn Session>)
    }

    async fn dial_with_peer(&self, addr: SocketAddr, peer_id: Option<&str>) -> Result<Arc<dyn Session>> {
        // Auto mode: derive per-peer ECDH obfs key if we know the peer and they support it.
        if let (QuicObfsMode::Auto, Some(pid)) = (&self.options.obfs.mode, peer_id) {
            let keypair = self.keypair.lock().await.clone();
            if let Some(kp) = keypair {
                let catalog = self.catalog.lock().await.clone();
                let supported = catalog
                    .as_ref()
                    .map(|c| c.quic_obfs_supported(&PeerId::from(pid)))
                    .unwrap_or(false);
                if supported {
                    let key = derive_obfs_key_from_ecdh(kp.signing_key(), pid)
                        .context("derive ECDH obfs key for dial")?;
                    return self.dial_with_obfs_key(addr, key).await;
                }
            }
        }
        self.dial(addr).await
    }
}

impl QuicTransport {
    async fn dial_with_obfs_key(&self, addr: SocketAddr, key: [u8; 32]) -> Result<Arc<dyn Session>> {
        let runtime = quinn::default_runtime()
            .ok_or_else(|| anyhow::anyhow!("no async runtime for QUIC obfs dial"))?;
        let std_sock = std::net::UdpSocket::bind("0.0.0.0:0")
            .context("bind QUIC obfs dial socket")?;
        let inner = runtime
            .wrap_udp_socket(std_sock)
            .context("wrap QUIC obfs dial socket")?;
        let obfs = Arc::new(XorObfsSocket::new_with_key(inner, key));
        let mut endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            obfs,
            runtime,
        )
        .context("create QUIC obfs dial endpoint")?;
        endpoint.set_default_client_config(self.client_config.clone());
        let endpoint = Arc::new(endpoint);
        let connection = endpoint
            .connect(addr, "lp2ln.local")
            .context(format!("quic obfs connect {}", addr))?
            .await
            .with_context(|| format!("quic obfs handshake {}", addr))?;
        let (send, recv) = connection.open_bi().await.context("open QUIC obfs bidi stream")?;
        let event_tx = self.event_tx.lock().await.clone();
        let adaptive = if self.options.adaptive_loss.enabled {
            Some(self.options.adaptive_loss.clone())
        } else {
            None
        };
        let session = QuicSession::new_from_streams(
            endpoint, connection, send, recv, None, LinkKind::DirectQuic, event_tx, adaptive,
        )?;
        crate::info!("[QuicTransport] Obfs session (ECDH) created for {}", addr);
        Ok(session as Arc<dyn Session>)
    }
}
