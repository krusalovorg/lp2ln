use crate::router::admission::{IngressBudget, IngressPermit};
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
    ENDPOINT_PENDING_CREDIT, MasqueradeConfig, QuicTransportOptions, build_client_config,
    build_server_config, native_connection_charge,
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

struct RealtimeService {
    authorized: std::sync::Mutex<std::collections::HashSet<(String, u16)>>,
    slots: Arc<tokio::sync::Semaphore>,
    tx: mpsc::Sender<crate::flow::Flow>,
    rx: Mutex<mpsc::Receiver<crate::flow::Flow>>,
    stop: tokio_util::sync::CancellationToken,
    tasks: tokio_util::task::TaskTracker,
}

impl RealtimeService {
    fn new() -> Arc<Self> {
        let (tx, rx) = mpsc::channel(16);
        Arc::new(Self {
            authorized: std::sync::Mutex::new(std::collections::HashSet::new()),
            slots: Arc::new(tokio::sync::Semaphore::new(32)),
            tx,
            rx: Mutex::new(rx),
            stop: tokio_util::sync::CancellationToken::new(),
            tasks: tokio_util::task::TaskTracker::new(),
        })
    }

    fn permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit> {
        Ok(self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| crate::flow::FlowError::QueueFull)?)
    }

    async fn shutdown(&self) {
        self.stop.cancel();
        self.slots.close();
        let mut rx = self.rx.lock().await;
        rx.close();
        while rx.try_recv().is_ok() {}
        self.tasks.close();
        self.tasks.wait().await;
    }
}

pub struct QuicTransport {
    receive_budget: std::sync::Mutex<Option<crate::transport::TransportReceiveBudget>>,
    realtime: Arc<RealtimeService>,
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
            receive_budget: std::sync::Mutex::new(None),
            realtime: RealtimeService::new(),
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
            receive_budget: std::sync::Mutex::new(None),
            realtime: RealtimeService::new(),
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

    pub(super) fn receive_ledger(&self) -> Option<Arc<IngressBudget>> {
        self.receive_budget
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|b| b.get())
    }

    fn reserve_connection(&self) -> Result<Option<IngressPermit>> {
        self.receive_ledger()
            .map(|budget| {
                budget
                    .native(native_connection_charge(&self.options))
                    .context("QUIC receive credit exhausted")
            })
            .transpose()
    }

    async fn get_or_create_client_endpoint(&self) -> Result<Arc<Endpoint>> {
        let mut slot = self.client_endpoint.lock().await;
        if let Some(endpoint) = slot.as_ref() {
            return Ok(endpoint.clone());
        }
        let mut endpoint = if self.options.obfs.is_active() {
            let password = self.options.obfs.password.as_deref().unwrap();
            let runtime = quinn::default_runtime()
                .ok_or_else(|| anyhow::anyhow!("no async runtime for QUIC obfs client"))?;
            let std_sock =
                std::net::UdpSocket::bind("0.0.0.0:0").context("bind QUIC obfs client socket")?;
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
        *slot = Some(endpoint.clone());
        Ok(endpoint)
    }
}

const INCOMING_HANDSHAKE_LIMIT: usize = 64;
const INCOMING_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

async fn register_session(
    endpoint: Arc<Endpoint>,
    connection: quinn::Connection,
    streams: (quinn::SendStream, quinn::RecvStream),
    remote: std::net::SocketAddr,
    incoming_sessions_tx: tokio::sync::mpsc::Sender<Arc<dyn Session>>,
    event_tx: Option<mpsc::Sender<CoreEvent>>,
    adaptive: Option<AdaptiveLossConfig>,
    credit: Option<IngressPermit>,
) {
    let Ok(Ok(slot)) =
        tokio::time::timeout(INCOMING_HANDSHAKE_TIMEOUT, incoming_sessions_tx.reserve()).await
    else {
        connection.close(0u32.into(), b"incoming session unavailable");
        return;
    };
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
            session.hold_receive_credit(credit);
            slot.send(session.clone() as Arc<dyn Session>);
            crate::session!(
                "[QuicTransport] Session registered: {} (peer_id: {:?})",
                session.id(),
                session.peer_id()
            );
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
    credit: Option<IngressPermit>,
) {
    let remote = connection.remote_address();
    let alpn = connection_alpn(&connection);

    // h3 ALPN: could be a DPI active probe or an LP2LN client using masquerade ALPN.
    // LP2LN always opens a bidi stream immediately; real h3 probes don't.
    if alpn.as_deref() == Some(b"h3") {
        match masquerade_config {
            Some(cfg) if cfg.enabled => {
                match tokio::time::timeout(Duration::from_millis(500), connection.accept_bi()).await
                {
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
                            credit,
                        )
                        .await;
                    }
                    _ => {
                        crate::info!(
                            "[QuicTransport] h3 probe from {}, serving masquerade",
                            remote
                        );
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

    let (send, recv) =
        match tokio::time::timeout(INCOMING_HANDSHAKE_TIMEOUT, connection.accept_bi()).await {
            Ok(Ok(streams)) => {
                crate::info!("[QuicTransport] Accepted bidi stream from {}", remote);
                streams
            }
            Ok(Err(e)) => {
                crate::error!(
                    "[QuicTransport] Failed to accept bidi stream from {}: {}",
                    remote,
                    e
                );
                return;
            }
            Err(_) => {
                connection.close(0u32.into(), b"first stream timed out");
                return;
            }
        };

    register_session(
        endpoint,
        connection,
        (send, recv),
        remote,
        incoming_sessions_tx,
        event_tx,
        adaptive,
        credit,
    )
    .await;
}

#[async_trait]
impl Transport for QuicTransport {
    fn bind_receive_budget(&self, budget: crate::transport::TransportReceiveBudget) -> Result<()> {
        let mut current = self.receive_budget.lock().unwrap();
        if let Some(active) = current.as_ref().and_then(|b| b.get()) {
            anyhow::ensure!(
                budget.get().is_some_and(|new| Arc::ptr_eq(&active, &new)),
                "transport already bound to another node"
            );
        }
        *current = Some(budget);
        Ok(())
    }

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

        let flow_identity = ctx.keypair.clone();
        let flows = self.realtime.clone();
        let flows_enabled = self.options.enable_realtime_flows;

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

        let shared = self.receive_ledger();
        let receive_charge = native_connection_charge(&self.options);
        let pending_credit = shared
            .as_ref()
            .map(|b| {
                b.native(ENDPOINT_PENDING_CREDIT as usize)
                    .context("QUIC listener receive credit exhausted")
            })
            .transpose()?;
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
            crate::info!(
                "[QuicTransport] Starting with quic_initial_obfs on {}",
                bind_addr
            );
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
            let _pending_credit = pending_credit;
            let mut handshakes = tokio::task::JoinSet::new();
            loop {
                let incoming = tokio::select! {
                    _ = handshakes.join_next(), if !handshakes.is_empty() => continue,
                    incoming = endpoint_for_accept.accept() => match incoming {
                        Some(incoming) => incoming,
                        None => break,
                    },
                };
                if handshakes.len() >= INCOMING_HANDSHAKE_LIMIT {
                    incoming.refuse();
                    continue;
                }
                let (credit, pre_auth) = match &shared {
                    Some(b) => {
                        let Some(credit) = b.native(receive_charge) else {
                            incoming.refuse();
                            continue;
                        };
                        let Some(pre_auth) = b.pre_auth(64 * 1024) else {
                            incoming.refuse();
                            continue;
                        };
                        (Some(credit), Some(pre_auth))
                    }
                    None => (None, None),
                };
                let incoming_sessions_tx = incoming_sessions_tx.clone();
                let endpoint = endpoint_for_accept.clone();
                let masquerade_cfg = masquerade_cfg.clone();
                let event_tx = event_tx.clone();
                let adaptive = adaptive.clone();
                let flow_identity = flow_identity.clone();
                let flows = flows.clone();
                let flow_ledger = shared.clone();
                handshakes.spawn(async move {
                    let connection =
                        match tokio::time::timeout(INCOMING_HANDSHAKE_TIMEOUT, incoming).await {
                            Ok(Ok(conn)) => conn,
                            Ok(Err(e)) => {
                                crate::error!("[QuicTransport] Incoming connection failed: {}", e);
                                return;
                            }
                            Err(_) => return,
                        };
                    if connection_alpn(&connection).as_deref() == Some(crate::flow::security::ALPN)
                    {
                        let outcome = async {
                            anyhow::ensure!(
                                flows_enabled && !flows.stop.is_cancelled(),
                                "realtime disabled"
                            );
                            let budget = flow_ledger.context("missing managed realtime budget")?;
                            let identity = flow_identity.context("missing realtime identity")?;
                            let _establishing = flows.tasks.token();
                            let slots = flows.permit()?;
                            // Do not fill the accept queue while a peer is still unverified.
                            let flow = crate::flow::establish(
                                endpoint,
                                connection.clone(),
                                identity,
                                None,
                                |peer, protocol| {
                                    flows
                                        .authorized
                                        .lock()
                                        .unwrap()
                                        .contains(&(peer.to_owned(), protocol))
                                },
                                crate::flow::FlowLifetime {
                                    budget,
                                    native: credit,
                                    pre_auth,
                                    end: flows.stop.clone(),
                                    tasks: flows.tasks.clone(),
                                    slots,
                                },
                            )
                            .await?;
                            flows
                                .tx
                                .try_send(flow)
                                .map_err(|_| crate::flow::FlowError::QueueFull)?;
                            Ok::<_, anyhow::Error>(())
                        }
                        .await;
                        if outcome.is_err() {
                            connection.close(1u32.into(), b"flow rejected");
                        }
                        return;
                    }
                    let _pre_auth = pre_auth;
                    handle_incoming_connection(
                        endpoint,
                        connection,
                        incoming_sessions_tx,
                        masquerade_cfg,
                        event_tx,
                        adaptive,
                        credit,
                    )
                    .await;
                });
            }
            handshakes.shutdown().await;
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
        self.realtime.shutdown().await;
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

    fn authorize_realtime(&self, peer: &PeerId, protocol: u16) -> Result<()> {
        anyhow::ensure!(
            self.options.enable_realtime_flows && self.is_listener,
            "Flow listener disabled"
        );
        anyhow::ensure!(peer.as_str().len() == 66, "invalid Flow Peer ID length");
        let mut policies = self.realtime.authorized.lock().unwrap();
        let entry = (peer.as_str().to_owned(), protocol);
        anyhow::ensure!(
            policies.contains(&entry) || policies.len() < 1024,
            "Flow authorization table full"
        );
        policies.insert(entry);
        Ok(())
    }

    fn revoke_realtime(&self, peer: &PeerId, protocol: u16) -> Result<()> {
        self.realtime
            .authorized
            .lock()
            .unwrap()
            .remove(&(peer.as_str().to_owned(), protocol));
        Ok(())
    }

    async fn open_realtime(
        &self,
        identity: Arc<NodeKeypair>,
        peer: &PeerId,
        addr: SocketAddr,
        protocol: u16,
    ) -> Result<crate::flow::Flow> {
        if !self.options.enable_realtime_flows {
            return Err(crate::flow::FlowError::Unsupported.into());
        }
        let flows = &self.realtime;
        let _establishing = flows.tasks.token();
        anyhow::ensure!(!flows.stop.is_cancelled(), "Flow transport stopped");
        let slots = flows.permit()?;
        let native = self.reserve_connection()?;
        let budget = self
            .receive_ledger()
            .context("missing managed realtime budget")?;
        let pre_auth = budget
            .pre_auth(64 * 1024)
            .ok_or(crate::flow::FlowError::QueueFull)?;
        let endpoint = self.get_or_create_client_endpoint().await?;
        let config = super::config::build_flow_client_config(&self.options)?;
        let connecting = endpoint.connect_with(config, addr, "lp2ln.local")?;
        let connection = tokio::select! {
            _ = flows.stop.cancelled() => return Err(crate::flow::FlowError::Closed.into()),
            result = tokio::time::timeout(crate::flow::HANDSHAKE_TIMEOUT, connecting) => result??,
        };
        anyhow::ensure!(
            connection_alpn(&connection).as_deref() == Some(crate::flow::security::ALPN),
            "Flow ALPN not negotiated"
        );
        crate::flow::establish(
            endpoint,
            connection,
            identity,
            Some(crate::flow::FlowRequest {
                peer: peer.as_str(),
                protocol,
            }),
            |_, _| false,
            crate::flow::FlowLifetime {
                budget,
                native,
                pre_auth: Some(pre_auth),
                end: flows.stop.clone(),
                tasks: flows.tasks.clone(),
                slots,
            },
        )
        .await
    }

    async fn accept_realtime(&self) -> Result<crate::flow::Flow> {
        if !self.options.enable_realtime_flows || !self.is_listener {
            return Err(crate::flow::FlowError::Unsupported.into());
        }
        let mut rx = self.realtime.rx.lock().await;
        tokio::select! {
            biased;
            _ = self.realtime.stop.cancelled() => Err(crate::flow::FlowError::Closed.into()),
            result = rx.recv() => result.ok_or(crate::flow::FlowError::Closed.into())
        }
    }

    async fn dial(&self, addr: SocketAddr) -> Result<Arc<dyn Session>> {
        crate::info!("[QuicTransport] Dialing {}", addr);
        let credit = self.reserve_connection()?;
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
        session.hold_receive_credit(credit);
        crate::info!("[QuicTransport] Session created for {}", addr);
        Ok(session as Arc<dyn Session>)
    }

    async fn dial_with_peer(
        &self,
        addr: SocketAddr,
        peer_id: Option<&str>,
    ) -> Result<Arc<dyn Session>> {
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
    async fn dial_with_obfs_key(
        &self,
        addr: SocketAddr,
        key: [u8; 32],
    ) -> Result<Arc<dyn Session>> {
        let credit = self.reserve_connection()?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| anyhow::anyhow!("no async runtime for QUIC obfs dial"))?;
        let std_sock =
            std::net::UdpSocket::bind("0.0.0.0:0").context("bind QUIC obfs dial socket")?;
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
        let (send, recv) = connection
            .open_bi()
            .await
            .context("open QUIC obfs bidi stream")?;
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
        crate::info!("[QuicTransport] Obfs session (ECDH) created for {}", addr);
        session.hold_receive_credit(credit);
        Ok(session as Arc<dyn Session>)
    }
}
