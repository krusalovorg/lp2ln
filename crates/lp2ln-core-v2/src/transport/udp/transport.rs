use crate::sessions::Session;
use crate::sessions::session::LinkKind;
use crate::stun::StunClient;
use crate::transport::obfuscation::{ObfuscationConfig, Obfuscator};
use crate::transport::transport::{PublicAddress, TransportContext, TunnelPunchParams};
use crate::transport::udp::session::UdpSession;
use crate::transport::{
    ACCEPT_TASK_JOIN_TIMEOUT, Transport, bind_with_port_fallback, join_accept_task,
};
use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};

pub struct UdpTransport {
    listen_addr: SocketAddr,
    shutdown_tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    accept_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    stun_client: StunClient,
    is_listener: bool,
    obfuscator: Arc<Obfuscator>,
}

impl UdpTransport {
    pub fn new() -> Self {
        Self {
            listen_addr: "0.0.0.0:0".parse().expect("valid socket addr"),
            shutdown_tx: Arc::new(Mutex::new(None)),
            accept_task: Arc::new(Mutex::new(None)),
            stun_client: StunClient::new(),
            is_listener: true,
            obfuscator: Arc::new(Obfuscator::plain()),
        }
    }

    pub fn new_listener(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            shutdown_tx: Arc::new(Mutex::new(None)),
            accept_task: Arc::new(Mutex::new(None)),
            stun_client: StunClient::new(),
            is_listener: true,
            obfuscator: Arc::new(Obfuscator::plain()),
        }
    }

    pub fn new_dial() -> Self {
        Self {
            listen_addr: "0.0.0.0:0".parse().expect("valid socket addr"),
            shutdown_tx: Arc::new(Mutex::new(None)),
            accept_task: Arc::new(Mutex::new(None)),
            stun_client: StunClient::new(),
            is_listener: false,
            obfuscator: Arc::new(Obfuscator::plain()),
        }
    }

    pub fn new_listener_with_obfuscation(
        listen_addr: SocketAddr,
        config: ObfuscationConfig,
    ) -> Self {
        Self {
            listen_addr,
            shutdown_tx: Arc::new(Mutex::new(None)),
            accept_task: Arc::new(Mutex::new(None)),
            stun_client: StunClient::new(),
            is_listener: true,
            obfuscator: Arc::new(Obfuscator::from_config(config)),
        }
    }

    pub fn new_dial_with_obfuscation(config: ObfuscationConfig) -> Self {
        Self {
            listen_addr: "0.0.0.0:0".parse().expect("valid socket addr"),
            shutdown_tx: Arc::new(Mutex::new(None)),
            accept_task: Arc::new(Mutex::new(None)),
            stun_client: StunClient::new(),
            is_listener: false,
            obfuscator: Arc::new(Obfuscator::from_config(config)),
        }
    }
}

#[async_trait]
impl Transport for UdpTransport {
    fn name(&self) -> &'static str {
        "udp"
    }

    fn is_listener(&self) -> bool {
        self.is_listener
    }

    async fn start(&self, ctx: TransportContext) -> Result<Option<SocketAddr>> {
        if !self.is_listener {
            return Ok(None);
        }
        {
            let shutdown_tx_guard = self.shutdown_tx.lock().await;
            if shutdown_tx_guard.is_some() {
                return Err(anyhow::anyhow!("UdpTransport is already started"));
            }
        }

        let bind_addr = ctx.listen_addr.unwrap_or(self.listen_addr);
        let (socket, actual_addr) = bind_with_port_fallback(bind_addr, |addr| async move {
            let socket = UdpSocket::bind(addr).await?;
            let actual = socket.local_addr()?;
            Ok((socket, actual))
        })
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind UDP: {}", e))?;
        if actual_addr != bind_addr {
            crate::info!(
                "[UdpTransport] Port {} busy, bound to {}",
                bind_addr.port(),
                actual_addr.port()
            );
        }

        let socket = Arc::new(socket);
        let socket_clone = socket.clone();
        let incoming_sessions_tx = ctx.incoming_sessions_tx.clone();
        let obfuscator = self.obfuscator.clone();

        let sessions: Arc<
            tokio::sync::Mutex<std::collections::HashMap<SocketAddr, Arc<dyn Session>>>,
        > = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        let sessions_clone = sessions.clone();

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        {
            let mut shutdown_tx_guard = self.shutdown_tx.lock().await;
            *shutdown_tx_guard = Some(shutdown_tx);
        }

        let accept_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65507];

            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        crate::info!("[UdpTransport] Listener shutting down");
                        break;
                    }
                    result = socket_clone.recv_from(&mut buf) => {
                        match result {
                            Ok((_size, peer_addr)) => {
                                let needs_new_session = {
                                    let sessions_guard = sessions_clone.lock().await;
                                    !sessions_guard.contains_key(&peer_addr)
                                };

                                if needs_new_session {
                                    match UdpSession::new_from_socket(
                                        socket_clone.clone(),
                                        peer_addr,
                                        None,
                                        LinkKind::DirectUdp,
                                        obfuscator.clone(),
                                    ) {
                                        Ok(session) => {
                                            crate::info!("[UdpTransport] New session from {}", peer_addr);

                                            let session_dyn = session.clone() as Arc<dyn Session>;
                                            match incoming_sessions_tx.send(session_dyn.clone()).await {
                                                Ok(()) => {
                                                    let mut sessions_guard = sessions_clone.lock().await;
                                                    if !sessions_guard.contains_key(&peer_addr) {
                                                        sessions_guard.insert(peer_addr, session_dyn);
                                                        crate::session!("[UdpTransport] Session registered: {}", session.id());
                                                    }
                                                }
                                                Err(_) => {
                                                    crate::error!("[UdpTransport] Failed to send incoming session: channel closed");
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            crate::error!("[UdpTransport] Failed to create session: {}", e);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                crate::error!("[UdpTransport] Error receiving datagram: {}", e);
                            }
                        }
                    }
                }
            }
        });

        {
            let mut accept_task_guard = self.accept_task.lock().await;
            *accept_task_guard = Some(accept_handle);
        }

        Ok(Some(actual_addr))
    }

    async fn stop(&self) -> Result<()> {
        let shutdown_tx = {
            let mut shutdown_tx_guard = self.shutdown_tx.lock().await;
            shutdown_tx_guard.take()
        };

        if let Some(shutdown_tx) = shutdown_tx {
            let _ = shutdown_tx.send(());
        } else {
            crate::info!("[UdpTransport] Already stopped or not started");
        }

        let accept_handle = {
            let mut accept_task_guard = self.accept_task.lock().await;
            accept_task_guard.take()
        };
        join_accept_task("UdpTransport", accept_handle, ACCEPT_TASK_JOIN_TIMEOUT).await;
        crate::info!("[UdpTransport] Stopped");

        Ok(())
    }

    async fn dial(&self, addr: SocketAddr) -> Result<Arc<dyn Session>> {
        crate::info!("[UdpTransport] Dialing {}", addr);

        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind UDP socket: {}", e))?;

        let socket = Arc::new(socket);

        let session = UdpSession::new_from_socket(
            socket,
            addr,
            None,
            LinkKind::DirectUdp,
            self.obfuscator.clone(),
        )?;

        crate::info!("[UdpTransport] Session created for {}", addr);

        Ok(session.clone() as Arc<dyn Session>)
    }

    fn supports_tunneling(&self) -> bool {
        true
    }

    async fn get_public_address(&self, local_port: u16) -> Result<PublicAddress> {
        crate::info!(
            "[UdpTransport] Getting public address via STUN for port {}",
            local_port
        );

        let (ip, port) = self
            .stun_client
            .get_public_address(local_port)
            .await
            .map_err(|e| anyhow::anyhow!("STUN lookup failed: {}", e))?;

        Ok(PublicAddress { ip, port })
    }

    async fn punch_tunnel(&self, params: TunnelPunchParams) -> Result<Arc<dyn Session>> {
        crate::info!(
            "[UdpTransport] Punching tunnel to {}:{}",
            params.target_ip,
            params.target_port
        );

        let target_addr: SocketAddr = format!("{}:{}", params.target_ip, params.target_port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid target address: {}", e))?;

        let local_port = self.listen_addr.port();

        let socket = UdpSocket::bind(format!("0.0.0.0:{}", local_port))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind UDP socket for tunnel: {}", e))?;

        let socket = Arc::new(socket);
        let socket_clone = socket.clone();

        // Отправляем handshake пакеты для пробития NAT
        let handshake_data = b"KPL"; // Keep-alive packet
        let mut timeout_count = params.timeout_secs;

        crate::info!(
            "[UdpTransport] Starting tunnel punch with {} attempts",
            timeout_count
        );

        while timeout_count > 0 {
            // Отправляем handshake пакет
            if let Err(e) = socket_clone.send_to(handshake_data, target_addr).await {
                crate::error!("[UdpTransport] Failed to send handshake: {}", e);
                timeout_count -= 1;
                continue;
            }

            crate::info!(
                "[UdpTransport] Handshake sent, waiting for response... ({}/{})",
                params.timeout_secs - timeout_count + 1,
                params.timeout_secs
            );

            // Ждем ответ в течение 2 секунд
            let mut buf = vec![0u8; 1024];
            match timeout(Duration::from_secs(2), socket_clone.recv_from(&mut buf)).await {
                Ok(Ok((_size, peer))) => {
                    if peer == target_addr {
                        crate::info!(
                            "[UdpTransport] Tunnel punch successful! Received response from {}",
                            peer
                        );

                        // Отправляем еще один пакет для подтверждения
                        let _ = socket_clone.send_to(handshake_data, target_addr).await;

                        // Создаем сессию для туннеля
                        let session = UdpSession::new_from_socket(
                            socket_clone.clone(),
                            target_addr,
                            None,
                            LinkKind::TunnelUdp,
                            self.obfuscator.clone(),
                        )?;

                        crate::info!("[UdpTransport] Tunnel session created: {}", session.id());
                        return Ok(session.clone() as Arc<dyn Session>);
                    }
                }
                Ok(Err(e)) => {
                    crate::error!("[UdpTransport] Error receiving response: {}", e);
                }
                Err(_) => {
                    // Timeout
                }
            }

            timeout_count -= 1;
        }

        Err(anyhow::anyhow!(
            "Failed to punch tunnel to {}:{} after {} attempts",
            params.target_ip,
            params.target_port,
            params.timeout_secs
        ))
    }
}
