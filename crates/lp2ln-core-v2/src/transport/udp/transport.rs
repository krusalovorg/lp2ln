use crate::sessions::Session;
use crate::sessions::session::LinkKind;
use crate::stun::StunClient;
use crate::transport::obfuscation::{ObfuscationConfig, Obfuscator};
use crate::transport::transport::{PublicAddress, TransportContext, TunnelPunchParams};
use crate::transport::udp::session::{InboundDatagram, MAX_UDP_DATAGRAM, UdpSession};
use crate::transport::{
    ACCEPT_TASK_JOIN_TIMEOUT, Transport, bind_with_port_fallback, join_accept_task,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Semaphore, mpsc};
use tokio::time::{Duration, timeout};

// All virtual sessions on one listener share a datagram memory budget.
const LISTENER_BYTE_BUDGET: usize = 8 * 1024 * 1024;
const MAX_LISTENER_SESSIONS: usize = 1024;
const SESSION_INBOX_CAPACITY: usize = 64;

pub struct UdpTransport {
    receive_budget: std::sync::Mutex<Option<crate::transport::TransportReceiveBudget>>,
    listen_addr: SocketAddr,
    shutdown_tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    accept_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    stun_client: StunClient,
    is_listener: bool,
    obfuscator: Arc<Obfuscator>,
}

impl Default for UdpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpTransport {
    pub fn new() -> Self {
        Self {
            receive_budget: std::sync::Mutex::new(None),
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
            receive_budget: std::sync::Mutex::new(None),
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
            receive_budget: std::sync::Mutex::new(None),
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
            receive_budget: std::sync::Mutex::new(None),
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
            receive_budget: std::sync::Mutex::new(None),
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
        let shared = self
            .receive_budget
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|b| b.get());
        let scratch = shared
            .as_ref()
            .map(|b| {
                b.wire(MAX_UDP_DATAGRAM + 256)
                    .context("UDP listener scratch budget exhausted")
            })
            .transpose()?;
        let incoming_sessions_tx = ctx.incoming_sessions_tx;
        let obfuscator = self.obfuscator.clone();
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        *self.shutdown_tx.lock().await = Some(shutdown_tx);

        let accept_handle = tokio::spawn(async move {
            let _scratch = scratch;
            let mut sessions: HashMap<
                SocketAddr,
                (Weak<UdpSession>, mpsc::Sender<InboundDatagram>),
            > = HashMap::new();
            let budget = Arc::new(Semaphore::new(LISTENER_BYTE_BUDGET));
            let mut buffer = vec![0; MAX_UDP_DATAGRAM];

            loop {
                let received = tokio::select! {
                    _ = &mut shutdown_rx => break,
                    _ = incoming_sessions_tx.closed() => break,
                    result = socket.recv_from(&mut buffer) => result,
                };
                let (size, peer_addr) = match received {
                    Ok(datagram) => datagram,
                    Err(error) => {
                        crate::debug!("[UdpTransport] Receive failed: {}", error);
                        break;
                    }
                };
                let Ok(permit) = budget.clone().try_acquire_many_owned((size + 128) as u32) else {
                    continue;
                };

                let node_permit = match &shared {
                    Some(b) => match b.wire(size + 128) {
                        Some(permit) => Some(permit),
                        None => continue,
                    },
                    None => None,
                };

                if let Some((peer, inbox)) = sessions.get(&peer_addr) {
                    if peer.upgrade().is_some_and(|session| !session.is_closed()) {
                        if let Ok(slot) = inbox.try_reserve() {
                            slot.send((buffer[..size].to_vec(), permit, node_permit));
                        }
                        continue;
                    }
                    sessions.remove(&peer_addr);
                }
                if sessions.len() >= MAX_LISTENER_SESSIONS {
                    sessions.retain(|_, (peer, _)| {
                        peer.upgrade().is_some_and(|session| !session.is_closed())
                    });
                    if sessions.len() >= MAX_LISTENER_SESSIONS {
                        continue;
                    }
                }
                // Validate framing before allocating a peer inbox. Authentication
                // still belongs to the existing packet processor.
                let first = &buffer[..size];
                let first_valid = {
                    let _decode = match &shared {
                        Some(b) => match b
                            .pre_auth(crate::transport::tcp::codec::decode_reservation(size))
                        {
                            Some(permit) => Some(permit),
                            None => continue,
                        },
                        None => None,
                    };
                    if obfuscator.is_enabled() {
                        obfuscator
                            .decode_datagram(first)
                            .and_then(crate::transport::tcp::codec::decode_packet)
                            .is_ok()
                    } else {
                        crate::transport::tcp::codec::decode_packet_slice(first).is_ok()
                    }
                };
                if !first_valid {
                    continue;
                }
                let Ok(registration) = incoming_sessions_tx.try_reserve() else {
                    continue;
                };
                let (inbox_tx, inbox_rx) = mpsc::channel(SESSION_INBOX_CAPACITY);
                let Ok(session) = UdpSession::from_listener(
                    socket.clone(),
                    peer_addr,
                    obfuscator.clone(),
                    inbox_rx,
                ) else {
                    continue;
                };
                // Register the inbox and retain the triggering packet before
                // publishing the session to the runtime.
                if inbox_tx
                    .try_send((first.to_vec(), permit, node_permit))
                    .is_ok()
                {
                    sessions.insert(peer_addr, (Arc::downgrade(&session), inbox_tx));
                    registration.send(session);
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

        let bind_addr = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_addr)
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
