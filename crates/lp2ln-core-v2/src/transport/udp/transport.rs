use anyhow::{Context, Result};
use async_trait::async_trait;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::sessions::{LinkKind, Session};
use crate::stun::StunClient;
use crate::transport::obfuscation::{ObfuscationConfig, Obfuscator};
use crate::transport::transport::{PublicAddress, TransportContext, TunnelPunchParams};
use crate::transport::{
    ACCEPT_TASK_JOIN_TIMEOUT, Transport, bind_with_port_fallback, join_accept_task,
};

use super::listener::SharedSocket;
use super::session::UdpSession;

struct Listener {
    shared: Arc<SharedSocket>,
    task: tokio::task::JoinHandle<()>,
}

pub struct UdpTransport {
    listen_addr: SocketAddr,
    listener: Mutex<Option<Listener>>,
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
        Self::new_listener(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
    }

    pub fn new_listener(listen_addr: SocketAddr) -> Self {
        Self::configured(listen_addr, true, Obfuscator::plain())
    }

    pub fn new_dial() -> Self {
        Self::configured(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            false,
            Obfuscator::plain(),
        )
    }

    pub fn new_listener_with_obfuscation(
        listen_addr: SocketAddr,
        config: ObfuscationConfig,
    ) -> Self {
        Self::configured(listen_addr, true, Obfuscator::from_config(config))
    }

    pub fn new_dial_with_obfuscation(config: ObfuscationConfig) -> Self {
        Self::configured(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            false,
            Obfuscator::from_config(config),
        )
    }

    fn configured(listen_addr: SocketAddr, is_listener: bool, obfuscator: Obfuscator) -> Self {
        Self {
            listen_addr,
            listener: Mutex::new(None),
            stun_client: StunClient::new(),
            is_listener,
            obfuscator: Arc::new(obfuscator),
        }
    }

    async fn shared_socket(&self) -> Option<Arc<SharedSocket>> {
        self.listener
            .lock()
            .await
            .as_ref()
            .map(|listener| listener.shared.clone())
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
        let mut listener = self.listener.lock().await;
        anyhow::ensure!(listener.is_none(), "UdpTransport is already started");
        let bind_addr = ctx.listen_addr.unwrap_or(self.listen_addr);
        let (socket, actual_addr) = bind_with_port_fallback(bind_addr, |addr| async move {
            let socket = UdpSocket::bind(addr).await?;
            let actual_addr = socket.local_addr()?;
            Ok((socket, actual_addr))
        })
        .await
        .context("Failed to bind UDP")?;
        let shared = Arc::new(SharedSocket::new(socket, self.obfuscator.clone()));
        let task = tokio::spawn(shared.clone().run(ctx.incoming_sessions_tx));
        *listener = Some(Listener { shared, task });
        Ok(Some(actual_addr))
    }

    async fn stop(&self) -> Result<()> {
        let mut listener = self.listener.lock().await;
        if let Some(listener) = listener.take() {
            listener.shared.shutdown.cancel();
            join_accept_task(
                "UdpTransport",
                Some(listener.task),
                ACCEPT_TASK_JOIN_TIMEOUT,
            )
            .await;
        }
        Ok(())
    }

    async fn dial(&self, addr: SocketAddr) -> Result<Arc<dyn Session>> {
        if let Some(shared) = self.shared_socket().await {
            if shared.socket.local_addr()?.is_ipv4() == addr.is_ipv4() {
                return Ok(shared.dial(addr, LinkKind::DirectUdp)?);
            }
        }
        let bind = if addr.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        let socket = Arc::new(
            UdpSocket::bind(bind)
                .await
                .context("Failed to bind UDP dial socket")?,
        );
        Ok(UdpSession::new_from_socket(
            socket,
            addr,
            None,
            LinkKind::DirectUdp,
            self.obfuscator.clone(),
        )?)
    }

    fn supports_tunneling(&self) -> bool {
        self.is_listener
    }

    async fn get_public_address(&self, _local_port: u16) -> Result<PublicAddress> {
        let shared = self
            .shared_socket()
            .await
            .context("UDP listener is not started")?;
        let ipv4 = shared.socket.local_addr()?.is_ipv4();
        let address = tokio::time::timeout(Duration::from_secs(2), async {
            for server in self.stun_client.get_servers() {
                let Ok(addresses) = tokio::net::lookup_host(&server).await else {
                    continue;
                };
                for address in addresses.filter(|address| address.is_ipv4() == ipv4) {
                    if let Ok(mapped) = shared.stun_binding(address).await {
                        return Ok(mapped);
                    }
                }
            }
            anyhow::bail!("No STUN server answered on the UDP listener")
        })
        .await
        .context("STUN lookup timed out")??;
        Ok(PublicAddress {
            ip: address.ip().to_string(),
            port: address.port(),
        })
    }

    async fn punch_tunnel(&self, params: TunnelPunchParams) -> Result<Arc<dyn Session>> {
        let peer = SocketAddr::new(
            params.target_ip.parse().context("Invalid UDP target IP")?,
            params.target_port,
        );
        let shared = self
            .shared_socket()
            .await
            .context("UDP listener is not started")?;
        Ok(shared
            .punch(peer, Duration::from_secs(params.timeout_secs))
            .await?)
    }
}
