use crate::crypto::NodeKeypair;
use crate::event_core::prelude::CoreEvent;
use crate::topology::PeerCatalog;
use crate::{sessions::Session, sessions::session::IncomingPacket};
use anyhow::Result;
use async_trait::async_trait;
use std::io::ErrorKind;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::mpsc;

pub async fn bind_with_port_fallback<F, Fut, T>(
    addr: SocketAddr,
    bind_fn: F,
) -> Result<(T, SocketAddr)>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<(T, SocketAddr)>>,
{
    let mut port = addr.port();
    let ip = addr.ip();
    let mut bind_addr = SocketAddr::new(ip, port);
    loop {
        match bind_fn(bind_addr).await {
            Ok((t, actual)) => return Ok((t, actual)),
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                if port == 65535 {
                    return Err(anyhow::anyhow!(
                        "No free port in range (started from {})",
                        addr.port()
                    ));
                }
                port += 1;
                bind_addr = SocketAddr::new(ip, port);
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Joins a transport accept task after the shutdown signal was sent.
/// Aborts (and then awaits) the task if it does not finish in time, so the
/// accept loop never outlives `Transport::stop()`.
pub(crate) async fn join_accept_task(
    name: &str,
    handle: Option<tokio::task::JoinHandle<()>>,
    timeout: std::time::Duration,
) {
    let Some(mut handle) = handle else {
        return;
    };
    match tokio::time::timeout(timeout, &mut handle).await {
        Ok(_) => {}
        Err(_) => {
            crate::warn!(
                "[{}] accept task did not stop within {:?}, aborting",
                name,
                timeout
            );
            handle.abort();
            let _ = handle.await;
        }
    }
}

pub(crate) const ACCEPT_TASK_JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Transport-side access to a node's receive ledger. A transport may outlive
/// its node, so this binding does not keep the ledger alive.
#[derive(Clone)]
pub struct TransportReceiveBudget(
    pub(crate) std::sync::Weak<crate::router::admission::IngressBudget>,
);

impl TransportReceiveBudget {
    pub(crate) fn get(&self) -> Option<Arc<crate::router::admission::IngressBudget>> {
        self.0.upgrade()
    }
}

#[derive(Clone)]
pub struct TransportContext {
    pub incoming_sessions_tx: mpsc::Sender<Arc<dyn Session>>,
    pub incoming_packets_tx: mpsc::Sender<IncomingPacket>,
    pub listen_addr: Option<SocketAddr>,
    /// Channel for transports to emit `CoreEvent`s (e.g. loss degradation) back to the node.
    pub event_tx: Option<mpsc::Sender<CoreEvent>>,
    /// Node keypair — provided to QUIC transport for ECDH-derived obfs key derivation.
    pub keypair: Option<Arc<NodeKeypair>>,
    /// Peer catalog — used to look up per-peer obfs capability during dial.
    pub catalog: Option<Arc<PeerCatalog>>,
}

#[derive(Debug, Clone)]
pub struct PublicAddress {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct TunnelPunchParams {
    pub target_ip: String,
    pub target_port: u16,
    pub timeout_secs: u64,
}

#[async_trait]
pub trait Transport: Send + Sync {
    fn name(&self) -> &'static str;

    fn is_listener(&self) -> bool {
        true
    }

    #[doc(hidden)]
    fn bind_receive_budget(&self, _budget: TransportReceiveBudget) -> Result<()> {
        Ok(())
    }

    async fn start(&self, ctx: TransportContext) -> Result<Option<SocketAddr>>;

    async fn stop(&self) -> Result<()> {
        Ok(())
    }

    async fn dial(&self, addr: SocketAddr) -> Result<Arc<dyn Session>>;

    /// Dial with optional peer_id hint for per-peer obfs key derivation.
    /// Default: delegates to `dial`. Override in QUIC transport.
    async fn dial_with_peer(
        &self,
        addr: SocketAddr,
        _peer_id: Option<&str>,
    ) -> Result<Arc<dyn Session>> {
        self.dial(addr).await
    }

    #[doc(hidden)]
    fn authorize_realtime(&self, _peer: &crate::PeerId, _protocol: u16) -> Result<()> {
        Err(crate::flow::FlowError::Unsupported.into())
    }

    #[doc(hidden)]
    fn revoke_realtime(&self, _peer: &crate::PeerId, _protocol: u16) -> Result<()> {
        Err(crate::flow::FlowError::Unsupported.into())
    }

    #[doc(hidden)]
    async fn open_realtime(
        &self,
        _identity: Arc<NodeKeypair>,
        _peer: &crate::PeerId,
        _addr: SocketAddr,
        _protocol: u16,
    ) -> Result<crate::flow::Flow> {
        Err(crate::flow::FlowError::Unsupported.into())
    }

    #[doc(hidden)]
    async fn accept_realtime(&self) -> Result<crate::flow::Flow> {
        Err(crate::flow::FlowError::Unsupported.into())
    }

    fn supports_tunneling(&self) -> bool {
        false
    }

    async fn get_public_address(&self, _local_port: u16) -> Result<PublicAddress> {
        Err(anyhow::anyhow!(
            "Transport {} does not support tunneling",
            self.name()
        ))
    }

    async fn punch_tunnel(&self, _params: TunnelPunchParams) -> Result<Arc<dyn Session>> {
        Err(anyhow::anyhow!(
            "Transport {} does not support tunneling",
            self.name()
        ))
    }
}
