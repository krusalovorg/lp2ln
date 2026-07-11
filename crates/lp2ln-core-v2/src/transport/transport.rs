use crate::event_core::prelude::CoreEvent;
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

#[derive(Clone)]
pub struct TransportContext {
    pub incoming_sessions_tx: mpsc::Sender<Arc<dyn Session>>,
    pub incoming_packets_tx: mpsc::Sender<IncomingPacket>,
    pub listen_addr: Option<SocketAddr>,
    /// Channel for transports to emit `CoreEvent`s (e.g. loss degradation) back to the node.
    pub event_tx: Option<mpsc::Sender<CoreEvent>>,
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

    async fn start(&self, ctx: TransportContext) -> Result<Option<SocketAddr>>;

    async fn stop(&self) -> Result<()> {
        Ok(())
    }

    async fn dial(&self, addr: SocketAddr) -> Result<Arc<dyn Session>>;

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
