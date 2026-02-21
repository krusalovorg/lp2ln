use std::fmt;
use crate::packet::Packet;
use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkKind {
    DirectTcp,
    DirectUdp,
    TunnelTcp,
    TunnelUdp,
    Relay,
}

impl fmt::Display for LinkKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkKind::DirectTcp => write!(f, "tcp"),
            LinkKind::DirectUdp => write!(f, "udp"),
            LinkKind::TunnelTcp => write!(f, "tunnel_tcp"),
            LinkKind::TunnelUdp => write!(f, "tunnel_udp"),
            LinkKind::Relay => write!(f, "relay"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IncomingPacket {
    pub session_id: String,
    pub from_node: Option<String>,
    pub packet: Packet,
}

#[async_trait]
pub trait Session: Send + Sync {
    fn id(&self) -> &str;
    
    fn peer_id(&self) -> Option<&str>;
    
    fn kind(&self) -> LinkKind;

    async fn send(&self, packet: Packet) -> Result<u64>;
    
    async fn close(&self) -> Result<()>;
    
    fn spawn_reader(self: std::sync::Arc<Self>, incoming_packets_tx: tokio::sync::mpsc::Sender<IncomingPacket>);
}

