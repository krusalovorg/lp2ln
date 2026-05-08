use std::net::SocketAddr;

use crate::packet::Packet;
use crate::types::{PeerId, SessionId};

use super::events::{ServiceDescriptor, TransportProtocol};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CoreCommandKind {
    Lifecycle,
    Transport,
    Routing,
    Relay,
    Dht,
    Consensus,
    WasmExtension,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LifecycleAction {
    Start,
    Stop,
    Restart,
    Probe,
}

#[derive(Debug, Clone)]
pub struct LifecycleCommand {
    pub service: ServiceDescriptor,
    pub action: LifecycleAction,
}

#[derive(Debug, Clone)]
pub enum TransportCommand {
    Register {
        service: ServiceDescriptor,
        protocol: TransportProtocol,
        listen_addr: Option<SocketAddr>,
    },
    Start {
        service: ServiceDescriptor,
    },
    Stop {
        service: ServiceDescriptor,
    },
    Dial {
        protocol: TransportProtocol,
        addr: SocketAddr,
        expected_peer: Option<PeerId>,
    },
}

#[derive(Debug, Clone)]
pub enum RoutingCommand {
    SendToPeer {
        peer_id: PeerId,
        packet: Packet,
        exclude_from: Option<PeerId>,
    },
    SendToSession {
        session_id: SessionId,
        packet: Packet,
    },
}

#[derive(Debug, Clone)]
pub enum RelayCommand {
    ReserveCircuit {
        peer_id: PeerId,
        ttl_ms: u64,
    },
    Forward {
        relay_peer: PeerId,
        target_peer: PeerId,
        packet: Packet,
    },
}

#[derive(Debug, Clone)]
pub enum DhtCommand {
    Put { key: Vec<u8>, value: Vec<u8> },
    Get { key: Vec<u8> },
    FindPeer { peer_id: PeerId },
}

#[derive(Debug, Clone)]
pub enum ConsensusCommand {
    Propose { topic: String, payload: Vec<u8> },
    Vote { proposal_id: String, accept: bool },
}

#[derive(Debug, Clone)]
pub enum WasmExtensionCommand {
    LoadModule {
        module_id: String,
        wasm_bytes: Vec<u8>,
    },
    UnloadModule {
        module_id: String,
    },
    Invoke {
        module_id: String,
        operation: String,
        payload: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub enum CoreCommand {
    Lifecycle(LifecycleCommand),
    Transport(TransportCommand),
    Routing(RoutingCommand),
    Relay(RelayCommand),
    Dht(DhtCommand),
    Consensus(ConsensusCommand),
    WasmExtension(WasmExtensionCommand),
}

impl CoreCommand {
    pub fn kind(&self) -> CoreCommandKind {
        match self {
            Self::Lifecycle(_) => CoreCommandKind::Lifecycle,
            Self::Transport(_) => CoreCommandKind::Transport,
            Self::Routing(_) => CoreCommandKind::Routing,
            Self::Relay(_) => CoreCommandKind::Relay,
            Self::Dht(_) => CoreCommandKind::Dht,
            Self::Consensus(_) => CoreCommandKind::Consensus,
            Self::WasmExtension(_) => CoreCommandKind::WasmExtension,
        }
    }
}
