use std::net::SocketAddr;

use crate::packet::Packet;
use crate::types::{PeerId, SessionId};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CoreEventKind {
    Lifecycle,
    Transport,
    Session,
    Packet,
    Routing,
    Peer,
    Relay,
    Dht,
    Consensus,
    WasmExtension,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceDescriptor {
    pub name: String,
    pub kind: ServiceKind,
}

impl ServiceDescriptor {
    pub fn new(name: impl Into<String>, kind: ServiceKind) -> Self {
        Self {
            name: name.into(),
            kind,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceKind {
    Runtime,
    Router,
    PacketIngress,
    TransportManager,
    Transport,
    SessionManager,
    Topology,
    NatTraversal,
    Relay,
    Dht,
    Consensus,
    WasmExtensionHost,
    Metrics,
    Storage,
    Custom(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceStatus {
    Created,
    Starting,
    Ready,
    Degraded,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Debug, Clone)]
pub struct LifecycleEvent {
    pub service: ServiceDescriptor,
    pub status: ServiceStatus,
    pub generation: u64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Quic,
    WebRtc,
    Relay,
    Custom(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportCapability {
    Listener,
    Dialer,
    NatTraversal,
    Multiplexing,
    Relay,
    Obfuscation,
    SecureChannel,
}

#[derive(Debug, Clone)]
pub struct TransportReadiness {
    pub service: ServiceDescriptor,
    pub protocol: TransportProtocol,
    pub listen_addr: Option<SocketAddr>,
    pub public_addr: Option<String>,
    pub capabilities: Vec<TransportCapability>,
}

#[derive(Debug, Clone)]
pub enum TransportEvent {
    Registered {
        service: ServiceDescriptor,
        protocol: TransportProtocol,
    },
    Starting {
        service: ServiceDescriptor,
        protocol: TransportProtocol,
        listen_addr: Option<SocketAddr>,
    },
    Ready(TransportReadiness),
    Degraded {
        service: ServiceDescriptor,
        protocol: TransportProtocol,
        reason: String,
        /// Measured packet-loss fraction (0.0–1.0); 0.0 for non-loss degradation.
        loss_rate: f64,
    },
    Recovered {
        service: ServiceDescriptor,
        protocol: TransportProtocol,
        loss_rate: f64,
    },
    Stopped {
        service: ServiceDescriptor,
        protocol: TransportProtocol,
    },
}

#[derive(Debug, Clone)]
pub enum SessionEvent {
    Accepted {
        session_id: SessionId,
        peer_id: Option<PeerId>,
        transport: TransportProtocol,
    },
    BoundToPeer {
        session_id: SessionId,
        peer_id: PeerId,
    },
    Closed {
        session_id: SessionId,
        peer_id: Option<PeerId>,
        reason: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub enum PacketEvent {
    Received {
        session_id: SessionId,
        from_peer: Option<PeerId>,
        packet: Packet,
    },
    Classified {
        session_id: SessionId,
        from_peer: PeerId,
        class: PacketClass,
        request_id: Option<u64>,
    },
    Dropped {
        session_id: Option<SessionId>,
        from_peer: Option<PeerId>,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketClass {
    Local,
    Control,
    Forwarded,
    Relay,
    Dht,
    Consensus,
    WasmExtension,
}

#[derive(Debug, Clone)]
pub enum RoutingEvent {
    RouteRequested {
        target: PeerId,
        request_id: Option<u64>,
    },
    RouteResolved {
        target: PeerId,
        via_session: SessionId,
        request_id: Option<u64>,
    },
    RouteFailed {
        target: PeerId,
        request_id: Option<u64>,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub enum PeerEvent {
    Discovered {
        peer_id: PeerId,
        source: String,
    },
    Connected {
        peer_id: PeerId,
        session_id: SessionId,
    },
    Disconnected {
        peer_id: PeerId,
        reason: Option<String>,
    },
    ScoreChanged {
        peer_id: PeerId,
        score: f64,
    },
}

#[derive(Debug, Clone)]
pub enum RelayEvent {
    ReservationRequested { peer_id: PeerId, ttl_ms: u64 },
    ReservationReady { peer_id: PeerId, relay_peer: PeerId },
    ReservationFailed { peer_id: PeerId, reason: String },
}

#[derive(Debug, Clone)]
pub enum DhtEvent {
    PutAccepted { key: Vec<u8> },
    ValueFound { key: Vec<u8>, value: Vec<u8> },
    ValueNotFound { key: Vec<u8> },
}

#[derive(Debug, Clone)]
pub enum ConsensusEvent {
    ProposalSubmitted { proposal_id: String, topic: String },
    ProposalFinalized { proposal_id: String, accepted: bool },
    ProposalRejected { proposal_id: String, reason: String },
}

#[derive(Debug, Clone)]
pub enum WasmExtensionEvent {
    ModuleLoaded {
        module_id: String,
    },
    ModuleUnloaded {
        module_id: String,
    },
    InvocationCompleted {
        module_id: String,
        operation: String,
    },
    InvocationFailed {
        module_id: String,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub enum CoreEvent {
    Lifecycle(LifecycleEvent),
    Transport(TransportEvent),
    Session(SessionEvent),
    Packet(PacketEvent),
    Routing(RoutingEvent),
    Peer(PeerEvent),
    Relay(RelayEvent),
    Dht(DhtEvent),
    Consensus(ConsensusEvent),
    WasmExtension(WasmExtensionEvent),
}

impl CoreEvent {
    pub fn kind(&self) -> CoreEventKind {
        match self {
            Self::Lifecycle(_) => CoreEventKind::Lifecycle,
            Self::Transport(_) => CoreEventKind::Transport,
            Self::Session(_) => CoreEventKind::Session,
            Self::Packet(_) => CoreEventKind::Packet,
            Self::Routing(_) => CoreEventKind::Routing,
            Self::Peer(_) => CoreEventKind::Peer,
            Self::Relay(_) => CoreEventKind::Relay,
            Self::Dht(_) => CoreEventKind::Dht,
            Self::Consensus(_) => CoreEventKind::Consensus,
            Self::WasmExtension(_) => CoreEventKind::WasmExtension,
        }
    }
}
