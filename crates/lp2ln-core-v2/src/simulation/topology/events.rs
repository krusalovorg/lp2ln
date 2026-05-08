use super::types::SimNodeId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimulationEventKind {
    Tick {
        node_id: SimNodeId,
    },
    DialAttempt {
        from: SimNodeId,
        to: SimNodeId,
    },
    DialResult {
        from: SimNodeId,
        to: SimNodeId,
        success: bool,
        latency_ms: u16,
    },
    Disconnect {
        from: SimNodeId,
        to: SimNodeId,
    },
    PeerExchange {
        node_id: SimNodeId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulationEvent {
    pub at_ms: u64,
    pub kind: SimulationEventKind,
}

impl SimulationEvent {
    pub fn new(at_ms: u64, kind: SimulationEventKind) -> Self {
        Self { at_ms, kind }
    }
}
