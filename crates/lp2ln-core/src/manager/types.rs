#[derive(Debug, Clone)]
pub struct ConnectionTurnStatus {
    pub connected: bool,
    pub stun_connection: bool,
    pub is_signal: bool,
}

pub enum ConnectionType {
    Signal(String),
    Stun,
}

#[derive(Debug, Clone)]
pub struct PeerOpenNetInfo {
    pub ip: String,
    pub port: u16,
}
