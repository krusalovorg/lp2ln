use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct PeerOptions {
    pub signal_addr: SocketAddr,
    pub storage_size: u64,
}

impl PeerOptions {
    pub fn new(signal_addr: SocketAddr, storage_size: u64) -> Self {
        Self {
            signal_addr,
            storage_size,
        }
    }

    pub fn storage_size(mut self, v: u64) -> Self {
        self.storage_size = v;
        self
    }

    pub fn signal_addr(mut self, v: SocketAddr) -> Self {
        self.signal_addr = v;
        self
    }
}