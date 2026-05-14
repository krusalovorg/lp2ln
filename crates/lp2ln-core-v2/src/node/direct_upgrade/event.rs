use crate::types::PeerId;

#[derive(Debug, Clone)]
pub enum DirectUpgradeEvent {
    FallbackTraffic { peer_id: PeerId, bytes: u64 },
}

#[derive(Clone)]
pub struct DirectUpgradeRouterSink {
    pub enabled: bool,
    pub tx: tokio::sync::mpsc::Sender<DirectUpgradeEvent>,
}
