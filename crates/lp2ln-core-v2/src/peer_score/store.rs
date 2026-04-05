use dashmap::DashMap;

use crate::peer_score::PeerScore;
use crate::types::PeerId;

#[derive(Debug, Default)]
pub struct PeerScoreStore {
    inner: DashMap<PeerId, PeerScore>,
}

impl PeerScoreStore {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    pub fn get(&self, peer_id: &PeerId) -> PeerScore {
        self.inner
            .get(peer_id)
            .map(|r| r.clone())
            .unwrap_or_default()
    }

    pub fn insert(&self, peer_id: PeerId, score: PeerScore) {
        self.inner.insert(peer_id, score);
    }

    pub fn update(&self, peer_id: &PeerId, f: impl FnOnce(&mut PeerScore)) {
        let mut score = self.get(peer_id);
        f(&mut score);
        self.inner.insert(peer_id.clone(), score);
    }

    pub fn touch_peer(&self, peer_id: &PeerId) {
        self.inner
            .entry(peer_id.clone())
            .or_insert_with(PeerScore::neutral);
    }

    pub fn snapshot(&self) -> Vec<(PeerId, PeerScore)> {
        self.inner
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    }
}
