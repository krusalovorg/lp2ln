use std::sync::Arc;
use dashmap::DashMap;
use crate::sessions::session::LinkKind;
use crate::sessions::{Session, SessionMetrics};
use crate::types::{PeerId, SessionId};

pub struct SessionManager {
    sessions: Arc<DashMap<SessionId, Arc<dyn Session + Send + Sync>>>,
    by_peer: Arc<DashMap<PeerId, Vec<SessionId>>>,
    session_to_peer: Arc<DashMap<SessionId, PeerId>>,
    metrics: Arc<DashMap<SessionId, SessionMetrics>>,
    by_protocol: Arc<DashMap<LinkKind, Vec<SessionId>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            by_peer: Arc::new(DashMap::new()),
            session_to_peer: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            by_protocol: Arc::new(DashMap::new()),
        }
    }

    fn add_to_protocol(&self, kind: LinkKind, session_id: SessionId) {
        self.by_protocol
            .entry(kind)
            .or_default()
            .push(session_id);
    }

    pub fn register(&self, peer_id: PeerId, session_id: SessionId, session: Arc<dyn Session + Send + Sync>) {
        self.add_to_protocol(session.kind(), session_id.clone());
        self.sessions.insert(session_id.clone(), session);
        self.metrics.insert(session_id.clone(), SessionMetrics::new());
        self.session_to_peer.insert(session_id.clone(), peer_id.clone());
        self.by_peer
            .entry(peer_id)
            .or_default()
            .push(session_id);
    }

    pub fn register_session(&self, session_id: SessionId, session: Arc<dyn Session + Send + Sync>) {
        self.add_to_protocol(session.kind(), session_id.clone());
        self.sessions.insert(session_id.clone(), session);
        self.metrics.insert(session_id.clone(), SessionMetrics::new());
    }

    pub fn set_peer_for_session(&self, session_id: SessionId, peer_id: PeerId) {
        if self.session_to_peer.contains_key(&session_id) {
            return;
        }
        self.session_to_peer.insert(session_id.clone(), peer_id.clone());
        self.by_peer
            .entry(peer_id)
            .or_default()
            .push(session_id);
    }

    pub fn get(&self, session_id: &SessionId) -> Option<Arc<dyn Session + Send + Sync>> {
        self.sessions.get(session_id).map(|s| s.clone())
    }

    pub fn get_session_ids(&self, peer_id: &PeerId) -> Option<Vec<SessionId>> {
        self.by_peer.get(peer_id).map(|v| v.clone())
    }

    pub fn get_all_for_peer(&self, peer_id: &PeerId) -> Vec<Arc<dyn Session + Send + Sync>> {
        let Some(ids_ref) = self.by_peer.get(peer_id) else { return vec![] };
        let ids = ids_ref.clone();
        drop(ids_ref);

        ids.into_iter()
            .filter_map(|id| self.get(&id))
            .collect()
    }

    pub fn get_all_peers(&self) -> Vec<PeerId> {
        self.by_peer.iter().map(|r| r.key().clone()).collect()
    }

    pub fn get_best_session_for_peer(&self, peer_id: &PeerId) -> Option<Arc<dyn Session + Send + Sync>> {
        let sessions = self.get_all_for_peer(peer_id);
        if sessions.is_empty() {
            return None;
        }
        if sessions.len() == 1 {
            return sessions.into_iter().next();
        }
        let mut best: Option<(Arc<dyn Session + Send + Sync>, SessionMetrics)> = None;
        for session in sessions {
            let session_id = SessionId::from(session.id().to_string());
            let Some(metrics) = self.get_metrics(&session_id) else { continue };
            let better = match &best {
                None => true,
                Some((_, ref m)) => {
                    if metrics.is_active != m.is_active {
                        metrics.is_active
                    } else if metrics.total_errors() != m.total_errors() {
                        metrics.total_errors() < m.total_errors()
                    } else {
                        metrics.time_since_last_activity() < m.time_since_last_activity()
                    }
                }
            };
            if better {
                best = Some((session, metrics));
            }
        }
        best.map(|(s, _)| s)
    }

    pub fn get_metrics(&self, session_id: &SessionId) -> Option<SessionMetrics> {
        self.metrics.get(session_id).map(|m| m.clone())
    }

    pub fn update_metrics<F>(&self, session_id: &SessionId, f: F)
    where
        F: FnOnce(&mut SessionMetrics),
    {
        if let Some(mut metrics) = self.metrics.get_mut(session_id) {
            f(&mut metrics);
        }
    }

    pub fn get_metrics_for_protocol(&self, kind: LinkKind) -> Vec<SessionMetrics> {
        let Some(guard) = self.by_protocol.get(&kind) else {
            return vec![];
        };
        let ids: Vec<SessionId> = guard.value().clone();
        drop(guard);
        ids.into_iter()
            .filter_map(|id| self.metrics.get(&id).map(|m| m.clone()))
            .collect()
    }

    pub fn get_metrics_by_protocol(&self) -> Vec<(LinkKind, Vec<SessionMetrics>)> {
        self.by_protocol
            .iter()
            .map(|entry| {
                let kind = *entry.key();
                let metrics: Vec<SessionMetrics> = entry
                    .value()
                    .iter()
                    .filter_map(|id| self.metrics.get(id).map(|m| m.clone()))
                    .collect();
                (kind, metrics)
            })
            .collect()
    }
}