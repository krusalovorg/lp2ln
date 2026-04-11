use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;

use crate::peer_score::{total_score, PeerScoreStore, PeerScoreWeights};
use crate::sessions::session::LinkKind;
use crate::sessions::{Session, SessionMetrics};
use crate::types::{PeerId, SessionId};

pub struct SessionManager {
    sessions: Arc<DashMap<SessionId, Arc<dyn Session + Send + Sync>>>,
    by_peer: Arc<DashMap<PeerId, Vec<SessionId>>>,
    session_to_peer: Arc<DashMap<SessionId, PeerId>>,
    metrics: Arc<DashMap<SessionId, SessionMetrics>>,
    by_protocol: Arc<DashMap<LinkKind, Vec<SessionId>>>,
    peer_scores: Arc<PeerScoreStore>,
    peer_weights: PeerScoreWeights,
}

#[derive(Debug, Clone)]
pub struct SessionDebugEntry {
    pub session_id: String,
    pub peer_id: Option<String>,
    pub protocol: String,
    pub is_active: bool,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub send_errors: u64,
    pub receive_errors: u64,
    pub reconnections: u64,
    pub uptime_secs: u64,
    pub last_activity_secs_ago: u64,
}

impl SessionManager {
    fn prune_stale_peer_index(&self) {
        let peers: Vec<PeerId> = self.by_peer.iter().map(|r| r.key().clone()).collect();
        for pid in peers {
            let mut remove = false;
            if let Some(mut ids) = self.by_peer.get_mut(&pid) {
                ids.retain(|id| self.sessions.contains_key(id));
                remove = ids.is_empty();
            }
            if remove {
                self.by_peer.remove(&pid);
            }
        }
    }

    pub fn new(peer_scores: Arc<PeerScoreStore>, peer_weights: PeerScoreWeights) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            by_peer: Arc::new(DashMap::new()),
            session_to_peer: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            by_protocol: Arc::new(DashMap::new()),
            peer_scores,
            peer_weights,
        }
    }

    pub fn peer_score_store(&self) -> Arc<PeerScoreStore> {
        self.peer_scores.clone()
    }

    pub fn peer_weights(&self) -> &PeerScoreWeights {
        &self.peer_weights
    }

    fn add_to_protocol(&self, kind: LinkKind, session_id: SessionId) {
        self.by_protocol
            .entry(kind)
            .or_default()
            .push(session_id);
    }

    pub fn register(&self, peer_id: PeerId, session_id: SessionId, session: Arc<dyn Session + Send + Sync>) {
        self.peer_scores.touch_peer(&peer_id);
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
        self.peer_scores.touch_peer(&peer_id);
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
        self.prune_stale_peer_index();
        self.by_peer.get(peer_id).map(|v| v.clone())
    }

    pub fn get_all_for_peer(&self, peer_id: &PeerId) -> Vec<Arc<dyn Session + Send + Sync>> {
        self.prune_stale_peer_index();
        let Some(ids_ref) = self.by_peer.get(peer_id) else { return vec![] };
        let ids = ids_ref.clone();
        drop(ids_ref);

        ids.into_iter()
            .filter_map(|id| self.get(&id))
            .collect()
    }

    pub fn get_all_peers(&self) -> Vec<PeerId> {
        self.prune_stale_peer_index();
        self.by_peer.iter().map(|r| r.key().clone()).collect()
    }

    pub fn get_all_peers_sorted_by_score(&self) -> Vec<PeerId> {
        let peers = self.get_all_peers();
        crate::peer_score::rank_peers(&peers, |p| self.peer_scores.get(p), &self.peer_weights)
    }

    fn session_send_priority(
        &self,
        peer_id: &PeerId,
        _session_id: &SessionId,
        metrics: &SessionMetrics,
    ) -> f32 {
        let peer_score = self.peer_scores.get(peer_id);
        let base = total_score(&peer_score, &self.peer_weights);
        let packets = metrics.total_packets().max(1) as f32;
        let err_rate = (metrics.total_errors() as f32 / packets).min(1.0);
        let stale_secs = metrics.time_since_last_activity().as_secs_f32();
        let stale = (stale_secs / 120.0).min(1.0);
        base - self.peer_weights.w_latency * stale * 0.35 - self.peer_weights.w_load * err_rate
    }

    pub fn get_best_session_for_peer(&self, peer_id: &PeerId) -> Option<Arc<dyn Session + Send + Sync>> {
        let sessions = self.get_all_for_peer(peer_id);
        if sessions.is_empty() {
            return None;
        }
        if sessions.len() == 1 {
            return sessions.into_iter().next();
        }
        let mut best: Option<(Arc<dyn Session + Send + Sync>, f32)> = None;
        for session in sessions {
            let session_id = SessionId::from(session.id().to_string());
            let Some(metrics) = self.get_metrics(&session_id) else { continue };
            let rank = self.session_send_priority(peer_id, &session_id, &metrics);
            let better = match &best {
                None => true,
                Some((_, prev)) => rank > *prev,
            };
            if better {
                best = Some((session, rank));
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

    pub fn peer_metrics_rollup(&self) -> Vec<(PeerId, Vec<SessionMetrics>)> {
        self.by_peer
            .iter()
            .map(|entry| {
                let peer_id = entry.key().clone();
                let metrics = entry
                    .value()
                    .iter()
                    .filter_map(|sid| self.metrics.get(sid).map(|m| m.clone()))
                    .collect::<Vec<_>>();
                (peer_id, metrics)
            })
            .collect()
    }

    pub fn total_sessions_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn debug_sessions(&self) -> Vec<SessionDebugEntry> {
        self.sessions
            .iter()
            .filter_map(|entry| {
                let session_id = entry.key().clone();
                let session = entry.value().clone();
                let metrics = self.metrics.get(&session_id).map(|m| m.clone())?;
                let peer_id = self
                    .session_to_peer
                    .get(&session_id)
                    .map(|pid| pid.as_str().to_string());
                Some(SessionDebugEntry {
                    session_id: session_id.as_str().to_string(),
                    peer_id,
                    protocol: session.kind().to_string(),
                    is_active: metrics.is_active,
                    packets_sent: metrics.packets_sent,
                    packets_received: metrics.packets_received,
                    bytes_sent: metrics.bytes_sent,
                    bytes_received: metrics.bytes_received,
                    send_errors: metrics.send_errors,
                    receive_errors: metrics.receive_errors,
                    reconnections: metrics.reconnections,
                    uptime_secs: metrics.uptime().as_secs(),
                    last_activity_secs_ago: metrics.time_since_last_activity().as_secs(),
                })
            })
            .collect()
    }

    /// Distinct remote peers with at least one registered session.
    pub fn distinct_peer_count(&self) -> usize {
        self.prune_stale_peer_index();
        self.by_peer.len()
    }

    pub fn is_connected_to_peer(&self, peer_id: &PeerId) -> bool {
        self.prune_stale_peer_index();
        self.by_peer.contains_key(peer_id)
    }

    /// Worst-ranked peers (low `total_score`), for pruning when above `max_active_peers`.
    pub fn lowest_scored_distinct_peers(&self, take: usize) -> Vec<PeerId> {
        let mut peers: Vec<_> = self.get_all_peers();
        peers.sort_by(|a, b| {
            let ta = total_score(&self.peer_scores.get(a), &self.peer_weights);
            let tb = total_score(&self.peer_scores.get(b), &self.peer_weights);
            ta.partial_cmp(&tb).unwrap_or(std::cmp::Ordering::Equal)
        });
        peers.into_iter().take(take).collect()
    }

    pub async fn close_session(&self, session_id: &SessionId) -> Result<()> {
        let session = self.sessions.remove(session_id).map(|(_, s)| s);
        let Some(session) = session else {
            return Ok(());
        };
        let kind = session.kind();
        let peer_id = self.session_to_peer.remove(session_id).map(|(_, p)| p);
        self.metrics.remove(session_id);
        if let Some(ref pid) = peer_id {
            if let Some(mut ids) = self.by_peer.get_mut(pid) {
                ids.retain(|id| id != session_id);
                let empty = ids.is_empty();
                drop(ids);
                if empty {
                    self.by_peer.remove(pid);
                }
            }
        }
        if let Some(mut list) = self.by_protocol.get_mut(&kind) {
            list.retain(|id| id != session_id);
        }
        session.close().await
    }

    pub async fn close_all_sessions_for_peer(&self, peer_id: &PeerId) -> Result<()> {
        let ids: Vec<SessionId> = self.get_session_ids(peer_id).unwrap_or_default();
        for id in ids {
            self.close_session(&id).await?;
        }
        Ok(())
    }
}
