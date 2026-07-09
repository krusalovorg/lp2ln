use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use dashmap::DashMap;

use crate::peer_score::{PeerScoreStore, PeerScoreWeights, total_score};
use crate::services::{MetricsProvider, SessionRegistry, SessionSelector};
use crate::sessions::session::LinkKind;
use crate::sessions::{Session, SessionMetrics};
use crate::types::{PeerId, SessionId};

use crate::event_core::prelude::{CoreBus, CoreEvent, SessionEvent, TransportProtocol};

pub trait SessionSelectionStrategy: Send + Sync {
    fn rank(
        &self,
        peer_id: &PeerId,
        session_id: &SessionId,
        kind: LinkKind,
        metrics: &SessionMetrics,
    ) -> f32;
}

pub struct DefaultSessionStrategy {
    peer_scores: Arc<PeerScoreStore>,
    weights: PeerScoreWeights,
}

impl SessionSelectionStrategy for DefaultSessionStrategy {
    fn rank(
        &self,
        peer_id: &PeerId,
        _session_id: &SessionId,
        kind: LinkKind,
        metrics: &SessionMetrics,
    ) -> f32 {
        let peer_score = self.peer_scores.get(peer_id);
        let base = total_score(&peer_score, &self.weights);
        let packets = metrics.total_packets().max(1) as f32;
        let err_rate = (metrics.total_errors() as f32 / packets).min(1.0);
        let stale = (metrics.time_since_last_activity().as_secs_f32() / 120.0).min(1.0);
        let priority =
            base - self.weights.w_latency * stale * 0.35 - self.weights.w_load * err_rate;
        let damp = (1.0 - err_rate).clamp(0.0, 1.0);
        let link_bonus = match kind {
            LinkKind::DirectQuic => 0.10 * damp,
            LinkKind::DirectTcp | LinkKind::DirectUdp => 0.08 * damp,
            LinkKind::TunnelTcp | LinkKind::TunnelUdp => 0.03 * damp,
            LinkKind::Relay => 0.0,
        };
        priority + link_bonus
    }
}

pub struct SessionManager {
    sessions: Arc<DashMap<SessionId, Arc<dyn Session + Send + Sync>>>,
    by_peer: Arc<DashMap<PeerId, Vec<SessionId>>>,
    session_to_peer: Arc<DashMap<SessionId, PeerId>>,
    metrics: Arc<DashMap<SessionId, SessionMetrics>>,
    by_protocol: Arc<DashMap<LinkKind, Vec<SessionId>>>,
    peer_scores: Arc<PeerScoreStore>,
    peer_weights: PeerScoreWeights,
    strategy: Arc<dyn SessionSelectionStrategy>,
    session_join_timeout: Duration,
    session_events: Option<CoreBus>,
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
    pub fn new(peer_scores: Arc<PeerScoreStore>, peer_weights: PeerScoreWeights) -> Self {
        let strategy = Arc::new(DefaultSessionStrategy {
            peer_scores: peer_scores.clone(),
            weights: peer_weights.clone(),
        });
        Self {
            sessions: Arc::new(DashMap::new()),
            by_peer: Arc::new(DashMap::new()),
            session_to_peer: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            by_protocol: Arc::new(DashMap::new()),
            peer_scores,
            peer_weights,
            strategy,
            session_join_timeout: Duration::from_secs(2),
            session_events: None,
        }
    }

    pub fn with_event_bus(mut self, bus: CoreBus) -> Self {
        self.session_events = Some(bus);
        self
    }

    fn link_kind_to_protocol(kind: LinkKind) -> TransportProtocol {
        match kind {
            LinkKind::DirectTcp | LinkKind::TunnelTcp => TransportProtocol::Tcp,
            LinkKind::DirectUdp | LinkKind::TunnelUdp => TransportProtocol::Udp,
            LinkKind::DirectQuic => TransportProtocol::Quic,
            LinkKind::Relay => TransportProtocol::Relay,
        }
    }

    fn emit_session_event(&self, event: SessionEvent) {
        let Some(bus) = self.session_events.clone() else {
            return;
        };
        tokio::spawn(async move {
            let _ = bus.emit(CoreEvent::Session(event)).await;
        });
    }

    pub fn with_join_timeout(mut self, d: Duration) -> Self {
        self.session_join_timeout = d;
        self
    }

    pub fn with_strategy(mut self, strategy: Arc<dyn SessionSelectionStrategy>) -> Self {
        self.strategy = strategy;
        self
    }

    pub fn peer_score_store(&self) -> Arc<PeerScoreStore> {
        self.peer_scores.clone()
    }

    pub fn peer_weights(&self) -> &PeerScoreWeights {
        &self.peer_weights
    }

    fn add_to_protocol(&self, kind: LinkKind, session_id: SessionId) {
        self.by_protocol.entry(kind).or_default().push(session_id);
    }

    pub fn register(
        &self,
        peer_id: PeerId,
        session_id: SessionId,
        session: Arc<dyn Session + Send + Sync>,
    ) {
        self.peer_scores.touch_peer(&peer_id);
        let kind = session.kind();
        self.add_to_protocol(kind, session_id.clone());
        self.sessions.insert(session_id.clone(), session);
        self.metrics
            .insert(session_id.clone(), SessionMetrics::new());
        self.session_to_peer
            .insert(session_id.clone(), peer_id.clone());
        self.by_peer
            .entry(peer_id.clone())
            .or_default()
            .push(session_id.clone());
        self.emit_session_event(SessionEvent::Accepted {
            session_id,
            peer_id: Some(peer_id),
            transport: Self::link_kind_to_protocol(kind),
        });
    }

    pub fn register_session(&self, session_id: SessionId, session: Arc<dyn Session + Send + Sync>) {
        let kind = session.kind();
        self.add_to_protocol(kind, session_id.clone());
        self.sessions.insert(session_id.clone(), session);
        self.metrics
            .insert(session_id.clone(), SessionMetrics::new());
        self.emit_session_event(SessionEvent::Accepted {
            session_id,
            peer_id: None,
            transport: Self::link_kind_to_protocol(kind),
        });
    }

    pub fn set_peer_for_session(&self, session_id: SessionId, peer_id: PeerId) {
        if self.session_to_peer.contains_key(&session_id) {
            return;
        }
        self.peer_scores.touch_peer(&peer_id);
        self.session_to_peer
            .insert(session_id.clone(), peer_id.clone());
        self.by_peer
            .entry(peer_id.clone())
            .or_default()
            .push(session_id.clone());
        self.emit_session_event(SessionEvent::BoundToPeer {
            session_id,
            peer_id,
        });
    }

    pub fn peer_has_link_kind(&self, peer_id: &PeerId, kind: LinkKind) -> bool {
        let Some(ids) = self.get_session_ids(peer_id) else {
            return false;
        };
        ids.iter().any(|id| {
            self.sessions
                .get(id)
                .map(|s| s.kind() == kind)
                .unwrap_or(false)
        })
    }

    pub fn get(&self, session_id: &SessionId) -> Option<Arc<dyn Session + Send + Sync>> {
        self.sessions.get(session_id).map(|s| s.clone())
    }

    pub fn get_session_ids(&self, peer_id: &PeerId) -> Option<Vec<SessionId>> {
        self.by_peer.get(peer_id).map(|v| v.clone())
    }

    pub fn get_all_for_peer(&self, peer_id: &PeerId) -> Vec<Arc<dyn Session + Send + Sync>> {
        let Some(ids_ref) = self.by_peer.get(peer_id) else {
            return vec![];
        };
        let ids = ids_ref.clone();
        drop(ids_ref);

        ids.into_iter().filter_map(|id| self.get(&id)).collect()
    }

    pub fn get_all_peers(&self) -> Vec<PeerId> {
        self.by_peer.iter().map(|r| r.key().clone()).collect()
    }

    pub fn get_all_peers_sorted_by_score(&self) -> Vec<PeerId> {
        let peers = self.get_all_peers();
        crate::peer_score::rank_peers(&peers, |p| self.peer_scores.get(p), &self.peer_weights)
    }

    pub fn get_best_session_for_peer(
        &self,
        peer_id: &PeerId,
    ) -> Option<Arc<dyn Session + Send + Sync>> {
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
            let Some(metrics) = self.get_metrics(&session_id) else {
                continue;
            };
            let rank = self
                .strategy
                .rank(peer_id, &session_id, session.kind(), &metrics);
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

    /// All registered session IDs, including sessions not yet bound to a
    /// PeerId (handshake/redirect). Used for full drain at node shutdown.
    pub fn all_session_ids(&self) -> Vec<SessionId> {
        self.sessions.iter().map(|e| e.key().clone()).collect()
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
        self.by_peer.len()
    }

    pub fn is_connected_to_peer(&self, peer_id: &PeerId) -> bool {
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
        let close_result = session.close().await;
        // Join the session's reader/writer tasks so they do not outlive the
        // session. The reader holds an ingress-channel sender clone, so
        // joining it before shutdown closes the router ingress lets the
        // router drain cleanly. Bounded: a hung writer must not stall us.
        if tokio::time::timeout(self.session_join_timeout, session.join_tasks())
            .await
            .is_err()
        {
            crate::warn!(
                "[SessionManager] session '{}' tasks did not finish within {:?}",
                session_id,
                self.session_join_timeout
            );
        }
        self.emit_session_event(SessionEvent::Closed {
            session_id: session_id.clone(),
            peer_id,
            reason: None,
        });
        close_result
    }

    pub async fn close_all_sessions_for_peer(&self, peer_id: &PeerId) -> Result<()> {
        let ids: Vec<SessionId> = self.get_session_ids(peer_id).unwrap_or_default();
        for id in ids {
            self.close_session(&id).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl SessionRegistry for SessionManager {
    fn register_session(
        &self,
        peer_id: PeerId,
        session_id: SessionId,
        session: Arc<dyn Session + Send + Sync>,
    ) {
        SessionManager::register(self, peer_id, session_id, session);
    }

    fn register_session_only(
        &self,
        session_id: SessionId,
        session: Arc<dyn Session + Send + Sync>,
    ) {
        SessionManager::register_session(self, session_id, session);
    }

    fn set_peer_for_session(&self, session_id: SessionId, peer_id: PeerId) {
        SessionManager::set_peer_for_session(self, session_id, peer_id);
    }

    async fn teardown_session(&self, session_id: &SessionId) -> Result<()> {
        SessionManager::close_session(self, session_id).await
    }
}

impl SessionSelector for SessionManager {
    fn session(&self, session_id: &SessionId) -> Option<Arc<dyn Session + Send + Sync>> {
        SessionManager::get(self, session_id)
    }

    fn best_session_for_peer(&self, peer_id: &PeerId) -> Option<Arc<dyn Session + Send + Sync>> {
        SessionManager::get_best_session_for_peer(self, peer_id)
    }

    fn connected_peers(&self) -> Vec<PeerId> {
        SessionManager::get_all_peers(self)
    }

    fn peers_sorted_by_score(&self) -> Vec<PeerId> {
        SessionManager::get_all_peers_sorted_by_score(self)
    }
}

impl MetricsProvider for SessionManager {
    fn record_packets_sent(&self, session_id: &SessionId, bytes: u64) {
        self.update_metrics(session_id, |m| m.increment_packets_sent(bytes));
    }

    fn record_send_error(&self, session_id: &SessionId) {
        self.update_metrics(session_id, |m| m.increment_send_errors());
    }

    fn record_packets_received(&self, session_id: &SessionId, bytes: u64) {
        self.update_metrics(session_id, |m| m.increment_packets_received(bytes));
    }

    fn get_metrics_for_protocol(&self, kind: LinkKind) -> Vec<SessionMetrics> {
        SessionManager::get_metrics_for_protocol(self, kind)
    }

    fn get_metrics_by_protocol(&self) -> Vec<(LinkKind, Vec<SessionMetrics>)> {
        SessionManager::get_metrics_by_protocol(self)
    }

    fn peer_metrics_rollup(&self) -> Vec<(PeerId, Vec<SessionMetrics>)> {
        SessionManager::peer_metrics_rollup(self)
    }

    fn total_sessions_count(&self) -> usize {
        SessionManager::total_sessions_count(self)
    }
}

#[cfg(test)]
mod link_kind_rank_tests {
    use super::*;
    use anyhow::Result;
    use async_trait::async_trait;

    use crate::packet::Packet;
    use crate::sessions::session::IncomingPacket;

    struct KindSession {
        id: String,
        kind: LinkKind,
        peer: String,
    }

    #[async_trait]
    impl Session for KindSession {
        fn id(&self) -> &str {
            &self.id
        }

        fn peer_id(&self) -> Option<&str> {
            Some(&self.peer)
        }

        fn kind(&self) -> LinkKind {
            self.kind
        }

        async fn send(&self, _packet: Packet) -> Result<u64> {
            Ok(0)
        }

        async fn close(&self) -> Result<()> {
            Ok(())
        }

        fn spawn_reader(self: Arc<Self>, _tx: tokio::sync::mpsc::Sender<IncomingPacket>) {}
    }

    #[test]
    fn best_session_prefers_direct_when_metrics_equal() {
        let store = Arc::new(PeerScoreStore::new());
        let mgr = SessionManager::new(store, PeerScoreWeights::default());
        let peer = PeerId::from("same-peer");
        let tun = Arc::new(KindSession {
            id: "t1".into(),
            kind: LinkKind::TunnelTcp,
            peer: peer.as_str().to_string(),
        }) as Arc<dyn Session + Send + Sync>;
        let dir = Arc::new(KindSession {
            id: "d1".into(),
            kind: LinkKind::DirectTcp,
            peer: peer.as_str().to_string(),
        }) as Arc<dyn Session + Send + Sync>;
        mgr.register(peer.clone(), SessionId::from("t1"), tun.clone());
        mgr.register(peer.clone(), SessionId::from("d1"), dir.clone());
        let best = mgr.get_best_session_for_peer(&peer).expect("session");
        assert_eq!(best.kind(), LinkKind::DirectTcp);
    }
}
