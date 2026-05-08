use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::packet::Packet;
use crate::protocol::control::{NatAnswerPayload, NatCandidate, NatOfferPayload};
use crate::sessions::{LinkKind, Session, SessionMetrics};
use crate::types::{PeerId, SessionId};

#[async_trait]
pub trait PacketPublisher: Send + Sync {
    async fn send_to_session(&self, session_id: SessionId, packet: Packet) -> Result<u64>;

    async fn send_to_peer(
        &self,
        peer_id: PeerId,
        packet: Packet,
        exclude_from: Option<PeerId>,
    ) -> Result<u64>;
}

#[async_trait]
pub trait SessionRegistry: Send + Sync {
    fn register_session(
        &self,
        peer_id: PeerId,
        session_id: SessionId,
        session: Arc<dyn Session + Send + Sync>,
    );

    fn register_session_only(&self, session_id: SessionId, session: Arc<dyn Session + Send + Sync>);

    fn set_peer_for_session(&self, session_id: SessionId, peer_id: PeerId);

    async fn teardown_session(&self, session_id: &SessionId) -> Result<()>;
}

pub trait SessionSelector: Send + Sync {
    fn session(&self, session_id: &SessionId) -> Option<Arc<dyn Session + Send + Sync>>;

    fn best_session_for_peer(&self, peer_id: &PeerId) -> Option<Arc<dyn Session + Send + Sync>>;

    fn connected_peers(&self) -> Vec<PeerId>;

    fn peers_sorted_by_score(&self) -> Vec<PeerId>;
}

pub trait MetricsProvider: Send + Sync {
    fn record_packets_sent(&self, session_id: &SessionId, bytes: u64);

    fn record_send_error(&self, session_id: &SessionId);

    fn record_packets_received(&self, session_id: &SessionId, bytes: u64);

    fn get_metrics_for_protocol(&self, kind: LinkKind) -> Vec<SessionMetrics>;

    fn get_metrics_by_protocol(&self) -> Vec<(LinkKind, Vec<SessionMetrics>)>;

    fn peer_metrics_rollup(&self) -> Vec<(PeerId, Vec<SessionMetrics>)>;

    fn total_sessions_count(&self) -> usize;
}

pub trait NatTraversalPort: Send + Sync {
    fn cleanup_expired(&self);

    fn create_offer(
        &self,
        session_id: String,
        peer_id: String,
        local_candidates: Vec<NatCandidate>,
    ) -> NatOfferPayload;

    fn handle_offer(
        &self,
        from: &str,
        offer: &NatOfferPayload,
        local_candidates: Vec<NatCandidate>,
    ) -> NatAnswerPayload;

    fn handle_answer(&self, from: &str, answer: &NatAnswerPayload) -> Option<u64>;

    fn mark_punch_start(&self, session_id: &str, start_after_ms: u64);

    fn mark_punching(&self, session_id: &str);

    fn mark_result(
        &self,
        session_id: &str,
        success: bool,
        selected_addr: Option<String>,
        reason: Option<String>,
    );
}
