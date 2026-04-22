use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use tokio::time::Instant;

use crate::protocol::control::{NatAnswerPayload, NatCandidate, NatOfferPayload};
use crate::topology::now_ms;

const NAT_SESSION_TTL_MS: u64 = 120_000;
const DEFAULT_PUNCH_DELAY_MS: u64 = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatSessionStage {
    OfferCreated,
    OfferReceived,
    AnswerSent,
    AnswerReceived,
    PunchScheduled,
    Punching,
    Established,
    Failed,
}

#[derive(Debug, Clone)]
pub struct NatTraversalSession {
    pub session_id: String,
    pub peer_id: String,
    pub stage: NatSessionStage,
    pub local_candidates: Vec<NatCandidate>,
    pub remote_candidates: Vec<NatCandidate>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub start_after_ms: Option<u64>,
    pub selected_addr: Option<String>,
    pub failure_reason: Option<String>,
}

impl NatTraversalSession {
    fn new(
        session_id: String,
        peer_id: String,
        stage: NatSessionStage,
        local_candidates: Vec<NatCandidate>,
        remote_candidates: Vec<NatCandidate>,
    ) -> Self {
        let now = now_ms();
        Self {
            session_id,
            peer_id,
            stage,
            local_candidates,
            remote_candidates,
            created_at_ms: now,
            updated_at_ms: now,
            start_after_ms: None,
            selected_addr: None,
            failure_reason: None,
        }
    }
}

#[derive(Debug)]
pub struct NatTraversalState {
    sessions: DashMap<String, NatTraversalSession>,
    next_cleanup_deadline: DashMap<&'static str, Instant>,
    started: AtomicU64,
    succeeded: AtomicU64,
    failed: AtomicU64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::control::{NatCandidate, NatCandidateKind};

    #[test]
    fn state_machine_offer_answer_flow() {
        let state = NatTraversalState::new();
        let local = vec![NatCandidate {
            protocol: "udp".to_string(),
            addr: "10.0.0.2:8081".to_string(),
            kind: NatCandidateKind::Host,
            priority: 100,
        }];
        let offer = state.create_offer(
            "sess-a".to_string(),
            "peer-b".to_string(),
            local.clone(),
        );
        assert_eq!(offer.session_id, "sess-a");
        let answer = state.handle_offer("peer-a", &offer, local);
        assert_eq!(answer.session_id, "sess-a");
        let delay = state.handle_answer("peer-b", &answer).expect("delay");
        assert!(delay > 0);
        let jobs = state.take_punch_jobs();
        assert_eq!(jobs.len(), 1);
        state.mark_result("sess-a", true, Some("1.2.3.4:9999".to_string()), None);
        let snap = state.session("sess-a").expect("session");
        assert_eq!(snap.stage, NatSessionStage::Established);
    }
}

impl NatTraversalState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: DashMap::new(),
            next_cleanup_deadline: DashMap::new(),
            started: AtomicU64::new(0),
            succeeded: AtomicU64::new(0),
            failed: AtomicU64::new(0),
        })
    }

    pub fn create_offer(
        &self,
        session_id: String,
        peer_id: String,
        local_candidates: Vec<NatCandidate>,
    ) -> NatOfferPayload {
        let payload = NatOfferPayload {
            session_id: session_id.clone(),
            candidates: local_candidates.clone(),
        };
        let session = NatTraversalSession::new(
            session_id.clone(),
            peer_id,
            NatSessionStage::OfferCreated,
            local_candidates,
            vec![],
        );
        self.sessions.insert(session_id, session);
        self.started.fetch_add(1, Ordering::Relaxed);
        payload
    }

    pub fn handle_offer(&self, from: &str, offer: &NatOfferPayload, local_candidates: Vec<NatCandidate>) -> NatAnswerPayload {
        let mut session = NatTraversalSession::new(
            offer.session_id.clone(),
            from.to_string(),
            NatSessionStage::OfferReceived,
            local_candidates.clone(),
            offer.candidates.clone(),
        );
        session.stage = NatSessionStage::AnswerSent;
        session.updated_at_ms = now_ms();
        self.sessions.insert(offer.session_id.clone(), session);
        NatAnswerPayload {
            session_id: offer.session_id.clone(),
            candidates: local_candidates,
        }
    }

    pub fn handle_answer(&self, from: &str, answer: &NatAnswerPayload) -> Option<u64> {
        let mut entry = self.sessions.get_mut(&answer.session_id)?;
        entry.peer_id = from.to_string();
        entry.remote_candidates = answer.candidates.clone();
        entry.stage = NatSessionStage::PunchScheduled;
        entry.updated_at_ms = now_ms();
        entry.start_after_ms = Some(DEFAULT_PUNCH_DELAY_MS);
        Some(DEFAULT_PUNCH_DELAY_MS)
    }

    pub fn mark_punch_start(&self, session_id: &str, start_after_ms: u64) {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.stage = NatSessionStage::PunchScheduled;
            session.start_after_ms = Some(start_after_ms);
            session.updated_at_ms = now_ms();
        }
    }

    pub fn mark_punching(&self, session_id: &str) {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.stage = NatSessionStage::Punching;
            session.updated_at_ms = now_ms();
        }
    }

    pub fn mark_result(
        &self,
        session_id: &str,
        success: bool,
        selected_addr: Option<String>,
        reason: Option<String>,
    ) {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.stage = if success {
                NatSessionStage::Established
            } else {
                NatSessionStage::Failed
            };
            session.selected_addr = selected_addr;
            session.failure_reason = reason;
            session.updated_at_ms = now_ms();
            if success {
                self.succeeded.fetch_add(1, Ordering::Relaxed);
            } else {
                self.failed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn session(&self, session_id: &str) -> Option<NatTraversalSession> {
        self.sessions.get(session_id).map(|s| s.clone())
    }

    pub fn take_punch_jobs(&self) -> Vec<NatTraversalSession> {
        let mut jobs = Vec::new();
        for mut entry in self.sessions.iter_mut() {
            if entry.stage == NatSessionStage::PunchScheduled {
                entry.stage = NatSessionStage::Punching;
                entry.updated_at_ms = now_ms();
                jobs.push(entry.clone());
            }
        }
        jobs
    }

    pub fn sessions_len(&self) -> usize {
        self.sessions.len()
    }

    pub fn metrics(&self) -> (u64, u64, u64) {
        (
            self.started.load(Ordering::Relaxed),
            self.succeeded.load(Ordering::Relaxed),
            self.failed.load(Ordering::Relaxed),
        )
    }

    pub fn cleanup_expired(&self) {
        let key = "cleanup";
        let now = Instant::now();
        if let Some(deadline) = self.next_cleanup_deadline.get(key) {
            if now < *deadline {
                return;
            }
        }
        self.next_cleanup_deadline
            .insert(key, now + Duration::from_secs(5));

        let cutoff = now_ms().saturating_sub(NAT_SESSION_TTL_MS);
        self.sessions.retain(|_, s| s.updated_at_ms >= cutoff);
    }
}

