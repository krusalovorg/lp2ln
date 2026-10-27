//! Happy-eyeballs dialing across transports, where "connected" means the
//! remote node actually answered — not merely that a socket opened.
//!
//! Carrier filtering often lets the TCP/UDP handshake through and then drops
//! the payload, so a dial that only checks `connect()` happily keeps dead
//! links. Here each attempt sends our hello and waits for the first packet
//! back; attempts start staggered in ranked order, the first verified one
//! wins, and every outcome (losers included) is fed to the scoreboard.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use futures::stream::FuturesUnordered;

use super::scoreboard::PathFailure;
use crate::packet::Packet;
use crate::router::Router;
use crate::sessions::session::IncomingPacket;
use crate::topology::now_ms;
use crate::transport::Transport;
use crate::types::SessionId;

#[derive(Debug, Clone, Copy)]
pub struct RaceConfig {
    /// Head start each attempt gets before the next candidate is launched.
    pub stagger: Duration,
    pub connect_timeout: Duration,
    /// How long to wait for the first packet back after sending the hello.
    pub verify_timeout: Duration,
}

impl Default for RaceConfig {
    fn default() -> Self {
        Self {
            stagger: Duration::from_millis(400),
            connect_timeout: Duration::from_secs(6),
            verify_timeout: Duration::from_secs(8),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RaceWinner {
    pub session_id: SessionId,
    pub transport: String,
    pub addr: SocketAddr,
    pub rtt_ms: u64,
}

pub struct RaceCandidate {
    pub transport: Arc<dyn Transport>,
    pub addr: SocketAddr,
    pub peer_hint: Option<String>,
}

const VERIFY_POLL: Duration = Duration::from_millis(20);

async fn attempt(
    candidate: RaceCandidate,
    router: Arc<Router>,
    incoming: tokio::sync::mpsc::Sender<IncomingPacket>,
    hello: Packet,
    cfg: RaceConfig,
) -> Result<RaceWinner, ()> {
    let name = candidate.transport.name();
    let addr = candidate.addr;
    let dial = candidate
        .transport
        .dial_with_peer(addr, candidate.peer_hint.as_deref());
    let session = match tokio::time::timeout(cfg.connect_timeout, dial).await {
        Ok(Ok(session)) => session,
        Ok(Err(e)) => {
            crate::net_dial!("[LinkSurvival] {} {} connect failed: {}", name, addr, e);
            router
                .paths()
                .record_failure(name, addr, PathFailure::Connect, now_ms());
            return Err(());
        }
        Err(_) => {
            crate::net_dial!("[LinkSurvival] {} {} connect timed out", name, addr);
            router
                .paths()
                .record_failure(name, addr, PathFailure::Connect, now_ms());
            return Err(());
        }
    };

    let session_id = SessionId::from(session.id().to_string());
    router.register_session_only(session_id.clone(), session.clone());
    session.spawn_reader(incoming);
    let sent_at = Instant::now();
    if let Err(e) = router.send_to_session(session_id.clone(), hello).await {
        crate::net_dial!("[LinkSurvival] {} {} hello failed: {}", name, addr, e);
        let _ = router.teardown_session(&session_id).await;
        router
            .paths()
            .record_failure(name, addr, PathFailure::Connect, now_ms());
        return Err(());
    }

    while sent_at.elapsed() < cfg.verify_timeout {
        if router.session_has_received(&session_id) {
            let rtt_ms = sent_at.elapsed().as_millis() as u64;
            router.paths().record_success(name, addr, rtt_ms);
            crate::info!("[LinkSurvival] {} {} verified in {} ms", name, addr, rtt_ms);
            return Ok(RaceWinner {
                session_id,
                transport: name.to_string(),
                addr,
                rtt_ms,
            });
        }
        tokio::time::sleep(VERIFY_POLL).await;
    }

    crate::warn!(
        "[LinkSurvival] {} {} connected but node never answered, dropping path",
        name,
        addr
    );
    let _ = router.teardown_session(&session_id).await;
    router
        .paths()
        .record_failure(name, addr, PathFailure::Silent, now_ms());
    Err(())
}

/// Races `candidates` (already in preference order). Returns the first path
/// whose node answered, or `None` when every attempt failed. Attempts still in
/// flight when a winner is found are finished in the background so their
/// outcome is still learned, and their sessions are closed.
pub async fn race_verified_dial(
    candidates: Vec<RaceCandidate>,
    router: Arc<Router>,
    incoming: tokio::sync::mpsc::Sender<IncomingPacket>,
    hello: Packet,
    cfg: RaceConfig,
) -> Option<RaceWinner> {
    let mut pending = candidates.into_iter();
    let mut running = FuturesUnordered::new();
    let launch =
        |c: RaceCandidate| attempt(c, router.clone(), incoming.clone(), hello.clone(), cfg);
    running.push(launch(pending.next()?));

    let winner = loop {
        let next_launch = tokio::time::sleep(cfg.stagger);
        tokio::pin!(next_launch);
        tokio::select! {
            done = running.next() => match done {
                Some(Ok(w)) => break Some(w),
                // A failed attempt frees its slot right away.
                Some(Err(())) => match pending.next() {
                    Some(c) => running.push(launch(c)),
                    None if running.is_empty() => break None,
                    None => {}
                },
                None => break None,
            },
            _ = &mut next_launch => {
                if let Some(c) = pending.next() {
                    running.push(launch(c));
                }
            }
        }
    };

    if !running.is_empty() {
        let router = router.clone();
        tokio::spawn(async move {
            while let Some(result) = running.next().await {
                if let Ok(late) = result {
                    let _ = router.teardown_session(&late.session_id).await;
                }
            }
        });
    }
    winner
}
