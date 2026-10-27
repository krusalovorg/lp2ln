//! Finds links that look open but no longer carry anything back, closes them
//! and marks the path, so the normal redial logic picks another protocol.
//!
//! Three failure shapes seen on cellular networks are covered:
//! * ghost handshakes — the socket opened, the remote never answered;
//! * freezes — traffic flowed, then the return direction went silent
//!   (DPI cutting a flow after N kilobytes, a dead NAT mapping);
//! * idle links that died unnoticed — kept honest with periodic pings, which
//!   also keep carrier NAT mappings alive.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use super::scoreboard::PathFailure;
use crate::packet::Packet;
use crate::router::Router;
use crate::sessions::SessionMetrics;
use crate::sessions::session::LinkKind;
use crate::topology::now_ms;
use crate::types::{PeerId, SessionId};

#[derive(Debug, Clone)]
pub struct LinkSnapshot {
    pub session_id: SessionId,
    pub peer_id: Option<PeerId>,
    pub kind: LinkKind,
    pub remote_addr: Option<SocketAddr>,
    pub metrics: SessionMetrics,
}

#[derive(Debug, Clone, Copy)]
pub struct WatchdogConfig {
    pub tick: Duration,
    /// A link that never received anything is dropped after this long.
    pub ghost_after: Duration,
    /// Silence (with our data outstanding) before we start probing.
    pub probe_after: Duration,
    /// Silence (with our data outstanding) after which the link is dead.
    pub freeze_after: Duration,
    /// Ping links with no traffic at all this often.
    pub keepalive_every: Duration,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            tick: Duration::from_secs(2),
            ghost_after: Duration::from_secs(15),
            probe_after: Duration::from_secs(10),
            freeze_after: Duration::from_secs(35),
            keepalive_every: Duration::from_secs(40),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkVerdict {
    Healthy,
    /// Send a ping to force an answer.
    Probe,
    /// Close it and penalise the path.
    Dead(PathFailure),
}

/// Pure decision for one link. `last_probe` is when we last pinged it.
pub fn assess(
    link: &LinkSnapshot,
    cfg: &WatchdogConfig,
    now: Instant,
    last_probe: Option<Instant>,
) -> LinkVerdict {
    // UDP sessions are fire-and-forget by design; relays are judged by the
    // relay's own link.
    if !matches!(
        link.kind,
        LinkKind::DirectTcp | LinkKind::DirectQuic | LinkKind::TunnelTcp
    ) {
        return LinkVerdict::Healthy;
    }
    let m = &link.metrics;
    if m.last_received.is_none()
        && link.peer_id.is_none()
        && now.duration_since(m.created_at) >= cfg.ghost_after
    {
        // A link we dialed whose node never said who it is: nothing to ping.
        return LinkVerdict::Dead(PathFailure::Silent);
    }
    let last_rx = m.last_received.unwrap_or(m.created_at);
    let silent = now.duration_since(last_rx);
    let probed_recently = last_probe.is_some_and(|p| now.duration_since(p) < cfg.probe_after);

    if m.bytes_sent_since_last_receive() > 0 {
        if silent >= cfg.freeze_after && last_probe.is_some_and(|p| p > last_rx) {
            let kind = if m.last_received.is_some() {
                PathFailure::Frozen
            } else {
                PathFailure::Silent
            };
            return LinkVerdict::Dead(kind);
        }
        if silent >= cfg.probe_after && !probed_recently {
            return LinkVerdict::Probe;
        }
        return LinkVerdict::Healthy;
    }
    if now.duration_since(m.last_activity) >= cfg.keepalive_every && !probed_recently {
        return LinkVerdict::Probe;
    }
    LinkVerdict::Healthy
}

fn transport_name(kind: LinkKind) -> &'static str {
    match kind {
        LinkKind::DirectQuic => "quic",
        LinkKind::DirectUdp | LinkKind::TunnelUdp => "udp",
        _ => "tcp",
    }
}

fn ping(our_peer_id: &str, receiver: &PeerId) -> Packet {
    Packet {
        signature: None,
        data: b"ping".to_vec(),
        nodes: vec![],
        sender: our_peer_id.to_string(),
        receiver: receiver.as_str().to_string(),
        max_hops: 1,
        request_id: None,
        chunk_stream_id: None,
        chunk_index: None,
        total_chunks: None,
        protocol_id: None,
    }
}

pub async fn run_link_watchdog(
    router: Arc<Router>,
    our_peer_id: String,
    cfg: WatchdogConfig,
    cancel: CancellationToken,
) {
    let mut last_probe: HashMap<SessionId, Instant> = HashMap::new();
    let mut ticker = tokio::time::interval(cfg.tick);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {}
        }
        let links = router.link_snapshots();
        last_probe.retain(|sid, _| links.iter().any(|l| &l.session_id == sid));
        let now = Instant::now();
        for link in links {
            match assess(&link, &cfg, now, last_probe.get(&link.session_id).copied()) {
                LinkVerdict::Healthy => {}
                LinkVerdict::Probe => {
                    let Some(peer) = link.peer_id.as_ref() else {
                        continue;
                    };
                    last_probe.insert(link.session_id.clone(), now);
                    let _ = router
                        .send_to_session(link.session_id.clone(), ping(&our_peer_id, peer))
                        .await;
                }
                LinkVerdict::Dead(kind) => {
                    let transport = transport_name(link.kind);
                    crate::warn!(
                        "[LinkSurvival] {} link {} to {:?} is dead ({:?}), closing",
                        transport,
                        link.session_id,
                        link.remote_addr,
                        kind
                    );
                    if let Some(addr) = link.remote_addr {
                        router
                            .paths()
                            .record_failure(transport, addr, kind, now_ms());
                    }
                    last_probe.remove(&link.session_id);
                    let _ = router.teardown_session(&link.session_id).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(peer: bool, kind: LinkKind) -> LinkSnapshot {
        LinkSnapshot {
            session_id: SessionId::from("s".to_string()),
            peer_id: peer.then(|| PeerId::from("p")),
            kind,
            remote_addr: Some(SocketAddr::from(([1, 2, 3, 4], 18080))),
            metrics: SessionMetrics::new(),
        }
    }

    fn cfg() -> WatchdogConfig {
        WatchdogConfig::default()
    }

    #[test]
    fn unanswered_dial_becomes_ghost() {
        let l = link(false, LinkKind::DirectTcp);
        let t0 = l.metrics.created_at;
        assert_eq!(
            assess(&l, &cfg(), t0 + Duration::from_secs(5), None),
            LinkVerdict::Healthy
        );
        assert_eq!(
            assess(&l, &cfg(), t0 + Duration::from_secs(16), None),
            LinkVerdict::Dead(PathFailure::Silent)
        );
    }

    #[test]
    fn unanswered_link_with_known_peer_is_probed_before_drop() {
        let mut l = link(true, LinkKind::DirectTcp);
        l.metrics.increment_packets_sent(377);
        let t0 = l.metrics.created_at;
        let probe_at = t0 + Duration::from_secs(11);
        assert_eq!(assess(&l, &cfg(), probe_at, None), LinkVerdict::Probe);
        assert_eq!(
            assess(&l, &cfg(), t0 + Duration::from_secs(36), Some(probe_at)),
            LinkVerdict::Dead(PathFailure::Silent)
        );
    }

    #[test]
    fn udp_links_are_left_alone() {
        let l = link(false, LinkKind::DirectUdp);
        let t0 = l.metrics.created_at;
        assert_eq!(
            assess(&l, &cfg(), t0 + Duration::from_secs(600), None),
            LinkVerdict::Healthy
        );
    }

    #[test]
    fn frozen_link_is_probed_then_dropped() {
        let mut l = link(true, LinkKind::DirectTcp);
        l.metrics.increment_packets_received(100);
        let rx = l.metrics.last_received.unwrap();
        l.metrics.increment_packets_sent(16_000);

        assert_eq!(
            assess(&l, &cfg(), rx + Duration::from_secs(5), None),
            LinkVerdict::Healthy
        );
        let probe_at = rx + Duration::from_secs(11);
        assert_eq!(assess(&l, &cfg(), probe_at, None), LinkVerdict::Probe);
        assert_eq!(
            assess(
                &l,
                &cfg(),
                probe_at + Duration::from_secs(2),
                Some(probe_at)
            ),
            LinkVerdict::Healthy
        );
        assert_eq!(
            assess(&l, &cfg(), rx + Duration::from_secs(36), Some(probe_at)),
            LinkVerdict::Dead(PathFailure::Frozen)
        );
    }

    #[test]
    fn freeze_needs_an_unanswered_probe() {
        let mut l = link(true, LinkKind::DirectQuic);
        l.metrics.increment_packets_received(100);
        let rx = l.metrics.last_received.unwrap();
        l.metrics.increment_packets_sent(500);
        // Never probed: probe first rather than killing on silence alone.
        assert_eq!(
            assess(&l, &cfg(), rx + Duration::from_secs(60), None),
            LinkVerdict::Probe
        );
    }

    #[test]
    fn answered_link_is_healthy_and_idle_gets_keepalive() {
        let mut l = link(true, LinkKind::DirectTcp);
        l.metrics.increment_packets_sent(200);
        l.metrics.increment_packets_received(100);
        let t = l.metrics.last_activity;
        assert_eq!(
            assess(&l, &cfg(), t + Duration::from_secs(30), None),
            LinkVerdict::Healthy
        );
        assert_eq!(
            assess(&l, &cfg(), t + Duration::from_secs(41), None),
            LinkVerdict::Probe
        );
    }
}
