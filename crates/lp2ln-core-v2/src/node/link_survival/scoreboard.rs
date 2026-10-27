//! Learns which (transport, endpoint) paths actually work from this network.
//!
//! Every dial outcome and every link that dies mid-flight feeds a recency
//! weighted reliability estimate and an RTT average per path. Dialers ask for
//! a ranking instead of walking a fixed protocol list, so a path that a
//! carrier starts blocking sinks below the alternatives within a few attempts,
//! and comes back once it works again.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

/// How a path failed. Later failures say more about deliberate blocking than
/// an early refusal does, so they are punished harder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathFailure {
    /// Transport-level connect failed or timed out.
    Connect,
    /// Connected, but the peer never answered the handshake (blackholed).
    Silent,
    /// Worked, then stopped delivering anything back (mid-flow freeze / DPI cut).
    Frozen,
}

impl PathFailure {
    fn base_backoff_ms(self) -> u64 {
        match self {
            PathFailure::Connect => 5_000,
            PathFailure::Silent => 20_000,
            PathFailure::Frozen => 30_000,
        }
    }

    fn weight(self) -> f64 {
        match self {
            PathFailure::Connect => 1.0,
            PathFailure::Silent | PathFailure::Frozen => 1.5,
        }
    }
}

const MAX_BACKOFF_MS: u64 = 10 * 60 * 1_000;
/// Old outcomes fade so the ranking follows a changing network.
const DECAY: f64 = 0.8;
const RTT_ALPHA: f64 = 0.3;
/// Assumed handshake RTT for a path we have never measured.
const UNKNOWN_RTT_MS: f64 = 250.0;

#[derive(Debug, Clone, Default)]
struct PathStats {
    successes: f64,
    failures: f64,
    consecutive_failures: u32,
    rtt_ms: Option<f64>,
    backoff_until_ms: u64,
}

impl PathStats {
    fn reliability(&self) -> f64 {
        // Laplace prior: an unknown path counts as a coin flip.
        (self.successes + 1.0) / (self.successes + self.failures + 2.0)
    }

    /// Expected cost of trying this path, in "milliseconds until a working
    /// link": RTT inflated by how often the path fails.
    fn cost(&self) -> f64 {
        self.rtt_ms.unwrap_or(UNKNOWN_RTT_MS) / self.reliability().max(0.02)
    }
}

/// Read-only view of one path, for diagnostics and UI.
#[derive(Debug, Clone, PartialEq)]
pub struct PathReport {
    pub transport: String,
    pub addr: SocketAddr,
    pub reliability: f64,
    pub rtt_ms: Option<f64>,
    pub consecutive_failures: u32,
    pub backoff_remaining_ms: u64,
}

#[derive(Default)]
pub struct PathScoreboard {
    paths: Mutex<HashMap<(String, SocketAddr), PathStats>>,
}

impl PathScoreboard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_success(&self, transport: &str, addr: SocketAddr, rtt_ms: u64) {
        let mut paths = self.paths.lock().unwrap_or_else(|e| e.into_inner());
        let stats = paths.entry((transport.to_string(), addr)).or_default();
        stats.successes = stats.successes * DECAY + 1.0;
        stats.failures *= DECAY;
        stats.consecutive_failures = 0;
        stats.backoff_until_ms = 0;
        let rtt = rtt_ms as f64;
        stats.rtt_ms = Some(match stats.rtt_ms {
            Some(prev) => prev + RTT_ALPHA * (rtt - prev),
            None => rtt,
        });
    }

    pub fn record_failure(
        &self,
        transport: &str,
        addr: SocketAddr,
        kind: PathFailure,
        now_ms: u64,
    ) {
        let mut paths = self.paths.lock().unwrap_or_else(|e| e.into_inner());
        let stats = paths.entry((transport.to_string(), addr)).or_default();
        stats.successes *= DECAY;
        stats.failures = stats.failures * DECAY + kind.weight();
        stats.consecutive_failures = stats.consecutive_failures.saturating_add(1);
        let shift = stats.consecutive_failures.saturating_sub(1).min(16);
        let backoff = kind
            .base_backoff_ms()
            .saturating_mul(1u64 << shift)
            .min(MAX_BACKOFF_MS);
        stats.backoff_until_ms = now_ms.saturating_add(backoff);
    }

    /// The device moved to another network (Wi-Fi <-> cellular, new carrier):
    /// what was blocked there may work here. Lift backoffs and halve the
    /// failure memory, but keep RTTs and successes as a starting guess.
    pub fn network_changed(&self) {
        let mut paths = self.paths.lock().unwrap_or_else(|e| e.into_inner());
        for stats in paths.values_mut() {
            stats.failures *= 0.5;
            stats.consecutive_failures = 0;
            stats.backoff_until_ms = 0;
        }
    }

    pub fn in_backoff(&self, transport: &str, addr: SocketAddr, now_ms: u64) -> bool {
        let paths = self.paths.lock().unwrap_or_else(|e| e.into_inner());
        paths
            .get(&(transport.to_string(), addr))
            .is_some_and(|s| now_ms < s.backoff_until_ms)
    }

    /// Orders candidate paths best first. Paths in backoff go last but are
    /// kept, so a node with nothing better still tries them. Ties keep the
    /// caller's order, which acts as the static preference.
    pub fn rank(
        &self,
        candidates: &[(String, SocketAddr)],
        now_ms: u64,
    ) -> Vec<(String, SocketAddr)> {
        let paths = self.paths.lock().unwrap_or_else(|e| e.into_inner());
        let mut keyed: Vec<(bool, f64, usize, (String, SocketAddr))> = candidates
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let stats = paths.get(c).cloned().unwrap_or_default();
                (now_ms < stats.backoff_until_ms, stats.cost(), i, c.clone())
            })
            .collect();
        keyed.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.total_cmp(&b.1)).then(a.2.cmp(&b.2)));
        keyed.into_iter().map(|(_, _, _, c)| c).collect()
    }

    pub fn report(&self, now_ms: u64) -> Vec<PathReport> {
        let paths = self.paths.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<PathReport> = paths
            .iter()
            .map(|((transport, addr), s)| PathReport {
                transport: transport.clone(),
                addr: *addr,
                reliability: s.reliability(),
                rtt_ms: s.rtt_ms,
                consecutive_failures: s.consecutive_failures,
                backoff_remaining_ms: s.backoff_until_ms.saturating_sub(now_ms),
            })
            .collect();
        out.sort_by(|a, b| (a.addr, &a.transport).cmp(&(b.addr, &b.transport)));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 1], port))
    }

    fn cands() -> Vec<(String, SocketAddr)> {
        vec![
            ("quic".to_string(), addr(18280)),
            ("tcp".to_string(), addr(18080)),
        ]
    }

    #[test]
    fn unknown_paths_keep_static_order() {
        let board = PathScoreboard::new();
        assert_eq!(board.rank(&cands(), 0), cands());
    }

    #[test]
    fn blocked_protocol_sinks_below_working_one() {
        let board = PathScoreboard::new();
        board.record_failure("quic", addr(18280), PathFailure::Silent, 0);
        board.record_success("tcp", addr(18080), 90);
        let ranked = board.rank(&cands(), 1_000);
        assert_eq!(ranked[0].0, "tcp");
        assert_eq!(ranked[1].0, "quic");
    }

    #[test]
    fn backoff_grows_and_expires() {
        let board = PathScoreboard::new();
        board.record_failure("tcp", addr(18080), PathFailure::Connect, 0);
        assert!(board.in_backoff("tcp", addr(18080), 4_999));
        assert!(!board.in_backoff("tcp", addr(18080), 5_000));
        board.record_failure("tcp", addr(18080), PathFailure::Connect, 5_000);
        assert!(board.in_backoff("tcp", addr(18080), 14_999));
        assert!(!board.in_backoff("tcp", addr(18080), 15_000));
    }

    #[test]
    fn path_recovers_after_success() {
        let board = PathScoreboard::new();
        for t in 0..3 {
            board.record_failure("tcp", addr(18080), PathFailure::Frozen, t);
        }
        board.record_success("tcp", addr(18080), 50);
        assert!(!board.in_backoff("tcp", addr(18080), 10));
        board.record_success("tcp", addr(18080), 50);
        board.record_success("tcp", addr(18080), 50);
        board.record_success("quic", addr(18280), 400);
        assert_eq!(board.rank(&cands(), 10)[0].0, "tcp");
    }

    #[test]
    fn faster_reliable_path_wins() {
        let board = PathScoreboard::new();
        board.record_success("tcp", addr(18080), 300);
        board.record_success("quic", addr(18280), 60);
        assert_eq!(board.rank(&cands(), 0)[0].0, "quic");
    }

    #[test]
    fn network_change_lifts_backoff() {
        let board = PathScoreboard::new();
        board.record_failure("quic", addr(18280), PathFailure::Frozen, 0);
        assert!(board.in_backoff("quic", addr(18280), 1));
        board.network_changed();
        assert!(!board.in_backoff("quic", addr(18280), 1));
    }
}
