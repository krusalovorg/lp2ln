use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::node::options::DirectUpgradeConfig;
use crate::types::PeerId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeState {
    Idle,
    Candidate,
    Dialing,
    NatTraversal,
    Cooldown,
}

struct PeerEntry {
    events: VecDeque<(Instant, u64)>,
    last_seen: Instant,
    last_upgrade_attempt: Option<Instant>,
    failed_attempts: u32,
    success_attempts: u32,
    state: UpgradeState,
    cooldown_until: Option<Instant>,
}

impl PeerEntry {
    fn new(now: Instant) -> Self {
        Self {
            events: VecDeque::new(),
            last_seen: now,
            last_upgrade_attempt: None,
            failed_attempts: 0,
            success_attempts: 0,
            state: UpgradeState::Idle,
            cooldown_until: None,
        }
    }

    fn normalize_cooldown(&mut self, now: Instant) {
        if matches!(self.state, UpgradeState::Cooldown) {
            if let Some(until) = self.cooldown_until {
                if now >= until {
                    self.state = UpgradeState::Idle;
                    self.cooldown_until = None;
                }
            }
        }
    }

    fn effective_state(&self, now: Instant) -> UpgradeState {
        if matches!(self.state, UpgradeState::Cooldown) {
            if let Some(until) = self.cooldown_until {
                if now >= until {
                    return UpgradeState::Idle;
                }
            }
        }
        self.state
    }

    fn prune(&mut self, window: Duration, now: Instant) {
        while let Some((t, _)) = self.events.front() {
            if now.duration_since(*t) > window {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    fn window_stats(&self) -> (usize, u64) {
        let packets = self.events.len();
        let bytes: u64 = self.events.iter().map(|(_, b)| *b).sum();
        (packets, bytes)
    }
}

pub struct TrafficDemandTracker {
    inner: Mutex<HashMap<PeerId, PeerEntry>>,
    max_peers: usize,
}

impl TrafficDemandTracker {
    pub fn new(max_peers: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_peers: max_peers.max(64),
        }
    }

    fn evict_lru(map: &mut HashMap<PeerId, PeerEntry>, max: usize) {
        if map.len() < max {
            return;
        }
        // Never evict a peer that is mid-attempt (Dialing / NatTraversal):
        // its entry is awaited by an in-flight upgrade task, and removing it
        // would make the subsequent mark_success/mark_failure silently no-op,
        // leaking the slot and stranding the attempt.
        if let Some(oldest) = map
            .iter()
            .filter(|(_, e)| !matches!(e.state, UpgradeState::Dialing | UpgradeState::NatTraversal))
            .min_by_key(|(_, e)| e.last_seen)
            .map(|(k, _)| k.clone())
        {
            map.remove(&oldest);
        }
    }

    pub fn record_fallback(&self, peer_id: PeerId, bytes: u64, cfg: &DirectUpgradeConfig) {
        let now = Instant::now();
        let window = Duration::from_secs(cfg.window_secs.max(1));
        let mut map = self.inner.lock().expect("tracker lock");
        Self::evict_lru(&mut map, self.max_peers);
        let e = map.entry(peer_id).or_insert_with(|| PeerEntry::new(now));
        e.normalize_cooldown(now);
        if matches!(e.effective_state(now), UpgradeState::Cooldown) {
            e.last_seen = now;
            return;
        }
        e.last_seen = now;
        e.prune(window, now);
        e.events.push_back((now, bytes));

        let (pkts, total_bytes) = e.window_stats();
        let meets = pkts >= cfg.min_packets_per_window && total_bytes >= cfg.min_bytes_per_window;
        let eff = e.effective_state(now);
        if matches!(eff, UpgradeState::Dialing | UpgradeState::NatTraversal) {
            return;
        }
        if meets && matches!(eff, UpgradeState::Idle) {
            e.state = UpgradeState::Candidate;
        }
        if !meets && matches!(e.state, UpgradeState::Candidate) {
            e.state = UpgradeState::Idle;
        }
    }

    pub fn mark_dialing(&self, peer_id: &PeerId) {
        let now = Instant::now();
        let mut map = self.inner.lock().expect("tracker lock");
        if let Some(e) = map.get_mut(peer_id) {
            e.normalize_cooldown(now);
            e.state = UpgradeState::Dialing;
            e.last_upgrade_attempt = Some(now);
        }
    }

    pub fn mark_nat_traversal(&self, peer_id: &PeerId) {
        let now = Instant::now();
        let mut map = self.inner.lock().expect("tracker lock");
        if let Some(e) = map.get_mut(peer_id) {
            e.normalize_cooldown(now);
            e.state = UpgradeState::NatTraversal;
        }
    }

    pub fn mark_success(&self, peer_id: &PeerId) {
        let now = Instant::now();
        let mut map = self.inner.lock().expect("tracker lock");
        if let Some(e) = map.get_mut(peer_id) {
            e.normalize_cooldown(now);
            e.success_attempts = e.success_attempts.saturating_add(1);
            e.events.clear();
            e.state = UpgradeState::Idle;
            e.cooldown_until = None;
        }
    }

    pub fn mark_failure(&self, peer_id: &PeerId, cooldown: Duration) {
        let now = Instant::now();
        let mut map = self.inner.lock().expect("tracker lock");
        if let Some(e) = map.get_mut(peer_id) {
            e.failed_attempts = e.failed_attempts.saturating_add(1);
            e.events.clear();
            e.state = UpgradeState::Cooldown;
            e.cooldown_until = Some(now + cooldown);
        }
    }

    /// Another subsystem established a session; stop upgrade work without counting as dial success.
    pub fn mark_satisfied_by_existing_session(&self, peer_id: &PeerId) {
        let now = Instant::now();
        let mut map = self.inner.lock().expect("tracker lock");
        if let Some(e) = map.get_mut(peer_id) {
            e.normalize_cooldown(now);
            e.events.clear();
            e.state = UpgradeState::Idle;
            e.cooldown_until = None;
        }
    }

    pub fn pick_candidate(&self, cfg: &DirectUpgradeConfig) -> Option<PeerId> {
        let now = Instant::now();
        let window = Duration::from_secs(cfg.window_secs.max(1));
        let cooldown = Duration::from_secs(cfg.cooldown_secs.max(1));
        let mut map = self.inner.lock().expect("tracker lock");

        let mut first: Option<PeerId> = None;
        for (pid, e) in map.iter_mut() {
            e.normalize_cooldown(now);
            e.prune(window, now);
            let eff = e.effective_state(now);
            if matches!(
                eff,
                UpgradeState::Dialing | UpgradeState::NatTraversal | UpgradeState::Cooldown
            ) {
                continue;
            }
            let (pkts, total_bytes) = e.window_stats();
            let meets =
                pkts >= cfg.min_packets_per_window && total_bytes >= cfg.min_bytes_per_window;
            if meets && matches!(eff, UpgradeState::Idle) {
                e.state = UpgradeState::Candidate;
            }
            if !meets && matches!(e.state, UpgradeState::Candidate) {
                e.state = UpgradeState::Idle;
            }
            if e.state != UpgradeState::Candidate {
                continue;
            }
            let can_attempt = e
                .last_upgrade_attempt
                .map(|t| now.duration_since(t) >= cooldown)
                .unwrap_or(true);
            if can_attempt {
                first = Some(pid.clone());
                break;
            }
        }
        first
    }

    pub fn state_of(&self, peer_id: &PeerId) -> Option<UpgradeState> {
        let now = Instant::now();
        let map = self.inner.lock().expect("tracker lock");
        map.get(peer_id).map(|e| e.effective_state(now))
    }

    pub fn window_counts(&self, peer_id: &PeerId, cfg: &DirectUpgradeConfig) -> (usize, u64) {
        let now = Instant::now();
        let window = Duration::from_secs(cfg.window_secs.max(1));
        let mut map = self.inner.lock().expect("tracker lock");
        let Some(e) = map.get_mut(peer_id) else {
            return (0, 0);
        };
        e.normalize_cooldown(now);
        e.prune(window, now);
        e.window_stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> DirectUpgradeConfig {
        DirectUpgradeConfig {
            enabled: true,
            min_packets_per_window: 3,
            min_bytes_per_window: 10,
            window_secs: 60,
            cooldown_secs: 10,
            max_parallel_attempts: 1,
            prefer_lan_addrs: true,
            try_nat_traversal: false,
            direct_dial_timeout_ms: 1000,
            event_queue_cap: 128,
            tick_interval_ms: 10,
            max_tracker_peers: 1024,
        }
    }

    #[test]
    fn becomes_candidate_after_n_packets() {
        let t = TrafficDemandTracker::new(1024);
        let c = cfg();
        let p = PeerId::from("abc");
        t.record_fallback(p.clone(), 5, &c);
        t.record_fallback(p.clone(), 5, &c);
        assert_ne!(t.state_of(&p).unwrap(), UpgradeState::Candidate);
        t.record_fallback(p.clone(), 5, &c);
        assert_eq!(t.state_of(&p).unwrap(), UpgradeState::Candidate);
    }

    #[test]
    fn cooldown_blocks_pick() {
        let t = TrafficDemandTracker::new(1024);
        let mut c = cfg();
        c.cooldown_secs = 3600;
        let p = PeerId::from("peer1");
        for _ in 0..3 {
            t.record_fallback(p.clone(), 10, &c);
        }
        assert_eq!(t.state_of(&p).unwrap(), UpgradeState::Candidate);
        t.mark_dialing(&p);
        t.mark_failure(&p, Duration::from_secs(c.cooldown_secs));
        assert_eq!(t.pick_candidate(&c), None);
    }

    #[test]
    fn traffic_during_cooldown_does_not_accumulate_or_promote() {
        let t = TrafficDemandTracker::new(1024);
        let mut c = cfg();
        c.cooldown_secs = 60;
        let p = PeerId::from("peer-cd");
        for _ in 0..3 {
            t.record_fallback(p.clone(), 10, &c);
        }
        t.mark_dialing(&p);
        t.mark_failure(&p, Duration::from_secs(c.cooldown_secs));
        for _ in 0..100 {
            t.record_fallback(p.clone(), 1000, &c);
        }
        assert_eq!(t.window_counts(&p, &c).0, 0);
        assert_ne!(t.state_of(&p).unwrap(), UpgradeState::Candidate);
    }
}
