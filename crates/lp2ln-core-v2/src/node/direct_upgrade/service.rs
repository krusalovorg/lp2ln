use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use crate::node::options::DirectUpgradeConfig;
use crate::router::Router;
use crate::sessions::manager::SessionManager;
use crate::topology::PeerCatalog;
use crate::types::PeerId;

use super::addrs::ranked_dial_targets;
use super::dialer::{CoreNatTraversalTrigger, DirectDialer, NatTraversalTrigger};
use super::event::DirectUpgradeEvent;
use super::tracker::TrafficDemandTracker;

pub struct DirectUpgradeContext {
    pub config: DirectUpgradeConfig,
    pub our_peer_id: String,
    pub router: Arc<Router>,
    pub session_manager: Arc<SessionManager>,
    pub peer_catalog: Arc<PeerCatalog>,
    pub dial_book: Arc<DashMap<PeerId, Vec<(String, std::net::SocketAddr)>>>,
    pub listens: HashMap<String, std::net::SocketAddr>,
    pub advertise: HashMap<String, std::net::SocketAddr>,
    pub dialer: Arc<dyn DirectDialer>,
    pub nat: Option<Arc<dyn NatTraversalTrigger>>,
    pub tracker: Arc<TrafficDemandTracker>,
}

pub async fn run_direct_upgrade_loop(
    mut rx: mpsc::Receiver<DirectUpgradeEvent>,
    ctx: DirectUpgradeContext,
    cancel: CancellationToken,
) {
    if !ctx.config.enabled {
        return;
    }
    let tick = Duration::from_millis(ctx.config.tick_interval_ms.max(50));
    let cfg = ctx.config.clone();
    let router = ctx.router.clone();
    let session_manager = ctx.session_manager.clone();
    let catalog = ctx.peer_catalog.clone();
    let dial_book = ctx.dial_book.clone();
    let listens = ctx.listens.clone();
    let advertise = ctx.advertise.clone();
    let dialer = ctx.dialer.clone();
    let nat = ctx.nat.clone();
    let tracker = ctx.tracker.clone();
    let our_peer_id = ctx.our_peer_id.clone();
    let parallel = Arc::new(Semaphore::new(cfg.max_parallel_attempts.max(1).min(32)));

    let mut interval = tokio::time::interval(tick);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            ev = rx.recv() => {
                match ev {
                    Some(DirectUpgradeEvent::FallbackTraffic { peer_id, bytes }) => {
                        if !session_manager.get_all_for_peer(&peer_id).is_empty() {
                            continue;
                        }
                        tracker.record_fallback(peer_id, bytes, &cfg);
                    }
                    None => break,
                }
            }
            _ = interval.tick() => {
                if !cfg.enabled {
                    continue;
                }
                loop {
                    let Ok(permit) = parallel.clone().try_acquire_owned() else {
                        break;
                    };
                    let Some(peer_id) = tracker.pick_candidate(&cfg) else {
                        drop(permit);
                        break;
                    };
                    if !session_manager.get_all_for_peer(&peer_id).is_empty() {
                        tracker.mark_satisfied_by_existing_session(&peer_id);
                        drop(permit);
                        continue;
                    }
                    tracker.mark_dialing(&peer_id);
                    let router2 = router.clone();
                    let session_manager2 = session_manager.clone();
                    let catalog2 = catalog.clone();
                    let dial_book2 = dial_book.clone();
                    let listens2 = listens.clone();
                    let advertise2 = advertise.clone();
                    let dialer2 = dialer.clone();
                    let nat2 = nat.clone();
                    let tracker2 = tracker.clone();
                    let cfg2 = cfg.clone();
                    let our_id = our_peer_id.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        // If the attempt panics, run_one_upgrade_attempt never
                        // reaches its mark_success/mark_failure calls, leaving the
                        // peer stuck in Dialing forever. The guard releases it on
                        // an unwind; on normal completion we disarm it.
                        let mut guard = DialingAbortGuard {
                            tracker: &tracker2,
                            peer_id: peer_id.clone(),
                            cooldown: Duration::from_secs(cfg2.cooldown_secs.max(1)),
                            armed: true,
                        };
                        run_one_upgrade_attempt(
                            peer_id,
                            our_id.as_str(),
                            &cfg2,
                            &tracker2,
                            &router2,
                            &session_manager2,
                            &catalog2,
                            &dial_book2,
                            &listens2,
                            &advertise2,
                            dialer2.as_ref(),
                            nat2.as_deref(),
                        )
                        .await;
                        guard.armed = false;
                    });
                }
            }
        }
    }
}

/// Releases a peer from the `Dialing`/`NatTraversal` state if the upgrade task
/// is dropped before completing normally (e.g. on a panic). On a clean run the
/// caller sets `armed = false` so this becomes a no-op.
struct DialingAbortGuard<'a> {
    tracker: &'a TrafficDemandTracker,
    peer_id: PeerId,
    cooldown: Duration,
    armed: bool,
}

impl Drop for DialingAbortGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.tracker.mark_failure(&self.peer_id, self.cooldown);
        }
    }
}

async fn run_one_upgrade_attempt(
    peer_id: PeerId,
    our_peer_id: &str,
    cfg: &DirectUpgradeConfig,
    tracker: &TrafficDemandTracker,
    router: &Router,
    session_manager: &SessionManager,
    catalog: &PeerCatalog,
    dial_book: &DashMap<PeerId, Vec<(String, std::net::SocketAddr)>>,
    listens: &HashMap<String, std::net::SocketAddr>,
    advertise: &HashMap<String, std::net::SocketAddr>,
    dialer: &dyn DirectDialer,
    nat: Option<&dyn NatTraversalTrigger>,
) {
    if !session_manager.get_all_for_peer(&peer_id).is_empty() {
        tracker.mark_satisfied_by_existing_session(&peer_id);
        return;
    }
    let targets = ranked_dial_targets(
        &peer_id,
        our_peer_id,
        catalog,
        dial_book,
        listens,
        advertise,
        cfg.prefer_lan_addrs,
    );
    if targets.is_empty() {
        if cfg.try_nat_traversal {
            if let Some(n) = nat {
                if session_manager.get_all_for_peer(&peer_id).is_empty() {
                    tracker.mark_nat_traversal(&peer_id);
                    let _ = n.trigger_nat_traversal(peer_id.clone()).await;
                }
            }
        }
        if !session_manager.get_all_for_peer(&peer_id).is_empty() {
            tracker.mark_satisfied_by_existing_session(&peer_id);
            return;
        }
        tracker.mark_failure(&peer_id, Duration::from_secs(cfg.cooldown_secs.max(1)));
        return;
    }

    let timeout = Duration::from_millis(cfg.direct_dial_timeout_ms.max(200));
    let mut any_ok = false;
    for (transport, addr) in targets {
        if !session_manager.get_all_for_peer(&peer_id).is_empty() {
            tracker.mark_satisfied_by_existing_session(&peer_id);
            return;
        }
        match tokio::time::timeout(
            timeout,
            dialer.direct_connect(transport.as_str(), addr, Some(peer_id.clone())),
        )
        .await
        {
            Ok(Ok(sid)) => {
                router.set_peer_for_session(sid, peer_id.clone());
                any_ok = true;
                break;
            }
            Ok(Err(e)) => {
                crate::debug!(
                    "[direct_upgrade] dial {:?} {} to {} failed: {}",
                    transport,
                    addr,
                    peer_id,
                    e
                );
            }
            Err(_) => {
                crate::debug!(
                    "[direct_upgrade] dial {:?} {} to {} timed out",
                    transport,
                    addr,
                    peer_id
                );
            }
        }
    }

    if any_ok {
        tracker.mark_success(&peer_id);
        crate::info!("[direct_upgrade] direct session established to {}", peer_id);
        return;
    }

    if !session_manager.get_all_for_peer(&peer_id).is_empty() {
        tracker.mark_satisfied_by_existing_session(&peer_id);
        return;
    }

    if cfg.try_nat_traversal {
        if let Some(n) = nat {
            tracker.mark_nat_traversal(&peer_id);
            if let Err(e) = n.trigger_nat_traversal(peer_id.clone()).await {
                crate::debug!(
                    "[direct_upgrade] NAT traversal trigger for {} failed: {}",
                    peer_id,
                    e
                );
            }
        }
    }
    if !session_manager.get_all_for_peer(&peer_id).is_empty() {
        tracker.mark_satisfied_by_existing_session(&peer_id);
        return;
    }
    tracker.mark_failure(&peer_id, Duration::from_secs(cfg.cooldown_secs.max(1)));
}

pub fn nat_trigger_from_parts(
    router: Arc<Router>,
    keypair: crate::crypto::NodeKeypair,
    transports: Vec<Arc<dyn crate::transport::Transport>>,
    listens: HashMap<String, std::net::SocketAddr>,
    nat_state: Arc<crate::nat::NatTraversalState>,
) -> Arc<dyn NatTraversalTrigger> {
    Arc::new(CoreNatTraversalTrigger {
        router,
        keypair,
        transports,
        listens,
        nat_state,
    })
}

#[cfg(test)]
mod service_tests {
    use super::run_one_upgrade_attempt;
    use super::*;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};

    use anyhow::Result;
    use async_trait::async_trait;

    use crate::packet::Packet;
    use crate::packet_processor::PacketProcessor;
    use crate::peer_score::{PeerScoreStore, PeerScoreWeights};
    use crate::sessions::Session;
    use crate::sessions::manager::SessionManager;
    use crate::sessions::session::{IncomingPacket, LinkKind};
    use crate::types::SessionId;

    struct NoopProc;

    #[async_trait::async_trait]
    impl PacketProcessor for NoopProc {
        async fn process(
            &self,
            _incoming_packet: crate::sessions::session::IncomingPacket,
            _router: Arc<Router>,
        ) {
        }
    }

    struct CountDialer(Arc<AtomicU64>);
    #[async_trait]
    impl DirectDialer for CountDialer {
        async fn direct_connect(
            &self,
            _transport_name: &str,
            _addr: std::net::SocketAddr,
            _expected_peer: Option<PeerId>,
        ) -> Result<SessionId> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(anyhow::anyhow!("fail dial"))
        }
    }

    struct CountNat(Arc<AtomicU64>);
    #[async_trait]
    impl NatTraversalTrigger for CountNat {
        async fn trigger_nat_traversal(&self, _peer_id: PeerId) -> Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    fn test_router() -> (Arc<Router>, Arc<SessionManager>) {
        let store = Arc::new(PeerScoreStore::new());
        let mgr = Arc::new(SessionManager::new(store, PeerScoreWeights::default()));
        let (router, _rx) = Router::new(mgr.clone(), Arc::new(NoopProc), None, "self-peer", None);
        (Arc::new(router), mgr)
    }

    #[tokio::test]
    async fn nat_triggered_when_no_addrs_and_try_nat_enabled() {
        let (router, sm) = test_router();
        let cat = PeerCatalog::new();
        let dial_book = Arc::new(DashMap::new());
        let nat_c = Arc::new(AtomicU64::new(0));
        let nat: Arc<dyn NatTraversalTrigger> = Arc::new(CountNat(nat_c.clone()));
        let tracker = TrafficDemandTracker::new(128);
        let mut cfg = DirectUpgradeConfig::default();
        cfg.try_nat_traversal = true;
        cfg.cooldown_secs = 1;

        run_one_upgrade_attempt(
            PeerId::from("p-x"),
            "self-peer",
            &cfg,
            &tracker,
            router.as_ref(),
            sm.as_ref(),
            &cat,
            dial_book.as_ref(),
            &HashMap::new(),
            &HashMap::new(),
            &CountDialer(Arc::new(AtomicU64::new(0))),
            Some(nat.as_ref()),
        )
        .await;

        assert!(nat_c.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test]
    async fn dial_invoked_for_dial_book_entry() {
        let (router, sm) = test_router();
        let cat = PeerCatalog::new();
        let dial_book = Arc::new(DashMap::new());
        let peer = PeerId::from("p-dial");
        dial_book.insert(
            peer.clone(),
            vec![(
                "tcp".into(),
                std::net::SocketAddr::from_str("192.0.2.2:1").unwrap(),
            )],
        );
        let dial_c = Arc::new(AtomicU64::new(0));
        let dialer: Arc<dyn DirectDialer> = Arc::new(CountDialer(dial_c.clone()));
        let tracker = TrafficDemandTracker::new(128);
        let mut cfg = DirectUpgradeConfig::default();
        cfg.try_nat_traversal = false;
        cfg.direct_dial_timeout_ms = 100;

        run_one_upgrade_attempt(
            peer.clone(),
            "self-peer",
            &cfg,
            &tracker,
            router.as_ref(),
            sm.as_ref(),
            &cat,
            dial_book.as_ref(),
            &HashMap::new(),
            &HashMap::new(),
            dialer.as_ref(),
            None,
        )
        .await;

        assert_eq!(dial_c.load(Ordering::Relaxed), 1);
    }

    struct DummyS;

    #[async_trait::async_trait]
    impl Session for DummyS {
        fn id(&self) -> &str {
            "sid-dummy"
        }

        fn peer_id(&self) -> Option<&str> {
            Some("p-have")
        }

        fn kind(&self) -> LinkKind {
            LinkKind::DirectTcp
        }

        async fn send(&self, _packet: Packet) -> Result<u64> {
            Ok(0)
        }

        async fn close(&self) -> Result<()> {
            Ok(())
        }

        fn spawn_reader(self: Arc<Self>, _tx: tokio::sync::mpsc::Sender<IncomingPacket>) {}
    }

    #[tokio::test]
    async fn dial_skipped_when_session_exists_for_peer() {
        let (router, sm) = test_router();
        let peer = PeerId::from("p-have");
        sm.register(
            peer.clone(),
            SessionId::from("sid-dummy"),
            Arc::new(DummyS) as Arc<dyn Session + Send + Sync>,
        );
        let cat = PeerCatalog::new();
        let dial_book = Arc::new(DashMap::new());
        dial_book.insert(
            peer.clone(),
            vec![(
                "tcp".into(),
                std::net::SocketAddr::from_str("192.0.2.3:1").unwrap(),
            )],
        );
        let dial_c = Arc::new(AtomicU64::new(0));
        let dialer: Arc<dyn DirectDialer> = Arc::new(CountDialer(dial_c.clone()));
        let tracker = TrafficDemandTracker::new(128);
        let cfg = DirectUpgradeConfig::default();

        run_one_upgrade_attempt(
            peer,
            "self-peer",
            &cfg,
            &tracker,
            router.as_ref(),
            sm.as_ref(),
            &cat,
            dial_book.as_ref(),
            &HashMap::new(),
            &HashMap::new(),
            dialer.as_ref(),
            None,
        )
        .await;

        assert_eq!(dial_c.load(Ordering::Relaxed), 0);
    }
}
