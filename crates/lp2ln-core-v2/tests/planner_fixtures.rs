/// fixture tests: verify SmartMeshPlanner produces correct decisions
/// for canned TopologySnapshot inputs. Network I/O is not involved.
use std::collections::{HashMap, HashSet};

use lp2ln_core_v2::node::options::{NodeRole, TopologyTuning};
use lp2ln_core_v2::peer_score::{PeerConnectionPolicy, PeerScoreWeights};
use lp2ln_core_v2::topology::{
    CapacityBudget, PeerCandidate, SmartMeshPlanner, TopologyPlanner, TopologySnapshot,
};
use lp2ln_core_v2::types::PeerId;

fn peer(s: &str) -> PeerId {
    PeerId::from(s)
}

fn base_snapshot() -> TopologySnapshot {
    TopologySnapshot {
        our_peer_id: peer("aabbcc"),
        node_role: NodeRole::Regular,
        policy: PeerConnectionPolicy {
            min_active_peers: 4,
            target_active_peers: 8,
            max_active_peers: 16,
        },
        weights: PeerScoreWeights::default(),
        topology_tuning: TopologyTuning::default(),
        connected_peers: vec![],
        connected_bootstrap_count: 0,
        known_peer_count: 50,
        peer_total_scores: HashMap::new(),
        bootstrap_peer_ids: HashSet::new(),
        descriptor_active_conns: HashMap::new(),
        catalog_descriptors: vec![],
        capacity: CapacityBudget::default(),
        dial_book: HashMap::new(),
        dial_cooldowns: HashMap::new(),
        peer_age_ms: HashMap::new(),
        bootstrap_targets_count: 3,
        last_bootstrap_reseed_ms: 0,
        now_ms: 60_000,
    }
}

#[test]
fn dial_when_under_target() {
    let planner = SmartMeshPlanner;
    let mut snap = base_snapshot();

    // 2 connected, target 8 → should want to dial
    snap.connected_peers = vec![peer("p1"), peer("p2")];
    snap.dial_book.insert(peer("p3"), vec![("tcp".into(), "127.0.0.1:9003".parse().unwrap())]);
    snap.dial_book.insert(peer("p4"), vec![("tcp".into(), "127.0.0.1:9004".parse().unwrap())]);

    let plan = planner.plan(&snap);

    assert!(!plan.dial.is_empty(), "should dial when under target");
    assert!(plan.drop.is_empty(), "should not drop when under target");
}

#[test]
fn no_dial_when_at_target() {
    let planner = SmartMeshPlanner;
    let mut snap = base_snapshot();

    // Exactly at target
    snap.connected_peers = (0..8).map(|i| peer(&format!("peer{i:02}"))).collect();
    for (i, p) in snap.connected_peers.iter().enumerate() {
        snap.dial_book.insert(
            p.clone(),
            vec![("tcp".into(), format!("127.0.0.1:{}", 9000 + i).parse().unwrap())],
        );
    }

    let plan = planner.plan(&snap);

    assert!(plan.dial.is_empty(), "should not dial when at target");
}

#[test]
fn drop_when_over_max() {
    let planner = SmartMeshPlanner;
    let mut snap = base_snapshot();

    // 20 connected, max 16 → should drop
    snap.connected_peers = (0..20).map(|i| peer(&format!("peer{i:02}"))).collect();
    // give them scores so drop selection is deterministic
    for (i, p) in snap.connected_peers.iter().enumerate() {
        snap.peer_total_scores.insert(p.clone(), i as f32 * 0.1);
    }

    let plan = planner.plan(&snap);

    assert!(!plan.drop.is_empty(), "should drop when over max");
    assert!(plan.drop.len() <= 20, "should not drop more than connected count");
}

#[test]
fn discovery_when_under_target() {
    let planner = SmartMeshPlanner;
    let mut snap = base_snapshot();

    // 2 connected, target 8 → should request peers
    snap.connected_peers = vec![peer("p1"), peer("p2")];

    let plan = planner.plan(&snap);

    assert!(!plan.discovery.is_empty(), "should request peers when under target");
    let req_from = &plan.discovery[0].request_from;
    assert!(req_from.contains(&peer("p1")) && req_from.contains(&peer("p2")));
}

#[test]
fn no_self_dial() {
    let planner = SmartMeshPlanner;
    let mut snap = base_snapshot();

    // dial_book contains our own peer_id
    snap.dial_book.insert(
        snap.our_peer_id.clone(),
        vec![("tcp".into(), "127.0.0.1:9000".parse().unwrap())],
    );

    let plan = planner.plan(&snap);

    assert!(
        plan.dial.iter().all(|d| d.peer_id != snap.our_peer_id),
        "must never dial self"
    );
}

#[test]
fn cooldown_peers_not_dialed() {
    let planner = SmartMeshPlanner;
    let mut snap = base_snapshot();

    let p = peer("coolpeer");
    snap.dial_book
        .insert(p.clone(), vec![("tcp".into(), "127.0.0.1:9001".parse().unwrap())]);
    // cooldown expires in the future
    snap.dial_cooldowns.insert(p.clone(), snap.now_ms + 60_000);

    let plan = planner.plan(&snap);

    assert!(
        plan.dial.iter().all(|d| d.peer_id != p),
        "must not dial peer in cooldown"
    );
}

#[test]
fn admission_accept_when_under_hard_limit() {
    let planner = SmartMeshPlanner;
    let mut snap = base_snapshot();
    snap.connected_peers = (0..4).map(|i| peer(&format!("c{i}"))).collect(); // target=8, hard limit > 4

    let candidate = PeerCandidate { peer_id: peer("newcomer"), is_bootstrap_entry: false };
    let decision = planner.evaluate_incoming(&snap, &candidate);

    assert!(
        matches!(decision, lp2ln_core_v2::topology::AdmissionDecision::Accept),
        "should accept when well under limit"
    );
}

#[test]
fn admission_redirect_when_over_hard_limit() {
    let planner = SmartMeshPlanner;
    let mut snap = base_snapshot();
    // target=8, headroom=2 → hard limit=10 for Regular; connect 12
    snap.connected_peers = (0..12).map(|i| peer(&format!("c{i:02}"))).collect();

    let candidate = PeerCandidate { peer_id: peer("newcomer"), is_bootstrap_entry: false };
    let decision = planner.evaluate_incoming(&snap, &candidate);

    assert!(
        matches!(decision, lp2ln_core_v2::topology::AdmissionDecision::Redirect { .. }),
        "should redirect when over hard limit"
    );
}
