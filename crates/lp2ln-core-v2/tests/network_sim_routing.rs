use std::time::Duration;

use lp2ln_core_v2::simulation::network::{
    SimNetwork, line_snapshot, make_routing_packet, make_routing_packet_with_id,
    wait_for_deliveries, wait_for_unique_deliveries,
};
use lp2ln_core_v2::simulation::topology::{ScenarioConfig, run_baseline_scenario};

const MAX_HOPS: u8 = 32;
const WAIT: Duration = Duration::from_secs(10);

async fn converged_snapshot(
    node_count: usize,
) -> lp2ln_core_v2::simulation::topology::TopologySnapshot {
    let scenario = ScenarioConfig {
        node_count,
        steps: node_count.saturating_mul(150),
    };
    run_baseline_scenario(scenario).0
}

#[tokio::test]
async fn delivers_across_farthest_pair_10_nodes() {
    let snapshot = converged_snapshot(10).await;
    let pair = SimNetwork::farthest_pair_from_snapshot(&snapshot).expect("farthest pair");
    let network = SimNetwork::from_topology_snapshot(&snapshot)
        .await
        .expect("network");
    let sender = network.peer_id(pair.source).to_string();
    let receiver = network.peer_id(pair.target).to_string();
    let mut rx = network.subscribe(pair.target);
    let packet = make_routing_packet(&sender, &receiver, 128, MAX_HOPS);
    network.send_from(pair.source, packet).await.expect("send");
    let metrics = wait_for_deliveries(&mut rx, 1, &sender, &receiver, WAIT).await;
    network.shutdown().await;
    assert_eq!(metrics.delivered, 1, "packet must reach farthest node");
    assert!(metrics.total_hops <= MAX_HOPS as usize);
}

#[tokio::test]
async fn hop_count_near_shortest_path() {
    let snapshot = converged_snapshot(10).await;
    let pair = SimNetwork::farthest_pair_from_snapshot(&snapshot).expect("farthest pair");
    let shortest = pair.distance;
    let network = SimNetwork::from_topology_snapshot(&snapshot)
        .await
        .expect("network");
    let sender = network.peer_id(pair.source).to_string();
    let receiver = network.peer_id(pair.target).to_string();
    let mut rx = network.subscribe(pair.target);
    let packet = make_routing_packet(&sender, &receiver, 64, MAX_HOPS);
    network.send_from(pair.source, packet).await.expect("send");
    let metrics = wait_for_deliveries(&mut rx, 1, &sender, &receiver, WAIT).await;
    network.shutdown().await;
    assert_eq!(metrics.delivered, 1);
    let actual_hops = metrics.total_hops;
    assert!(
        actual_hops <= shortest + 2,
        "actual hops {actual_hops} exceed shortest {shortest} + 2 (fallback overhead)"
    );
}

#[tokio::test]
async fn drops_when_max_hops_exhausted() {
    let snapshot = line_snapshot(5);
    let network = SimNetwork::from_topology_snapshot(&snapshot)
        .await
        .expect("network");
    let sender = network.peer_id(0).to_string();
    let receiver = network.peer_id(4).to_string();
    let mut rx = network.subscribe(4);
    let packet = make_routing_packet(&sender, &receiver, 32, 2);
    network.send_from(0, packet).await.expect("send");
    let metrics = wait_for_deliveries(&mut rx, 1, &sender, &receiver, WAIT).await;
    network.shutdown().await;
    assert_eq!(
        metrics.delivered, 0,
        "line of 5 nodes should not deliver with max_hops=2"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn flood_delivery_rate_above_threshold() {
    let snapshot = converged_snapshot(50).await;
    let pair = SimNetwork::farthest_pair_from_snapshot(&snapshot).expect("farthest pair");
    let network = SimNetwork::from_topology_snapshot(&snapshot)
        .await
        .expect("network");
    let sender = network.peer_id(pair.source).to_string();
    let receiver = network.peer_id(pair.target).to_string();
    const COUNT: usize = 20;
    let mut rx = network.subscribe(pair.target);
    for i in 0..COUNT {
        let packet =
            make_routing_packet_with_id(&sender, &receiver, 256, MAX_HOPS, Some(i as u64 + 1));
        network
            .send_from(pair.source, packet)
            .await
            .expect("flood send");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let metrics =
        wait_for_unique_deliveries(&mut rx, COUNT, &sender, &receiver, Duration::from_secs(120))
            .await;
    network.shutdown().await;
    assert!(
        metrics.delivery_rate() >= 0.95,
        "delivery rate {:.1}% below 95% (delivered {}/{})",
        metrics.delivery_rate() * 100.0,
        metrics.delivered,
        metrics.sent
    );
}
