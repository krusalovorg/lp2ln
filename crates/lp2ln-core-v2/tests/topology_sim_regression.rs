use lp2ln_core_v2::simulation::topology::{
    BasicNetworkModel, ScenarioConfig, SimConfig, run_baseline_scenario,
};

#[test]
fn topology_sim_regression_steady_mesh_keeps_reasonable_degree() {
    let scenario = ScenarioConfig {
        node_count: 96,
        steps: 6_000,
    };
    let (_, metrics) = run_baseline_scenario(scenario);
    println!("steady metrics: {:?}", metrics);

    assert!(
        metrics.average_degree >= 0.7,
        "avg_degree={}",
        metrics.average_degree
    );
    assert!(
        metrics.largest_component_ratio >= 0.1,
        "largest_component_ratio={}",
        metrics.largest_component_ratio
    );
    assert!(
        metrics.connected_components <= metrics.online_nodes,
        "components={}, online_nodes={}",
        metrics.connected_components,
        metrics.online_nodes
    );
}

#[test]
fn topology_sim_regression_churn_does_not_collapse_mesh() {
    let scenario = ScenarioConfig {
        node_count: 128,
        steps: 8_000,
    };
    let mut model = BasicNetworkModel::baseline();
    model.churn.offline_probability_per_tick = 0.015;
    model.churn.online_probability_per_tick = 0.10;
    let sim_config = SimConfig {
        tick_interval_ms: 5_000,
        random_seed: 42,
    };

    let (_, metrics) = lp2ln_core_v2::simulation::topology::run_scenario_with_adapter(
        scenario,
        sim_config,
        model,
        lp2ln_core_v2::simulation::topology::BasicHeuristicAdapter::default(),
    );
    println!("churn metrics: {:?}", metrics);

    assert!(
        metrics.online_nodes >= 70,
        "online_nodes={}",
        metrics.online_nodes
    );
    assert!(
        metrics.average_degree >= 0.5,
        "avg_degree={}",
        metrics.average_degree
    );
    assert!(metrics.degree_p95 >= 1, "degree_p95={}", metrics.degree_p95);
}
