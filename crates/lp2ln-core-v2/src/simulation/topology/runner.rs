use super::adapters::{BasicHeuristicAdapter, TopologyDecisionAdapter};
use super::engine::{SimConfig, TopologySimEngine};
use super::metrics::SimulationMetrics;
use super::network_model::BasicNetworkModel;
use super::types::TopologySnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScenarioConfig {
    pub node_count: usize,
    pub steps: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioMetricsRow {
    pub scenario: ScenarioConfig,
    pub metrics: SimulationMetrics,
}

impl Default for ScenarioConfig {
    fn default() -> Self {
        Self {
            node_count: 128,
            steps: 4_000,
        }
    }
}

pub fn run_scenario_with_adapter<D: TopologyDecisionAdapter>(
    scenario: ScenarioConfig,
    sim_config: SimConfig,
    network_model: BasicNetworkModel,
    adapter: D,
) -> (TopologySnapshot, SimulationMetrics) {
    let snapshot = TopologySnapshot::with_node_count(scenario.node_count);
    let mut engine = TopologySimEngine::new(sim_config, network_model, snapshot, adapter);
    engine.bootstrap_tick_schedule();
    engine.run_steps(scenario.steps);
    let metrics = SimulationMetrics::from_snapshot(&engine.snapshot);
    (engine.snapshot, metrics)
}

pub fn run_baseline_scenario(scenario: ScenarioConfig) -> (TopologySnapshot, SimulationMetrics) {
    run_scenario_with_adapter(
        scenario,
        SimConfig::default(),
        BasicNetworkModel::baseline(),
        BasicHeuristicAdapter::default(),
    )
}

pub fn run_baseline_size_sweep(node_sizes: &[usize], steps: usize) -> Vec<ScenarioMetricsRow> {
    let mut rows = Vec::with_capacity(node_sizes.len());
    for node_count in node_sizes {
        let scenario = ScenarioConfig {
            node_count: *node_count,
            steps,
        };
        let (_, metrics) = run_baseline_scenario(scenario);
        rows.push(ScenarioMetricsRow { scenario, metrics });
    }
    rows
}

pub fn run_baseline_size_sweep_by_ticks_per_node(
    node_sizes: &[usize],
    ticks_per_node: usize,
) -> Vec<ScenarioMetricsRow> {
    let mut rows = Vec::with_capacity(node_sizes.len());
    for node_count in node_sizes {
        let scenario = ScenarioConfig {
            node_count: *node_count,
            steps: node_count.saturating_mul(ticks_per_node),
        };
        let (_, metrics) = run_baseline_scenario(scenario);
        rows.push(ScenarioMetricsRow { scenario, metrics });
    }
    rows
}
