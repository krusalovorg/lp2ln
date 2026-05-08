mod adapters;
mod clock;
mod engine;
mod events;
mod metrics;
mod network_model;
mod runner;
mod types;

pub use adapters::RUNTIME_INTEGRATION_HOOKS;
pub use adapters::{
    BasicHeuristicAdapter, IntegrationHook, NodeActionPlan, SimNodeObservation,
    TopologyDecisionAdapter,
};
pub use clock::SimClock;
pub use engine::{SimConfig, TopologySimEngine};
pub use events::{SimulationEvent, SimulationEventKind};
pub use metrics::SimulationMetrics;
pub use network_model::{BasicNetworkModel, ChurnProfile, LatencyBucket};
pub use runner::{
    ScenarioConfig, ScenarioMetricsRow, run_baseline_scenario, run_baseline_size_sweep,
    run_baseline_size_sweep_by_ticks_per_node, run_scenario_with_adapter,
};
pub use types::{SimEdge, SimNodeId, SimNodeState, SimPeerView, TopologySnapshot};
