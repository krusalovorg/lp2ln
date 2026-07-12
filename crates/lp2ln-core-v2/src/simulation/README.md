# Topology Simulation Scaffold

This module provides a design-stage scaffold for topology simulation without running full node runtimes.

## Scope of this stage

- Event-driven simulation with virtual time.
- Node state and graph snapshot types.
- Adapter contract for topology decisions.
- Basic realism model:
  - dial success probability,
  - latency bucket approximation,
  - churn probability per tick.

## Explicit non-goals

- No integration with real transports or sockets.
- No NAT/STUN/TURN behavior simulation in this stage.
- No protocol packet execution.
- No changes in production runtime path.

## Runtime integration hooks

Planned integration references are defined in `simulation::topology::RUNTIME_INTEGRATION_HOOKS` and map to:

- `src/node/topology_maintenance/mod.rs`: tick orchestration and dial execution.
- `src/node/topology_maintenance/policy.rs`: policy snapshot and adaptive targets.
- `src/node/topology_maintenance/state.rs`: mutable maintenance state fields.

## Invariants

- Simulation edge set is undirected (`SimEdge` canonical ordering).
- Offline nodes cannot establish new successful dials.
- Disconnect removes edge and updates both peer views.
- Virtual time never moves backward.

## Next integration step

Implement a concrete adapter that translates `SimNodeObservation` into `NodeActionPlan`
using existing policy logic from topology maintenance while preserving runtime behavior.

## Network routing simulation (packet bench)

The `simulation::network` module wires converged topology snapshots to real
`Router` + `DefaultPacketProcessor` instances via in-memory `LinkedSession` links.
It measures multi-hop delivery between the farthest pair of nodes in the graph.

### Run network sim benchmark

```bash
cargo bench -p lp2ln-core-v2 --bench network_sim_bench
cargo bench -p lp2ln-core-v2 --bench network_sim_bench -- network_sim_single_delivery
```

Groups:

- `network_sim_setup` — topology converge + SimNetwork build (10/100/1000 nodes)
- `network_sim_single_delivery` — one packet farthest-pair latency (100/1000 nodes)
- `network_sim_flood` — sequential farthest-pair flood throughput (100/1000 nodes)
- `network_sim_live` — full NodeRuntime chain validation (10/20 nodes)

### Run routing regression tests

```bash
cargo test -p lp2ln-core-v2 --test network_sim_routing
```


- Fast local run:
  - `cargo test -p lp2ln-core-v2 --test topology_sim_regression -- --nocapture`
- Filter only simulation regression tests:
  - `cargo test -p lp2ln-core-v2 topology_sim_regression_ -- --nocapture`
- Run size sweep report for topology (10/50/100/1000):
  - `cargo test -p lp2ln-core-v2 --test topology_sim_size_sweep -- --nocapture`
  - Sweep now uses a proportional budget (`ticks_per_node`) so large graphs are not under-simulated.

## Suggested workflow for topology changes

1. Change topology logic.
2. Run simulation regression tests.
3. Run size sweep test for 10/50/100/1000.
4. Compare key metrics in test output and assertion thresholds:
   - `average_degree`,
   - `isolated_nodes`,
   - `connected_components`,
   - `online_nodes` (for churn scenario).
5. If thresholds fail, treat as topology regression and inspect action planning behavior.
