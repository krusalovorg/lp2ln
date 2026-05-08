use lp2ln_core_v2::simulation::topology::run_baseline_size_sweep_by_ticks_per_node;

#[test]
fn topology_sim_size_sweep_10_50_100_1000_reports_metrics() {
    let rows = run_baseline_size_sweep_by_ticks_per_node(&[10, 50, 100, 1000], 150);
    assert_eq!(rows.len(), 4);

    println!(
        "node_count,online_nodes,online_ratio,edge_count,average_degree,degree_p95,isolated_nodes,connected_components,largest_component_size,largest_component_ratio"
    );
    for row in &rows {
        println!(
            "{},{},{:.4},{},{:.4},{},{},{},{},{:.4}",
            row.scenario.node_count,
            row.metrics.online_nodes,
            row.metrics.online_ratio,
            row.metrics.edge_count,
            row.metrics.average_degree,
            row.metrics.degree_p95,
            row.metrics.isolated_nodes,
            row.metrics.connected_components,
            row.metrics.largest_component_size,
            row.metrics.largest_component_ratio
        );
    }

    for row in rows {
        assert!(
            row.metrics.connected_components <= row.metrics.online_nodes,
            "components must not exceed online nodes for size {}",
            row.scenario.node_count
        );
        assert!(
            row.metrics.average_degree.is_finite(),
            "average_degree must be finite for size {}",
            row.scenario.node_count
        );
        assert!(
            row.metrics.largest_component_ratio.is_finite(),
            "largest_component_ratio must be finite for size {}",
            row.scenario.node_count
        );
    }
}
