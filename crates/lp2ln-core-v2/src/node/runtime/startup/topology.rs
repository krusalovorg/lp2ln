use std::panic::AssertUnwindSafe;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use futures::FutureExt;

use crate::node::addressing::detect_lan_advertise_ip;
use crate::node::runtime::startup::context::{RuntimeService, StartupContext};
use crate::node::topology_maintenance::run_topology_maintenance_loop;
use crate::protocol::handshake;

pub struct TopologyService;

impl RuntimeService for TopologyService {
    fn name(&self) -> &'static str {
        "topology"
    }

    fn enabled(&self, ctx: &StartupContext<'_>) -> bool {
        ctx.options.enable_topology_maintenance
    }

    fn spawn(&self, ctx: &mut StartupContext<'_>) -> Result<()> {
        let bootstrap_targets_maint = ctx.bootstrap_targets.clone().unwrap_or_default();
        let advertise_fallback_ip =
            detect_lan_advertise_ip(&bootstrap_targets_maint, &ctx.options.default_nodes);
        let policy_live = ctx.peer_connection_policy_live.clone();
        let node_role = ctx.options.node_role;
        let weights = ctx.options.peer_score_weights.clone();
        let sm = ctx.session_manager.clone();
        let dial_book = ctx.dial_book.clone();
        let peer_store = ctx.session_manager.peer_score_store();
        let catalog = ctx.peer_catalog.clone();
        let db = ctx.db.clone();
        let listens = ctx.options.listens.clone();
        let advertise_addrs = ctx.options.advertise_addrs.clone();
        let transports = ctx.transports.to_vec();
        let router = ctx
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("router not initialized"))?
            .clone();
        let incoming = router.incoming_sender();
        let our_peer = ctx.keypair.peer_id().to_string();
        let descriptor_ver = ctx.descriptor_version.clone();
        let signing_key = ctx.keypair.signing_key().clone();
        let log_peer_scores = ctx.options.log_peer_score_snapshot;
        let topology_tuning = ctx.options.topology_tuning.clone();
        let mut obf_protocols: Vec<String> =
            ctx.options.transport_obfuscation.keys().cloned().collect();
        obf_protocols.sort();
        let maintenance_handshake = handshake::encode_hello(obf_protocols);
        let nat_state = ctx.nat_state.clone();
        let bootstrap_dedupe = ctx.bootstrap_dial_dedupe.clone();
        let bootstrap_ok = ctx.bootstrap_dial_ok_ms.clone();
        let health = ctx.health.clone();
        let cancel_topology = ctx.producer_cancel.clone();
        let session_redial_queue = ctx.session_redial_queue.clone();
        let react_to_session_events = ctx.options.topology_react_to_session_events;
        let dial_policy = ctx.options.dial_policy.clone();
        ctx.supervisor.spawn("topology", async move {
            let mut backoff = Duration::from_millis(500);
            loop {
                if cancel_topology.is_cancelled() {
                    break;
                }
                let result = tokio::select! {
                    _ = cancel_topology.cancelled() => break,
                    result = AssertUnwindSafe(run_topology_maintenance_loop(
                        cancel_topology.clone(),
                        policy_live.clone(),
                        node_role,
                        weights.clone(),
                        sm.clone(),
                        dial_book.clone(),
                        peer_store.clone(),
                        catalog.clone(),
                        db.clone(),
                        listens.clone(),
                        advertise_addrs.clone(),
                        advertise_fallback_ip,
                        transports.clone(),
                        router.clone(),
                        incoming.clone(),
                        our_peer.clone(),
                        descriptor_ver.clone(),
                        signing_key.clone(),
                        log_peer_scores,
                        topology_tuning.clone(),
                        maintenance_handshake.clone(),
                        bootstrap_targets_maint.clone(),
                        nat_state.clone(),
                        bootstrap_dedupe.clone(),
                        bootstrap_ok.clone(),
                        Some(session_redial_queue.clone()),
                        react_to_session_events,
                        dial_policy.clone(),
                    ))
                    .catch_unwind() => result,
                };
                match result {
                    Ok(Ok(_)) => {
                        backoff = Duration::from_millis(500);
                        health.mark_healthy();
                    }
                    Ok(Err(err)) => {
                        health.topology_restarts.fetch_add(1, Ordering::Relaxed);
                        health.record_error("topology_loop", err.to_string());
                    }
                    Err(_) => {
                        health.topology_restarts.fetch_add(1, Ordering::Relaxed);
                        health.record_error("topology_loop", "panic in topology loop");
                    }
                }
                tokio::select! {
                    _ = cancel_topology.cancelled() => break,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(15));
            }
        });
        Ok(())
    }
}
