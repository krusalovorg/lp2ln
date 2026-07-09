use std::panic::AssertUnwindSafe;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use futures::FutureExt;

use crate::node::incoming_sessions::run_incoming_session_handler;
use crate::node::runtime::startup::context::{RuntimeService, StartupContext};

pub struct IncomingService;

impl RuntimeService for IncomingService {
    fn name(&self) -> &'static str {
        "incoming"
    }

    fn spawn(&self, ctx: &mut StartupContext<'_>) -> Result<()> {
        let mut incoming_sessions_rx = ctx
            .incoming_sessions_rx
            .take()
            .ok_or_else(|| anyhow::anyhow!("incoming sessions rx missing"))?;
        let session_manager = ctx.session_manager.clone();
        let router = ctx
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("router not initialized"))?
            .clone();
        let incoming_packets_tx = router.incoming_sender();
        let our_peer_id = ctx.keypair.peer_id().to_string();
        let policy_live = ctx.peer_connection_policy_live.clone();
        let catalog = ctx.peer_catalog.clone();
        let peer_store = ctx.session_manager.peer_score_store();
        let weights = ctx.options.peer_score_weights.clone();
        let node_role = ctx.options.node_role;
        let topology_tuning = ctx.options.topology_tuning.clone();
        let discovery_fraction = ctx.options.peer_discovery_random_fraction;
        let health = ctx.health.clone();
        let cancel_incoming = ctx.producer_cancel.clone();
        ctx.supervisor.spawn("incoming", async move {
            let mut backoff = Duration::from_millis(500);
            loop {
                if cancel_incoming.is_cancelled() {
                    break;
                }
                let result = tokio::select! {
                    _ = cancel_incoming.cancelled() => break,
                    result = AssertUnwindSafe(run_incoming_session_handler(
                        cancel_incoming.clone(),
                        &mut incoming_sessions_rx,
                        session_manager.clone(),
                        router.clone(),
                        our_peer_id.clone(),
                        policy_live.clone(),
                        catalog.clone(),
                        peer_store.clone(),
                        weights.clone(),
                        node_role,
                        topology_tuning.clone(),
                        discovery_fraction,
                        incoming_packets_tx.clone(),
                    ))
                    .catch_unwind() => result,
                };
                match result {
                    Ok(Ok(_)) => {
                        backoff = Duration::from_millis(500);
                        health.mark_healthy();
                    }
                    Ok(Err(err)) => {
                        health.incoming_restarts.fetch_add(1, Ordering::Relaxed);
                        health.record_error("incoming_loop", err.to_string());
                    }
                    Err(_) => {
                        health.incoming_restarts.fetch_add(1, Ordering::Relaxed);
                        health.record_error("incoming_loop", "panic in incoming loop");
                    }
                }
                tokio::select! {
                    _ = cancel_incoming.cancelled() => break,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(15));
            }
        });
        Ok(())
    }
}
