use std::panic::AssertUnwindSafe;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use futures::FutureExt;

use crate::node::runtime::health::SharedHealth;
use crate::node::runtime::startup::context::{RuntimeService, StartupContext};
use crate::router::RouterRunOutcome;

pub struct RouterService;

impl RuntimeService for RouterService {
    fn name(&self) -> &'static str {
        "router"
    }

    fn spawn(&self, ctx: &mut StartupContext<'_>) -> Result<()> {
        let router = ctx
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("router not initialized"))?
            .clone();
        let mut incoming_packets_rx = ctx
            .incoming_packets_rx
            .take()
            .ok_or_else(|| anyhow::anyhow!("incoming packets rx missing"))?;
        let health: SharedHealth = ctx.health.clone();
        let cancel_router = ctx.cancel.clone();
        ctx.supervisor.spawn("router", async move {
            let mut backoff = Duration::from_millis(500);
            loop {
                if cancel_router.is_cancelled() {
                    break;
                }
                let result = AssertUnwindSafe(
                    router
                        .clone()
                        .run(&mut incoming_packets_rx, cancel_router.clone()),
                )
                .catch_unwind()
                .await;
                match result {
                    Ok(RouterRunOutcome::Cancelled | RouterRunOutcome::IngressClosed) => {
                        health.mark_healthy();
                        break;
                    }
                    Ok(RouterRunOutcome::ChannelClosedUnexpectedly) => {
                        health.router_restarts.fetch_add(1, Ordering::Relaxed);
                        health
                            .record_error("router", "router incoming channel closed unexpectedly");
                    }
                    Err(_) => {
                        health.router_restarts.fetch_add(1, Ordering::Relaxed);
                        health.record_error("router", "panic in router loop");
                    }
                }
                tokio::select! {
                    _ = cancel_router.cancelled() => break,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(15));
            }
        });
        Ok(())
    }
}
