use anyhow::Result;

use crate::node::link_survival::{WatchdogConfig, run_link_watchdog};
use crate::node::runtime::startup::context::{RuntimeService, StartupContext};

pub struct LinkWatchdogService;

impl RuntimeService for LinkWatchdogService {
    fn name(&self) -> &'static str {
        "link_watchdog"
    }

    fn spawn(&self, ctx: &mut StartupContext<'_>) -> Result<()> {
        let router = ctx
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("router not initialized"))?
            .clone();
        let our_peer_id = ctx.keypair.peer_id().to_string();
        let cancel = ctx.producer_cancel.clone();
        ctx.supervisor.spawn(
            "link_watchdog",
            run_link_watchdog(router, our_peer_id, WatchdogConfig::default(), cancel),
        );
        Ok(())
    }
}
