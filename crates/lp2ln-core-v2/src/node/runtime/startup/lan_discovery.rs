use anyhow::Result;

use crate::node::lan_discovery::run_lan_discovery_with_endpoints;
use crate::node::runtime::startup::context::{RuntimeService, StartupContext};

pub struct LanDiscoveryService;

impl RuntimeService for LanDiscoveryService {
    fn name(&self) -> &'static str {
        "lan_discovery"
    }

    fn enabled(&self, ctx: &StartupContext<'_>) -> bool {
        ctx.options.lan_discovery.enabled
    }

    fn spawn(&self, ctx: &mut StartupContext<'_>) -> Result<()> {
        let listens = ctx.bound_listens.clone();
        let our_peer_id = ctx.keypair.peer_id().to_string();
        let signing_key = ctx.keypair.signing_key().clone();
        let peer_dir = ctx.peer_dir.clone();
        let opts = ctx.options.lan_discovery.clone();
        let cancel = ctx.producer_cancel.clone();

        ctx.supervisor.spawn("lan_discovery", async move {
            run_lan_discovery_with_endpoints(
                cancel,
                our_peer_id,
                signing_key,
                move || {
                    listens
                        .iter()
                        .filter(|r| matches!(r.key().as_str(), "tcp" | "udp" | "quic"))
                        .map(|r| format!("{}:{}", r.key(), r.value()))
                        .collect()
                },
                peer_dir,
                opts,
            )
            .await;
        });

        Ok(())
    }
}
