use anyhow::Result;

use crate::node::lan_discovery::run_lan_discovery;
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
        // Build endpoint strings from listen addresses.
        // Receivers will substitute 0.0.0.0 with the UDP packet source IP.
        let endpoints: Vec<String> = ctx
            .options
            .listens
            .iter()
            .filter_map(|r| {
                let proto = r.key();
                let addr = r.value();
                if proto == "tcp" || proto == "udp" || proto == "quic" {
                    Some(format!("{}:{}", proto, addr))
                } else {
                    None
                }
            })
            .collect();

        let our_peer_id = ctx.keypair.peer_id().to_string();
        let signing_key = ctx.keypair.signing_key().clone();
        let peer_dir = ctx.peer_dir.clone();
        let opts = ctx.options.lan_discovery.clone();
        let cancel = ctx.producer_cancel.clone();

        ctx.supervisor.spawn("lan_discovery", async move {
            run_lan_discovery(cancel, our_peer_id, signing_key, endpoints, peer_dir, opts).await;
        });

        Ok(())
    }
}
