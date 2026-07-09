use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;

use crate::node::direct_upgrade::{
    CoreDirectDialer, DirectUpgradeContext, TrafficDemandTracker, nat_trigger_from_parts,
    run_direct_upgrade_loop,
};
use crate::node::runtime::startup::context::{RuntimeService, StartupContext};
use crate::services::SessionRegistry;

pub struct DirectUpgradeService;

impl RuntimeService for DirectUpgradeService {
    fn name(&self) -> &'static str {
        "direct_upgrade"
    }

    fn enabled(&self, ctx: &StartupContext<'_>) -> bool {
        ctx.options.direct_upgrade.enabled
    }

    fn spawn(&self, ctx: &mut StartupContext<'_>) -> Result<()> {
        let du_cfg = ctx.options.direct_upgrade.clone();
        let rx = ctx
            .direct_upgrade_rx
            .take()
            .ok_or_else(|| anyhow::anyhow!("direct upgrade rx missing"))?;
        let router = ctx
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("router not initialized"))?
            .clone();
        let mut obf_protocols: Vec<String> =
            ctx.options.transport_obfuscation.keys().cloned().collect();
        obf_protocols.sort();
        let listens: HashMap<_, _> = ctx
            .options
            .listens
            .iter()
            .map(|r| (r.key().clone(), *r.value()))
            .collect();
        let advertise = ctx.options.advertise_addrs.clone();
        let dialer = Arc::new(CoreDirectDialer {
            router: router.clone(),
            transports: ctx.transports.to_vec(),
            keypair: ctx.keypair.clone(),
            obfuscation_protocols: obf_protocols,
        });
        let nat = if du_cfg.try_nat_traversal {
            Some(nat_trigger_from_parts(
                router.clone(),
                ctx.keypair.clone(),
                ctx.transports.to_vec(),
                listens.clone(),
                ctx.nat_state.clone(),
            ))
        } else {
            None
        };
        let tracker = Arc::new(TrafficDemandTracker::new(du_cfg.max_tracker_peers));
        let cancel_du = ctx.producer_cancel.clone();
        let session_manager_du = ctx.session_manager.clone();
        let peer_catalog_du = ctx.peer_catalog.clone();
        let dial_book_du = ctx.dial_book.clone();
        let our_peer_id_du = ctx.keypair.peer_id().to_string();
        ctx.supervisor.spawn("direct_upgrade", async move {
            run_direct_upgrade_loop(
                rx,
                DirectUpgradeContext {
                    config: du_cfg,
                    our_peer_id: our_peer_id_du,
                    registry: router as Arc<dyn SessionRegistry>,
                    session_manager: session_manager_du,
                    peer_catalog: peer_catalog_du,
                    dial_book: dial_book_du,
                    listens,
                    advertise,
                    dialer,
                    nat,
                    tracker,
                },
                cancel_du,
            )
            .await;
        });
        Ok(())
    }
}
