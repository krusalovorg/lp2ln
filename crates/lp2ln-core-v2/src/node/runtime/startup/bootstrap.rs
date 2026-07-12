use std::sync::Arc;

use anyhow::Result;

use crate::node::addressing::ordered_bootstrap_targets;
use crate::node::runtime::startup::context::{RuntimeService, StartupContext};
use crate::node::runtime::startup::transports::spawn_listener_transports;
use crate::node::topology_maintenance::{BootstrapDialDedupe, dial_bootstrap_address};
use crate::protocol::handshake;
use crate::transport::TransportContext;

pub struct TransportListenerService;

impl RuntimeService for TransportListenerService {
    fn name(&self) -> &'static str {
        "transport_listeners"
    }

    fn spawn(&self, ctx: &mut StartupContext<'_>) -> Result<()> {
        let incoming_sessions_tx = ctx
            .incoming_sessions_tx
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("incoming sessions tx missing"))?
            .clone();
        let router = ctx
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("router not initialized"))?;
        let transport_ctx = TransportContext {
            incoming_sessions_tx,
            incoming_packets_tx: router.incoming_sender(),
            listen_addr: None,
            event_tx: None,
            keypair: Some(Arc::new(ctx.keypair.clone())),
            catalog: Some(ctx.peer_catalog.clone()),
        };
        spawn_listener_transports(
            ctx.supervisor,
            ctx.producer_cancel.clone(),
            ctx.transports,
            &ctx.options.listens,
            transport_ctx,
            ctx.health.clone(),
            ctx.core_bus.clone(),
        );
        Ok(())
    }
}

pub struct BootstrapService;

impl RuntimeService for BootstrapService {
    fn name(&self) -> &'static str {
        "bootstrap"
    }

    fn spawn(&self, ctx: &mut StartupContext<'_>) -> Result<()> {
        let peer_scores = ctx.session_manager.peer_score_store();
        let bootstrap_targets = ordered_bootstrap_targets(ctx.options, peer_scores.as_ref());
        ctx.bootstrap_targets = Some(bootstrap_targets.clone());
        let transports = ctx.transports.to_vec();
        let router = ctx
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("router not initialized"))?
            .clone();
        let incoming_packets_tx = router.incoming_sender();
        let our_peer_id = ctx.keypair.peer_id().to_string();
        let mut obf_protocols: Vec<String> =
            ctx.options.transport_obfuscation.keys().cloned().collect();
        obf_protocols.sort();
        let handshake_payload =
            handshake::encode_hello(obf_protocols, ctx.options.quic.obfs.hello_obfs_mode());
        let bootstrap_dedupe = ctx.bootstrap_dial_dedupe.clone();
        let bootstrap_ok = ctx.bootstrap_dial_ok_ms.clone();
        let cancel_bootstrap = ctx.producer_cancel.clone();
        ctx.supervisor.spawn("bootstrap", async move {
            for target in bootstrap_targets {
                if cancel_bootstrap.is_cancelled() {
                    break;
                }
                let dedupe_ctx = BootstrapDialDedupe {
                    active_peers: 0,
                    set: bootstrap_dedupe.clone(),
                };
                let ts = crate::topology::now_ms();
                tokio::select! {
                    _ = cancel_bootstrap.cancelled() => break,
                    _ = dial_bootstrap_address(
                        &transports,
                        &router,
                        &incoming_packets_tx,
                        &our_peer_id,
                        &target,
                        &handshake_payload,
                        Some(&dedupe_ctx),
                        Some((&bootstrap_ok, ts)),
                    ) => {}
                }
            }
        });
        Ok(())
    }
}
