use anyhow::Result;

use crate::node::runtime::startup::context::{RuntimeService, StartupContext};
use crate::storage::block_transfer::BlockTransferService;
use crate::storage::dht::DhtService;
use crate::storage::{block_store_from_db};

pub struct DhtRuntimeService;

impl RuntimeService for DhtRuntimeService {
    fn name(&self) -> &'static str {
        "dht"
    }

    fn enabled(&self, ctx: &StartupContext<'_>) -> bool {
        ctx.options.experimental.dht
    }

    fn spawn(&self, ctx: &mut StartupContext<'_>) -> Result<()> {
        let router = ctx
            .router
            .clone()
            .ok_or_else(|| anyhow::anyhow!("DHT requires router"))?;
        let max_records = ctx.options.experimental.effective_dht_max_records();
        let svc = DhtService::new(
            router,
            ctx.keypair.peer_id().to_string(),
            ctx.keypair.signing_key().clone(),
            max_records,
        );
        svc.clone().spawn(ctx.producer_cancel.clone());
        ctx.dht_svc = Some(svc);
        Ok(())
    }
}

pub struct BlockTransferRuntimeService;

impl RuntimeService for BlockTransferRuntimeService {
    fn name(&self) -> &'static str {
        "block_transfer"
    }

    fn enabled(&self, ctx: &StartupContext<'_>) -> bool {
        ctx.options.experimental.content
    }

    fn spawn(&self, ctx: &mut StartupContext<'_>) -> Result<()> {
        // content defaults to true; db-less nodes (tests, embedded) degrade
        // gracefully instead of failing the whole node start.
        let Some(db) = ctx.db.as_ref() else {
            crate::warn!("[block_transfer] no database configured — service disabled");
            return Ok(());
        };
        let router = ctx
            .router
            .clone()
            .ok_or_else(|| anyhow::anyhow!("block_transfer requires router"))?;
        let store = block_store_from_db(db.clone());
        let max_local_blocks = ctx.options.experimental.content_max_local_blocks;
        let svc = BlockTransferService::new(
            store,
            router,
            ctx.keypair.peer_id(),
            max_local_blocks,
        );
        svc.clone().spawn(ctx.producer_cancel.clone());
        ctx.block_transfer_svc = Some(svc);
        Ok(())
    }
}
