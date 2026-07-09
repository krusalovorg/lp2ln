use anyhow::Result;

use crate::node::flow_trace::FlowTraceService;
use crate::node::runtime::startup::context::{RuntimeService, StartupContext};

pub struct FlowTraceRuntimeService;

impl RuntimeService for FlowTraceRuntimeService {
    fn name(&self) -> &'static str {
        "flow_trace"
    }

    fn enabled(&self, ctx: &StartupContext<'_>) -> bool {
        FlowTraceService::is_enabled(&ctx.options.flow_trace)
    }

    fn spawn(&self, ctx: &mut StartupContext<'_>) -> Result<()> {
        let cancel_trace = ctx.cancel.clone();
        let node_role = ctx.options.node_role;
        let our_peer_id_trace = ctx.keypair.peer_id().to_string();
        let flow_trace = ctx.options.flow_trace.clone();
        let router_trace = ctx
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("router not initialized"))?
            .clone();
        ctx.supervisor.spawn("flow_trace", async move {
            FlowTraceService::run(
                &router_trace,
                node_role,
                our_peer_id_trace,
                &flow_trace,
                cancel_trace,
            )
            .await;
        });
        Ok(())
    }
}
