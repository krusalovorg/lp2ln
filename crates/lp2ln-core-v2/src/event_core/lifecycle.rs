use anyhow::Result;
use async_trait::async_trait;

use super::bus::CoreBus;
use super::commands::LifecycleAction;
use super::events::{ServiceDescriptor, ServiceStatus};

#[derive(Clone)]
pub struct ServiceContext {
    pub bus: CoreBus,
}

#[derive(Debug, Clone)]
pub struct ServiceReadiness {
    pub service: ServiceDescriptor,
    pub status: ServiceStatus,
    pub generation: u64,
    pub last_error: Option<String>,
}

#[async_trait]
pub trait ManagedService: Send + Sync {
    fn descriptor(&self) -> ServiceDescriptor;

    async fn start(&self, ctx: ServiceContext) -> Result<()>;

    async fn stop(&self) -> Result<()>;

    async fn probe(&self) -> Result<ServiceReadiness>;

    async fn handle_lifecycle_action(
        &self,
        action: LifecycleAction,
        ctx: ServiceContext,
    ) -> Result<ServiceReadiness> {
        match action {
            LifecycleAction::Start => {
                self.start(ctx).await?;
                self.probe().await
            }
            LifecycleAction::Stop => {
                self.stop().await?;
                self.probe().await
            }
            LifecycleAction::Restart => {
                self.stop().await?;
                self.start(ctx).await?;
                self.probe().await
            }
            LifecycleAction::Probe => self.probe().await,
        }
    }
}
