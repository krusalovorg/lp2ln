pub mod addressing;
pub mod autonomy;
pub mod builder;
pub mod direct_upgrade;
pub mod lan_discovery;
pub mod distribution;
pub mod flow_trace;
pub mod health_server;
pub mod incoming_sessions;
pub mod nat_traversal;
pub mod options;
mod options_file;
pub mod runtime;
mod supervisor;
pub mod topology_maintenance;

pub mod connection_strategy {
    pub use super::distribution::*;
    pub use super::incoming_sessions::send_discovery_redirect_and_close;
}

pub use autonomy::{ConfigAutonomy, StartupConfigResult, StartupConfigSource, ValidationReport};
pub use builder::NodeBuilder;
pub use options::{DirectUpgradeConfig, ExperimentalOptions, IpcTcpOptions, NodeOptions, NodeRole};
pub use runtime::{
    NodeLifecycleError, NodeLifecycleState, NodeRuntime, RuntimeHealthSnapshot, RuntimeMode,
};
