pub mod addressing;
pub mod autonomy;
pub mod builder;
pub mod config_v2;
pub mod direct_upgrade;
pub mod distribution;
pub mod flow_trace;
pub mod health_server;
pub mod incoming_sessions;
pub mod lan_discovery;
pub mod nat_traversal;
pub mod options;
mod options_file;
pub mod runtime;
pub mod seed_book;
mod supervisor;
pub mod topology_maintenance;

pub mod connection_strategy {
    pub use super::distribution::*;
    pub use super::incoming_sessions::send_discovery_redirect_and_close;
}

pub use autonomy::{ConfigAutonomy, StartupConfigResult, StartupConfigSource, ValidationReport};
pub use builder::NodeBuilder;
pub use config_v2::{
    CONFIG_SCHEMA_VERSION, ConfigCheckResult, ConfigLoadReport, check_file, load_json_with_report,
    migrate_file, migrate_json_to_v2, public_example_json,
};
pub use options::{
    AdaptiveTopologyProfile, AppPlaneIpcOptions, DirectUpgradeConfig, ExperimentalOptions,
    IpcTcpOptions, NodeOptions, NodeRole,
};
pub use runtime::{
    NodeLifecycleError, NodeLifecycleState, NodeRuntime, RuntimeHealthSnapshot, RuntimeMode,
};
