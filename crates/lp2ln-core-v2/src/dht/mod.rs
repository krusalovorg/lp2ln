//! # EXPERIMENTAL
//!
//! Global Discovery DHT — experimental content runtime.
//!
//! This module is a **library skeleton**. The default `lp2lnd` daemon does **not**
//! start DHT background lifecycle. Opt-in via `options.experimental.dht`
//! (flag only until a production lifecycle gate).
//!
//! DHT-0: NodeRecord, iterative find_node, k-buckets, TTL  
//! DHT-1: ProviderRecord, find_providers, announce_provider

pub mod records;
pub mod routing;
pub mod service;
pub mod store;

pub use crate::types::NodeId;
pub use records::{DHT_PROTOCOL_ID, DhtMsg, NodeRecord, ProviderRecord, node_id_of, unix_now};
pub use routing::{ALPHA, K, RoutingTable};
pub use service::DhtService;
pub use store::DhtStore;
