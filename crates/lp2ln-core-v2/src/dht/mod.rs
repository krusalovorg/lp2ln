// Global Discovery DHT — roadmap 03
//
// DHT-0: NodeRecord, iterative find_node, k-buckets, TTL
// DHT-1: ProviderRecord, find_providers, announce_provider

pub mod records;
pub mod routing;
pub mod service;
pub mod store;

pub use records::{
    DHT_PROTOCOL_ID, DhtMsg, NodeId, NodeRecord, ProviderRecord, node_id_of, unix_now,
};
pub use routing::{ALPHA, K, RoutingTable};
pub use service::DhtService;
pub use store::DhtStore;
