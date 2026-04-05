pub mod node;
pub mod peer_score;
pub mod metrics;
pub mod topology;
pub mod protocol;
pub mod db;
pub mod sessions;
pub mod transport;
pub mod types;
pub mod packet;
pub mod crypto;
pub mod stun;
pub mod packet_processor;
pub mod router;
pub mod logger;

pub use types::{PeerId, SessionId};
pub use packet::Packet;
pub use peer_score::{
    latency_penalty, total_score, PeerConnectionPolicy, PeerScore, PeerScoreStore, PeerScoreWeights,
    PeerSelectionContext, rank_peers, select_best_relay, select_committee_candidates,
    select_storage_replicas, select_top_k,
};
pub use topology::{
    now_ms, parse_observed_addr_line, select_peers_for_discovery_response, sign_descriptor,
    sign_evidence, verify_descriptor, verify_evidence, CapacityBudget, NeighborSet, NodeCapabilities,
    NodeDescriptor, NodeDynamicStatus, PeerCatalog, PeerEvidence, PeerView, TrustClass,
};
pub use metrics::{AggregatedMetricsSnapshot, MetricsAggregator, NodeHealthSnapshot, PeerHealthSnapshot};