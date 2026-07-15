pub mod app_plane;
pub mod crypto;
pub mod db;
pub mod dht;
pub mod event_core;
pub mod logger;
pub mod metrics;
pub mod nat;
pub mod node;
pub mod packet;
pub mod packet_processor;
pub mod peer_score;
pub mod protocol;
pub mod router;
pub mod services;
pub mod sessions;
pub mod simulation;
pub mod storage;
pub mod stun;
pub mod topology;
pub mod transport;
pub mod types;

pub use metrics::{
    AggregatedMetricsSnapshot, MetricsAggregator, NodeHealthSnapshot, PeerHealthSnapshot,
};
pub use packet::Packet;
pub use peer_score::{
    PeerConnectionPolicy, PeerScore, PeerScoreStore, PeerScoreWeights, PeerSelectionContext,
    latency_penalty, rank_peers, select_best_relay, select_committee_candidates,
    select_storage_replicas, select_top_k, total_score,
};
pub use topology::{
    CapacityBudget, NeighborSet, NodeCapabilities, NodeDescriptor, NodeDynamicStatus, PeerCatalog,
    PeerEvidence, PeerView, TrustClass, descriptor_ok_for_discovery_redirect, now_ms,
    parse_observed_addr_line, select_peers_for_discovery_response, sign_descriptor, sign_evidence,
    verify_descriptor, verify_evidence,
};
pub use types::{PeerId, SessionId};
