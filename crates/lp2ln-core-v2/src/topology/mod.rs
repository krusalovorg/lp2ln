pub mod capacity;
pub mod catalog;
pub mod descriptor;
pub mod discovery;
pub mod peer_directory;
pub mod planner;
pub mod reconciler;
pub mod smart_mesh;
pub mod snapshot;

pub use capacity::CapacityBudget;
pub use catalog::{
    KnownPeerRecord, NeighborSet, PeerCatalog, PeerEvidence, PeerView, TrustClass, sign_evidence,
    verify_evidence,
};
pub use descriptor::{
    NodeCapabilities, NodeDescriptor, NodeDynamicStatus, parse_observed_addr_line, sign_descriptor,
    verify_descriptor,
};
pub use discovery::{descriptor_ok_for_discovery_redirect, select_peers_for_discovery_response};
pub use peer_directory::{AddressRecord, AddressSource, DialRecord, PeerDirectory};
pub use planner::{
    AdmissionDecision, DialIntent, DiscoveryNeed, DropIntent, DropReason, PeerCandidate,
    TopologyPlan, TopologyPlanner,
};
pub use reconciler::TopologyReconciler;
pub use smart_mesh::SmartMeshPlanner;
pub use snapshot::TopologySnapshot;

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
