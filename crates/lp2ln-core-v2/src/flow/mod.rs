mod realtime;
pub(crate) mod security;

use serde::{Deserialize, Serialize};

pub use realtime::{Flow, FlowCapabilities, FlowControl, FlowError, FlowLink, FlowMetrics, FlowSender};

/// Stable identifier for a logical application Flow. No address or transport
/// handle is part of the end-to-end cryptographic identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowId(pub [u8; 16]);

pub(crate) use realtime::{
    DATAGRAM_BUFFER, FlowLifetime, FlowRequest, HANDSHAKE_TIMEOUT, establish,
};
