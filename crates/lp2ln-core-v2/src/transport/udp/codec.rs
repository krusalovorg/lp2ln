// Both transports use the same postcard representation and allocation guards.
pub use crate::transport::tcp::codec::{decode_packet, encode_packet};
