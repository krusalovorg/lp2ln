//! LP2LN App Plane client SDK (P3-06).
//!
//! Sidecars connect to the daemon's local IPC (named pipe / UDS / optional
//! loopback TCP), perform Hello, then Subscribe / Send / OpenStream without
//! importing Router internals (AD-06).

mod client;
mod connect;
mod error;

pub use client::{AppClient, OpenStreamOpts, SubscribeOpts};
pub use connect::{ConnectOpts, Endpoint};
pub use error::{AppSdkError, Result};
pub use lp2ln_app_protocol::{
    AppCapability, AppCmd, AppErrorCode, AppEvent, DEFAULT_STREAM_CREDITS, MAX_FRAME_BYTES,
    MAX_STREAM_CHUNK_BYTES, PROTOCOL_VERSION, QUEUE_CAP, decode_cmd, decode_event, encode_cmd,
    encode_event,
};
