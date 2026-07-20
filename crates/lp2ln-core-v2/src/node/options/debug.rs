use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowTraceOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub json_packets: bool,
    #[serde(default = "default_flow_trace_payload_preview_bytes")]
    pub payload_preview_bytes: usize,
}

impl Default for FlowTraceOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            json_packets: false,
            payload_preview_bytes: default_flow_trace_payload_preview_bytes(),
        }
    }
}

fn default_flow_trace_payload_preview_bytes() -> usize { 32 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugServerOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_debug_server_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_debug_server_push_interval_ms")]
    pub push_interval_ms: u64,
}

impl Default for DebugServerOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: default_debug_server_bind_addr(),
            push_interval_ms: default_debug_server_push_interval_ms(),
        }
    }
}

fn default_debug_server_bind_addr() -> String { "127.0.0.1:9090".to_string() }
fn default_debug_server_push_interval_ms() -> u64 { 1000 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcTcpOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ipc_tcp_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_true")]
    pub push_incoming_packets: bool,
    #[serde(default = "default_ipc_tcp_max_frame_bytes")]
    pub max_frame_bytes: u32,
}

impl Default for IpcTcpOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: default_ipc_tcp_bind_addr(),
            push_incoming_packets: true,
            max_frame_bytes: default_ipc_tcp_max_frame_bytes(),
        }
    }
}

fn default_true() -> bool { true }
fn default_ipc_tcp_bind_addr() -> String { "127.0.0.1:9091".to_string() }
fn default_ipc_tcp_max_frame_bytes() -> u32 { 16 * 1024 * 1024 }
