use serde::{Deserialize, Serialize};

/// Local App Plane IPC endpoint (AD-07: UDS / named pipe by default).
///
/// Gated by [`ExperimentalOptions::app_plane`]. Loopback TCP is opt-in via
/// [`Self::dev_tcp_bind`] for debug only — never the production default.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppPlaneIpcOptions {
    /// Unix: filesystem socket path. Windows: `\\.\pipe\…` or pipe name.
    #[serde(default = "default_app_plane_path")]
    pub path: String,
    /// Optional loopback TCP bind (e.g. `127.0.0.1:17999`). Empty/None = off.
    #[serde(default)]
    pub dev_tcp_bind: Option<String>,
    /// If set, `Hello.token` must match (P3-04). `None` = no token required.
    #[serde(default)]
    pub app_token: Option<String>,
    /// Allowed `protocol_id`s. Empty = allow any (open registry).
    #[serde(default)]
    pub allowed_protocol_ids: Vec<u16>,
}

impl Default for AppPlaneIpcOptions {
    fn default() -> Self {
        Self {
            path: default_app_plane_path(),
            dev_tcp_bind: None,
            app_token: None,
            allowed_protocol_ids: Vec::new(),
        }
    }
}

pub fn default_app_plane_path() -> String {
    #[cfg(windows)]
    {
        r"\\.\pipe\lp2ln-app".to_string()
    }
    #[cfg(not(windows))]
    {
        "/tmp/lp2ln-app.sock".to_string()
    }
}

/// DHT / content / repair / App Plane feature flags.
///
/// `dht` and `content` default to `true` — nodes ship with content routing
/// enabled. `repair` and `app_plane` remain opt-in until their gates close.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExperimentalOptions {
    /// DHT provider records + routing. On by default.
    #[serde(default = "default_true")]
    pub dht: bool,
    /// Block store + block transfer service. On by default.
    #[serde(default = "default_true")]
    pub content: bool,
    /// RepairWorker background loop. Off by default; requires content+dht.
    #[serde(default)]
    pub repair: bool,
    /// Binary App Plane IPC server (local UDS/named pipe). Off by default.
    #[serde(default)]
    pub app_plane: bool,
    /// Max records in the in-memory DHT store (0 → 4096).
    #[serde(default)]
    pub dht_max_records: usize,
    /// Max pushed blocks this node accepts before refusing further pushes (0 = unlimited).
    #[serde(default)]
    pub content_max_local_blocks: usize,
}

impl Default for ExperimentalOptions {
    fn default() -> Self {
        Self {
            dht: true,
            content: true,
            repair: false,
            app_plane: false,
            dht_max_records: 0,
            content_max_local_blocks: 0,
        }
    }
}

impl ExperimentalOptions {
    pub fn any_enabled(&self) -> bool {
        self.dht || self.content || self.repair || self.app_plane
    }

    pub fn effective_dht_max_records(&self) -> usize {
        if self.dht_max_records == 0 { 4096 } else { self.dht_max_records }
    }
}

fn default_true() -> bool {
    true
}
