use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    Normal,
    Degraded,
}

#[derive(Debug, Clone)]
pub struct RuntimeHealthSnapshot {
    pub mode: RuntimeMode,
    pub router_restarts: u64,
    pub transport_restarts: u64,
    pub incoming_restarts: u64,
    pub topology_restarts: u64,
    pub last_error: Option<String>,
}

#[derive(Default)]
pub(crate) struct RuntimeHealthState {
    pub router_restarts: AtomicU64,
    pub transport_restarts: AtomicU64,
    pub incoming_restarts: AtomicU64,
    pub topology_restarts: AtomicU64,
    degraded: AtomicBool,
    last_error: RwLock<Option<String>>,
}

impl RuntimeHealthState {
    pub fn record_error(&self, subsystem: &str, err: impl Into<String>) {
        let msg = format!("[{}] {}", subsystem, err.into());
        if let Ok(mut w) = self.last_error.write() {
            *w = Some(msg.clone());
        }
        self.degraded.store(true, Ordering::Relaxed);
        crate::warn!("[NodeRuntime] subsystem degraded: {}", msg);
    }

    pub fn mark_healthy(&self) {
        self.degraded.store(false, Ordering::Relaxed);
        if let Ok(mut w) = self.last_error.write() {
            *w = None;
        }
    }

    pub fn snapshot(&self) -> RuntimeHealthSnapshot {
        let mode = if self.degraded.load(Ordering::Relaxed) {
            RuntimeMode::Degraded
        } else {
            RuntimeMode::Normal
        };
        let last_error = self.last_error.read().ok().and_then(|v| v.clone());
        RuntimeHealthSnapshot {
            mode,
            router_restarts: self.router_restarts.load(Ordering::Relaxed),
            transport_restarts: self.transport_restarts.load(Ordering::Relaxed),
            incoming_restarts: self.incoming_restarts.load(Ordering::Relaxed),
            topology_restarts: self.topology_restarts.load(Ordering::Relaxed),
            last_error,
        }
    }
}

pub(crate) type SharedHealth = Arc<RuntimeHealthState>;
