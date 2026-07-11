use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SessionMetrics {
    pub created_at: Instant,
    pub last_activity: std::time::Instant,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub send_errors: u64,
    pub receive_errors: u64,
    pub reconnections: u64,
    pub last_reconnection: Option<std::time::Instant>,
    pub is_active: bool,
    pub is_degraded: bool,
}

impl SessionMetrics {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            created_at: now,
            last_activity: now,
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            send_errors: 0,
            receive_errors: 0,
            reconnections: 0,
            last_reconnection: None,
            is_active: true,
            is_degraded: false,
        }
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn increment_packets_sent(&mut self, bytes: u64) {
        self.packets_sent += 1;
        self.bytes_sent += bytes;
        self.update_activity();
    }

    pub fn increment_packets_received(&mut self, bytes: u64) {
        self.packets_received += 1;
        self.bytes_received += bytes;
        self.update_activity();
    }

    pub fn increment_send_errors(&mut self) {
        self.send_errors += 1;
    }

    pub fn increment_receive_errors(&mut self) {
        self.receive_errors += 1;
    }

    pub fn record_reconnection(&mut self) {
        self.reconnections += 1;
        self.last_reconnection = Some(Instant::now());
        self.update_activity();
    }

    pub fn set_active(&mut self, active: bool) {
        self.is_active = active;
        if active {
            self.update_activity();
        }
    }

    pub fn uptime(&self) -> Duration {
        self.created_at.elapsed()
    }

    pub fn time_since_last_activity(&self) -> Duration {
        self.last_activity.elapsed()
    }

    pub fn total_packets(&self) -> u64 {
        self.packets_sent + self.packets_received
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }

    pub fn total_errors(&self) -> u64 {
        self.send_errors + self.receive_errors
    }
}

impl Default for SessionMetrics {
    fn default() -> Self {
        Self::new()
    }
}
