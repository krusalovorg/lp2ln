#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SimClock {
    now_ms: u64,
}

impl SimClock {
    pub fn new(start_ms: u64) -> Self {
        Self { now_ms: start_ms }
    }

    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    pub fn advance_to(&mut self, target_ms: u64) {
        if target_ms > self.now_ms {
            self.now_ms = target_ms;
        }
    }

    pub fn advance_by(&mut self, delta_ms: u64) {
        self.now_ms = self.now_ms.saturating_add(delta_ms);
    }
}
