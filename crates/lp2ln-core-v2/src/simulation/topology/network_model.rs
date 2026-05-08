#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatencyBucket {
    Low,
    Medium,
    High,
}

impl LatencyBucket {
    pub fn sample_latency_ms(self) -> u16 {
        match self {
            LatencyBucket::Low => 20,
            LatencyBucket::Medium => 75,
            LatencyBucket::High => 160,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChurnProfile {
    pub offline_probability_per_tick: f64,
    pub online_probability_per_tick: f64,
}

impl ChurnProfile {
    pub fn conservative() -> Self {
        Self {
            offline_probability_per_tick: 0.005,
            online_probability_per_tick: 0.08,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BasicNetworkModel {
    pub dial_success_probability: f64,
    pub latency_bucket: LatencyBucket,
    pub churn: ChurnProfile,
    pub max_peer_degree: usize,
}

impl BasicNetworkModel {
    pub fn baseline() -> Self {
        Self {
            dial_success_probability: 0.86,
            latency_bucket: LatencyBucket::Medium,
            churn: ChurnProfile::conservative(),
            max_peer_degree: 24,
        }
    }

    pub fn dial_result(
        &self,
        from: u64,
        to: u64,
        from_degree: usize,
        to_degree: usize,
        sample: f64,
    ) -> (bool, u16) {
        let from_quality = node_quality_factor(from);
        let to_quality = node_quality_factor(to);
        let saturation_penalty = if to_degree >= self.max_peer_degree {
            0.2
        } else {
            let ratio = to_degree as f64 / self.max_peer_degree as f64;
            (1.0 - ratio * 0.6).clamp(0.3, 1.0)
        };
        let initiator_penalty = if from_degree >= self.max_peer_degree {
            0.6
        } else {
            1.0
        };
        let final_probability = (self.dial_success_probability
            * from_quality
            * to_quality
            * saturation_penalty
            * initiator_penalty)
            .clamp(0.02, 0.98);
        let success = sample <= final_probability;
        let latency = pair_latency_bucket(self.latency_bucket, from, to).sample_latency_ms();
        (success, latency)
    }

    pub fn should_go_offline(&self, node_id: u64, sample: f64) -> bool {
        let multiplier = 1.0 + ((node_id % 7) as f64 / 20.0);
        sample <= (self.churn.offline_probability_per_tick * multiplier).clamp(0.0, 0.35)
    }

    pub fn should_go_online(&self, node_id: u64, sample: f64) -> bool {
        let multiplier = 0.8 + ((node_id % 5) as f64 / 10.0);
        sample <= (self.churn.online_probability_per_tick * multiplier).clamp(0.0, 1.0)
    }
}

fn node_quality_factor(node_id: u64) -> f64 {
    match node_id % 10 {
        0 => 0.65,
        1 | 2 => 0.8,
        3..=7 => 1.0,
        _ => 1.1,
    }
}

fn pair_latency_bucket(base: LatencyBucket, from: u64, to: u64) -> LatencyBucket {
    let pair_class = (from ^ to) % 10;
    match base {
        LatencyBucket::Low => {
            if pair_class <= 1 {
                LatencyBucket::Medium
            } else {
                LatencyBucket::Low
            }
        }
        LatencyBucket::Medium => {
            if pair_class <= 2 {
                LatencyBucket::Low
            } else if pair_class >= 8 {
                LatencyBucket::High
            } else {
                LatencyBucket::Medium
            }
        }
        LatencyBucket::High => {
            if pair_class >= 8 {
                LatencyBucket::High
            } else {
                LatencyBucket::Medium
            }
        }
    }
}
