use std::cmp::Ordering;
use std::collections::BinaryHeap;

use super::adapters::{NodeActionPlan, SimNodeObservation, TopologyDecisionAdapter};
use super::clock::SimClock;
use super::events::{SimulationEvent, SimulationEventKind};
use super::network_model::BasicNetworkModel;
use super::types::{SimEdge, SimNodeId, SimPeerView, TopologySnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimConfig {
    pub tick_interval_ms: u64,
    pub random_seed: u64,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            tick_interval_ms: 5_000,
            random_seed: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScheduledEvent {
    at_ms: u64,
    sequence: u64,
    kind: SimulationEventKind,
}

impl Ord for ScheduledEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .at_ms
            .cmp(&self.at_ms)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

impl PartialOrd for ScheduledEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub struct TopologySimEngine<D: TopologyDecisionAdapter> {
    pub config: SimConfig,
    pub network_model: BasicNetworkModel,
    pub snapshot: TopologySnapshot,
    pub clock: SimClock,
    decision_adapter: D,
    queue: BinaryHeap<ScheduledEvent>,
    next_sequence: u64,
    random_state: u64,
}

impl<D: TopologyDecisionAdapter> TopologySimEngine<D> {
    pub fn new(
        config: SimConfig,
        network_model: BasicNetworkModel,
        snapshot: TopologySnapshot,
        decision_adapter: D,
    ) -> Self {
        Self {
            config,
            network_model,
            snapshot,
            clock: SimClock::default(),
            decision_adapter,
            queue: BinaryHeap::new(),
            next_sequence: 0,
            random_state: config.random_seed.max(1),
        }
    }

    pub fn bootstrap_tick_schedule(&mut self) {
        let node_ids: Vec<SimNodeId> = self.snapshot.node_ids().collect();
        for node_id in node_ids {
            self.push_event(SimulationEvent::new(
                self.clock.now_ms(),
                SimulationEventKind::Tick { node_id },
            ));
        }
    }

    pub fn push_event(&mut self, event: SimulationEvent) {
        self.queue.push(ScheduledEvent {
            at_ms: event.at_ms,
            sequence: self.next_sequence,
            kind: event.kind,
        });
        self.next_sequence = self.next_sequence.saturating_add(1);
    }

    pub fn step(&mut self) -> Option<SimulationEventKind> {
        let scheduled = self.queue.pop()?;
        self.clock.advance_to(scheduled.at_ms);
        self.snapshot.now_ms = self.clock.now_ms();
        let processed = scheduled.kind.clone();
        self.handle_event(scheduled.kind);
        Some(processed)
    }

    pub fn run_steps(&mut self, max_steps: usize) -> usize {
        let mut steps = 0usize;
        while steps < max_steps {
            if self.step().is_none() {
                break;
            }
            steps = steps.saturating_add(1);
        }
        steps
    }

    pub fn pending_events(&self) -> usize {
        self.queue.len()
    }

    fn handle_event(&mut self, kind: SimulationEventKind) {
        match kind {
            SimulationEventKind::Tick { node_id } => self.handle_tick(node_id),
            SimulationEventKind::DialAttempt { from, to } => {
                let sample = self.sample_from_pair(from, to);
                let from_degree = self.connected_degree(from);
                let to_degree = self.connected_degree(to);
                let (success, latency_ms) =
                    self.network_model
                        .dial_result(from, to, from_degree, to_degree, sample);
                self.push_event(SimulationEvent::new(
                    self.clock.now_ms(),
                    SimulationEventKind::DialResult {
                        from,
                        to,
                        success,
                        latency_ms,
                    },
                ));
            }
            SimulationEventKind::DialResult {
                from,
                to,
                success,
                latency_ms,
            } => self.apply_dial_result(from, to, success, latency_ms),
            SimulationEventKind::Disconnect { from, to } => self.apply_disconnect(from, to),
            SimulationEventKind::PeerExchange { node_id } => self.schedule_next_tick(node_id),
        }
    }

    fn handle_tick(&mut self, node_id: SimNodeId) {
        if !self.snapshot.nodes.contains_key(&node_id) {
            return;
        }

        let sample = self.sample_for_node(node_id);
        let is_online = self
            .snapshot
            .nodes
            .get(&node_id)
            .map(|node| node.online)
            .unwrap_or(false);
        let should_toggle = if is_online {
            self.network_model.should_go_offline(node_id, sample)
        } else {
            self.network_model.should_go_online(node_id, sample)
        };
        if should_toggle {
            self.toggle_node_online_state(node_id);
        }

        let node_state = match self.snapshot.nodes.get(&node_id).cloned() {
            Some(state) if state.online => state,
            _ => {
                self.schedule_next_tick(node_id);
                return;
            }
        };

        let observation = SimNodeObservation {
            node_id,
            now_ms: self.clock.now_ms(),
            connected_peers: node_state.connected_peers_count(),
            known_peers: self.snapshot.nodes.len().saturating_sub(1),
            node_state,
        };
        let plan = self
            .decision_adapter
            .plan_actions(&observation, &self.snapshot);
        self.apply_action_plan(node_id, plan);
        self.schedule_next_tick(node_id);
    }

    fn apply_action_plan(&mut self, node_id: SimNodeId, plan: NodeActionPlan) {
        for peer in plan.drop_candidates {
            self.push_event(SimulationEvent::new(
                self.clock.now_ms(),
                SimulationEventKind::Disconnect {
                    from: node_id,
                    to: peer,
                },
            ));
        }
        for peer in plan.dial_candidates {
            self.push_event(SimulationEvent::new(
                self.clock.now_ms(),
                SimulationEventKind::DialAttempt {
                    from: node_id,
                    to: peer,
                },
            ));
        }
        if plan.request_peer_exchange {
            self.push_event(SimulationEvent::new(
                self.clock.now_ms(),
                SimulationEventKind::PeerExchange { node_id },
            ));
        }
    }

    fn apply_dial_result(
        &mut self,
        from: SimNodeId,
        to: SimNodeId,
        success: bool,
        latency_ms: u16,
    ) {
        if !success || !self.both_nodes_online(from, to) {
            return;
        }

        self.snapshot.edges.insert(SimEdge::new(from, to));
        self.upsert_peer_view(from, to, true, latency_ms);
        self.upsert_peer_view(to, from, true, latency_ms);
    }

    fn apply_disconnect(&mut self, from: SimNodeId, to: SimNodeId) {
        self.snapshot.edges.remove(&SimEdge::new(from, to));
        self.upsert_peer_view(from, to, false, 0);
        self.upsert_peer_view(to, from, false, 0);
    }

    fn schedule_next_tick(&mut self, node_id: SimNodeId) {
        let next_tick = self
            .clock
            .now_ms()
            .saturating_add(self.config.tick_interval_ms);
        self.push_event(SimulationEvent::new(
            next_tick,
            SimulationEventKind::Tick { node_id },
        ));
    }

    fn toggle_node_online_state(&mut self, node_id: SimNodeId) {
        if let Some(node) = self.snapshot.nodes.get_mut(&node_id) {
            node.online = !node.online;
            if !node.online {
                let peers: Vec<SimNodeId> = node.peers.keys().copied().collect();
                for peer in peers {
                    self.apply_disconnect(node_id, peer);
                }
            }
        }
    }

    fn upsert_peer_view(
        &mut self,
        owner: SimNodeId,
        peer: SimNodeId,
        connected: bool,
        latency_ms: u16,
    ) {
        if let Some(node) = self.snapshot.nodes.get_mut(&owner) {
            node.peers.insert(
                peer,
                SimPeerView {
                    peer_id: peer,
                    connected,
                    latency_ms,
                },
            );
        }
    }

    fn both_nodes_online(&self, a: SimNodeId, b: SimNodeId) -> bool {
        self.snapshot
            .nodes
            .get(&a)
            .map(|n| n.online)
            .unwrap_or(false)
            && self
                .snapshot
                .nodes
                .get(&b)
                .map(|n| n.online)
                .unwrap_or(false)
    }

    fn connected_degree(&self, node_id: SimNodeId) -> usize {
        self.snapshot
            .nodes
            .get(&node_id)
            .map(|node| node.connected_peers_count())
            .unwrap_or(0)
    }

    fn sample_for_node(&mut self, node_id: SimNodeId) -> f64 {
        let mix = node_id.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ self.clock.now_ms();
        self.next_unit_fraction(mix)
    }

    fn sample_from_pair(&mut self, from: SimNodeId, to: SimNodeId) -> f64 {
        let mix = from
            .wrapping_mul(1_103_515_245)
            .wrapping_add(to.wrapping_mul(12_345))
            ^ self.clock.now_ms();
        self.next_unit_fraction(mix)
    }

    fn next_unit_fraction(&mut self, mix: u64) -> f64 {
        self.random_state ^= mix.wrapping_add(0x9E37_79B9_7F4A_7C15);
        self.random_state ^= self.random_state << 13;
        self.random_state ^= self.random_state >> 7;
        self.random_state ^= self.random_state << 17;
        let normalized = self.random_state % 1_000_000;
        normalized as f64 / 1_000_000.0
    }
}
