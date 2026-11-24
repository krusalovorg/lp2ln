//! Opt-in, bounded packet lifecycle probe for integration tests.
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::packet::Packet;

static ACTIVE: Mutex<Option<Arc<Probe>>> = Mutex::new(None);
const MAX_PACKETS: usize = 32768;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Stage {
    WriterAdmitted,
    StreamWritten,
    Decoded,
    RouterReceived,
    ProcessorAdmitted,
    Processing,
    SignatureRejected,
    ReplayRejected,
    RelayDuplicate,
    EnvelopeAccepted,
    Published,
    Observed,
}

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum LinkEvent {
    ReadFrame,
    DecodeFailed,
    ReadEnded,
    WriteFailed,
}

struct Probe {
    sender: String,
    first_id: u64,
    stages: Vec<AtomicU16>,
    link_events: [AtomicU64; 4],
    highest_decoded: AtomicU64,
    decoded_displacement: Vec<AtomicU64>,
}

/// Only one scoped probe is permitted per process. Matches a sender and a
/// bounded contiguous ID range. Never stores plaintext, wire bytes or keys.
pub struct PacketTrace(Arc<Probe>);

impl PacketTrace {
    pub fn start(sender: String, first_id: u64, count: usize) -> anyhow::Result<Self> {
        anyhow::ensure!((1..=MAX_PACKETS).contains(&count), "invalid probe size");
        anyhow::ensure!(
            first_id.checked_add(count as u64 - 1).is_some(),
            "invalid probe range"
        );
        let mut active = ACTIVE.lock().unwrap();
        anyhow::ensure!(active.is_none(), "a packet probe is already active");
        let probe = Arc::new(Probe {
            sender,
            first_id,
            stages: (0..count).map(|_| AtomicU16::new(0)).collect(),
            link_events: Default::default(),
            highest_decoded: AtomicU64::new(0),
            decoded_displacement: (0..count).map(|_| AtomicU64::new(0)).collect(),
        });
        *active = Some(probe.clone());
        Ok(Self(probe))
    }

    pub fn reached(&self, id: u64, stage: Stage) -> bool {
        self.0
            .offset(id)
            .and_then(|offset| self.0.stages.get(offset))
            .is_some_and(|s| s.load(Ordering::Relaxed) & (1 << stage as u8) != 0)
    }

    pub fn link_events(&self, event: LinkEvent) -> u64 {
        self.0.link_events[event as usize].load(Ordering::Relaxed)
    }

    /// Distance behind the largest sequence read earlier for the probed sender.
    pub fn decoded_displacement(&self, id: u64) -> Option<u64> {
        self.0
            .offset(id)
            .and_then(|offset| self.0.decoded_displacement.get(offset))
            .map(|distance| distance.load(Ordering::Relaxed))
    }

    pub fn observe(&self, packet: &Packet) {
        self.0.record(packet, Stage::Observed);
    }
}

impl Drop for PacketTrace {
    fn drop(&mut self) {
        ACTIVE.lock().unwrap().take();
    }
}

impl Probe {
    fn offset(&self, id: u64) -> Option<usize> {
        let offset = usize::try_from(id.checked_sub(self.first_id)?).ok()?;
        Some(offset)
    }

    fn record(&self, packet: &Packet, stage: Stage) {
        if packet.sender != self.sender {
            return;
        }
        let offset = packet.request_id.and_then(|id| self.offset(id));
        if stage == Stage::Decoded
            && crate::crypto::secure_channel::is_secure_envelope(&packet.data)
        {
            // Trace data is untrusted until authenticated. Never use it to
            // decide acceptance or update the replay window.
            let seq = u64::from_be_bytes(packet.data[5..13].try_into().unwrap());
            let prior = self.highest_decoded.fetch_max(seq, Ordering::Relaxed);
            if let Some(distance) = offset.and_then(|i| self.decoded_displacement.get(i)) {
                distance.fetch_max(prior.saturating_sub(seq), Ordering::Relaxed);
            }
        }
        if let Some(slot) = offset.and_then(|i| self.stages.get(i)) {
            slot.fetch_or(1 << stage as u8, Ordering::Relaxed);
        }
    }
}

pub(crate) fn record(packet: &Packet, stage: Stage) {
    if let Some(probe) = ACTIVE.lock().unwrap().as_ref() {
        probe.record(packet, stage);
    }
}

pub(crate) fn record_wire(bytes: &[u8], stage: Stage) {
    let probe = ACTIVE.lock().unwrap().clone();
    if let Some(probe) = probe
        && let Ok(packet) = postcard::from_bytes::<Packet>(bytes)
    {
        probe.record(&packet, stage);
    }
}

pub(crate) fn link_event(event: LinkEvent) {
    if let Some(probe) = ACTIVE.lock().unwrap().as_ref() {
        probe.link_events[event as usize].fetch_add(1, Ordering::Relaxed);
    }
}
