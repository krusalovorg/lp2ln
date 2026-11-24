//! Direct one-to-one voice profile. Each invitation owns a fresh authenticated Flow.
use anyhow::{Result, anyhow, ensure};
use lp2ln_core_v2::flow::{FlowControl, FlowId, FlowSender};
use opus::{Application, Bitrate, Channels, Decoder, Encoder};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

pub const PROTOCOL: u16 = 0xff82;
pub const FRAME: usize = 960;
const RATE: u32 = 48000;
const MAX_OPUS: usize = 240;
const MAX_AGE: Duration = Duration::from_millis(140);
const MAX_DEPTH: usize = 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Signal {
    Invite = 1,
    Ringing,
    Accept,
    Active,
    Reject,
    Cancel,
    Hangup,
    EndAck,
}

impl TryFrom<u8> for Signal {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self> {
        use Signal::*;
        [
            Invite, Ringing, Accept, Active, Reject, Cancel, Hangup, EndAck,
        ]
        .get(usize::from(value).wrapping_sub(1))
        .copied()
        .ok_or(anyhow!("invalid signal"))
    }
}

/// CallID uses the random FlowID of this invitation. One mandatory profile bit
/// negotiates mono Opus at 48 kHz, 20 ms, nominal 24 kbit/s.
fn signal_wire(id: FlowId, signal: Signal) -> [u8; 19] {
    let mut message = [0; 19];
    message[..3].copy_from_slice(&[1, signal as u8, 1]);
    message[3..].copy_from_slice(&id.0);
    message
}
fn parse_signal(id: FlowId, wire: &[u8]) -> Result<Signal> {
    ensure!(
        wire.len() == 19 && wire[0] == 1 && wire[2] == 1 && wire[3..] == id.0,
        "wrong call or capabilities"
    );
    wire[1].try_into()
}
pub async fn exchange(control: &FlowControl, call: FlowId, state: Signal) -> Result<Signal> {
    parse_signal(call, &control.exchange(&signal_wire(call, state)).await?)
}

pub struct Capture {
    encoder: Encoder,
    seq: u64,
}
impl Capture {
    pub fn new() -> Result<Self> {
        let mut encoder = Encoder::new(RATE, Channels::Mono, Application::Voip)?;
        encoder.set_bitrate(Bitrate::Bits(24_000))?;
        Ok(Self { encoder, seq: 0 })
    }
    pub fn offer(&mut self, tx: &FlowSender, pcm: &[i16; FRAME], captured: Instant) -> Result<()> {
        let mut packet = [0; 8 + MAX_OPUS];
        let limit = packet.len().min(tx.max_payload());
        ensure!(limit > 8, "path MTU");
        packet[..8].copy_from_slice(&self.seq.to_be_bytes());
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(anyhow!("sequence exhausted"))?;
        let n = self.encoder.encode(pcm, &mut packet[8..limit])?;
        tx.try_send(&packet[..8 + n], captured + MAX_AGE)?;
        Ok(())
    }
}

#[derive(Default, Clone, Copy)]
pub struct AudioStats {
    pub late: u64,
    pub gaps: u64,
    pub played: u64,
    pub received: u64,
    pub last_seq: u64,
    pub bytes: u64,
    pub jitter_us: f64,
    pub depth: usize,
    pub target: usize,
}
pub struct Playout {
    decoder: Decoder,
    pending: BTreeMap<u64, (Instant, Vec<u8>)>,
    next: Option<u64>,
    previous: Option<(u64, Instant)>,
    stats: AudioStats,
    empty_ticks: usize,
}
impl Playout {
    pub fn new() -> Result<Self> {
        Ok(Self {
            decoder: Decoder::new(RATE, Channels::Mono)?,
            pending: BTreeMap::new(),
            next: None,
            previous: None,
            stats: AudioStats::default(),
            empty_ticks: 0,
        })
    }
    pub fn stats(&self) -> AudioStats {
        AudioStats {
            depth: self.pending.len(),
            ..self.stats
        }
    }
    pub fn push(&mut self, data: &[u8], now: Instant, deadline: Instant) -> Result<()> {
        if now >= deadline {
            self.stats.late += 1;
            return Ok(());
        }
        ensure!(
            (9..=MAX_OPUS + 8).contains(&data.len()),
            "invalid voice payload"
        );
        ensure!(
            self.decoder.get_nb_samples(&data[8..])? == FRAME,
            "wrong Opus frame duration"
        );
        let seq = u64::from_be_bytes(data[..8].try_into()?);
        ensure!(seq < u64::MAX - 128, "invalid sequence");
        self.stats.last_seq = self.stats.last_seq.max(seq);
        if self.next.is_some_and(|n| seq < n) || self.pending.contains_key(&seq) {
            self.stats.late += 1;
            return Ok(());
        }
        if let Some((last, t)) = self.previous {
            let deviation = ((now.saturating_duration_since(t).as_micros() as f64)
                - (seq as f64 - last as f64) * 20_000.)
                .abs()
                .min(140_000.);
            self.stats.jitter_us += (deviation - self.stats.jitter_us) / 16.;
        }
        self.previous = Some((seq, now));
        if self.pending.len() == MAX_DEPTH {
            self.pending.pop_first();
            self.stats.late += 1;
        }
        self.stats.received += 1;
        self.stats.bytes += data.len() as u64 - 8;
        self.pending
            .insert(seq, (deadline.min(now + MAX_AGE), data[8..].to_vec()));
        Ok(())
    }
    pub fn render(&mut self, now: Instant, pcm: &mut [i16; FRAME]) -> Result<()> {
        pcm.fill(0);
        self.stats.target = (2 + (self.stats.jitter_us / 10_000.) as usize).clamp(2, 5);
        let prev = self.pending.len();
        self.pending.retain(|_, (t, _)| now < *t);
        self.stats.late += (prev - self.pending.len()) as u64;
        if self.next.is_none() {
            if self.pending.len() < self.stats.target {
                return Ok(());
            }
            self.next = self.pending.keys().next().copied();
        }
        let mut seq = self.next.unwrap();
        if let Some((&first, _)) = self.pending.first_key_value() {
            if first.saturating_sub(seq) > MAX_DEPTH as u64 {
                seq = first;
            }
        }
        self.next = Some(seq + 1);
        if let Some((_, frame)) = self.pending.remove(&seq) {
            self.empty_ticks = 0;
            ensure!(
                self.decoder.decode(&frame, pcm, false)? == FRAME,
                "wrong frame duration"
            );
            self.stats.played += 1;
        } else {
            self.stats.gaps += 1;
            self.decoder.decode(&[], pcm, false)?;
            self.empty_ticks += 1;
            if self.empty_ticks >= 3 {
                self.next = None;
                self.empty_ticks = 0;
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signals_bound_to_call_and_profile() {
        let id = FlowId([1; 16]);
        let mut wire = signal_wire(id, Signal::Accept);
        assert_eq!(parse_signal(id, &wire).unwrap(), Signal::Accept);
        assert!(parse_signal(FlowId([2; 16]), &wire).is_err());
        wire[2] = 0;
        assert!(parse_signal(id, &wire).is_err());
    }
    #[test]
    fn opus_reorder_loss_and_stale_playout() {
        let mut enc = Capture::new().unwrap();
        let mut play = Playout::new().unwrap();
        let now = Instant::now();
        let mut pcm = [0; FRAME];
        let input =
            std::array::from_fn::<_, FRAME, _>(|i| ((i as f32 * 0.06).sin() * 6000.) as i16);
        for seq in [0u64, 2, 1, 4] {
            let mut packet = vec![0; 248];
            packet[..8].copy_from_slice(&seq.to_be_bytes());
            let n = enc.encoder.encode(&input, &mut packet[8..]).unwrap();
            play.push(&packet[..8 + n], now, now + MAX_AGE).unwrap();
        }
        for _ in 0..4 {
            play.render(now, &mut pcm).unwrap();
        }
        assert_eq!(play.stats().played, 3);
        assert_eq!(play.stats().gaps, 1);
        play.render(now + MAX_AGE, &mut pcm).unwrap();
        assert_eq!(play.stats().late, 1);
        assert_eq!(play.stats().depth, 0);
    }
}

/// One invitation/Flow in v1. Ring timeout uses the local monotonic clock.
pub struct CallDialog {
    pub caller: bool,
    pub state: Signal,
    invited: bool,
    saw_end: bool,
    started: Instant,
}

impl CallDialog {
    pub fn new(caller: bool, now: Instant) -> Self {
        Self {
            caller,
            state: if caller {
                Signal::Invite
            } else {
                Signal::Ringing
            },
            invited: false,
            saw_end: false,
            started: now,
        }
    }
    pub fn incoming(&self) -> bool {
        self.invited && self.state == Signal::Ringing
    }
    pub fn consent(&mut self) {
        if self.incoming() {
            self.state = Signal::Accept;
        }
    }
    pub fn end(&mut self) {
        self.state = match self.state {
            Signal::Invite => Signal::Cancel,
            Signal::Ringing => Signal::Reject,
            Signal::Accept | Signal::Active => Signal::Hangup,
            terminal => terminal,
        }
    }
    pub fn next(&mut self, now: Instant) -> Signal {
        if self.state != Signal::Active
            && now.saturating_duration_since(self.started) >= Duration::from_secs(30)
        {
            self.end();
        }
        if self.saw_end {
            Signal::EndAck
        } else {
            self.state
        }
    }
    /// True once a terminal signal has been acknowledged. A local user ending
    /// a call during an exchange still gets a chance to transmit that decision.
    pub fn observe(&mut self, sent: Signal, remote: Signal) -> Result<bool> {
        if remote == Signal::EndAck {
            ensure!(
                self.state.terminal() && (sent.terminal() || sent == Signal::EndAck),
                "unexpected end acknowledgement"
            );
            return Ok(true);
        }
        if remote.terminal() {
            if !self.state.terminal() {
                self.state = remote;
            }
            self.saw_end = true;
            return Ok(sent == Signal::EndAck);
        }
        if self.state.terminal() {
            return Ok(false);
        }
        match (self.state, remote) {
            (Signal::Invite, Signal::Ringing)
            | (Signal::Accept, Signal::Invite)
            | (Signal::Active, Signal::Active) => (),
            (Signal::Ringing, Signal::Invite) => self.invited = true,
            (Signal::Invite, Signal::Accept) | (Signal::Accept, Signal::Active) => {
                self.state = Signal::Active
            }
            (Signal::Active, Signal::Accept) if self.caller => (),
            _ => anyhow::bail!("unexpected call state"),
        }
        Ok(false)
    }
}
impl Signal {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Reject | Self::Cancel | Self::Hangup)
    }
}

#[cfg(test)]
mod dialog_tests {
    use super::*;
    #[test]
    fn idempotent_invite_consent_and_hangup() {
        let now = Instant::now();
        let (mut a, mut b) = (CallDialog::new(true, now), CallDialog::new(false, now));
        b.consent();
        assert_eq!(b.state, Signal::Ringing);
        for _ in 0..2 {
            b.observe(b.state, a.state).unwrap();
            a.observe(a.state, b.state).unwrap();
        }
        b.consent();
        b.consent();
        a.observe(a.state, b.state).unwrap();
        b.observe(b.state, a.state).unwrap();
        assert_eq!(a.state, Signal::Active);
        assert_eq!(b.state, a.state);
        b.end();
        let sent = a.state;
        a.end();
        assert!(!a.observe(sent, Signal::Active).unwrap());
        assert!(!a.observe(a.state, b.state).unwrap());
        assert_eq!(a.next(now), Signal::EndAck);
        assert!(a.observe(Signal::EndAck, b.state).unwrap());
    }
    #[test]
    fn timeout_rejection_and_unsolicited_activation() {
        let now = Instant::now();
        let mut b = CallDialog::new(false, now);
        assert!(b.observe(b.state, Signal::Active).is_err());
        assert_eq!(b.next(now + Duration::from_secs(30)), Signal::Reject);
        b.consent();
        assert_eq!(b.state, Signal::Reject);
        let mut a = CallDialog::new(true, now);
        assert_eq!(a.next(now + Duration::from_secs(30)), Signal::Cancel);
        assert!(!a.observe(a.state, Signal::Accept).unwrap());
        assert!(a.observe(a.state, Signal::EndAck).unwrap());
        assert_eq!(a.state, Signal::Cancel);
    }
}
