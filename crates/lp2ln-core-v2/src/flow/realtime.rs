use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Result, ensure};
use bytes::Bytes;
use rand::TryRngCore;
use rand_core::OsRng;
use tokio::sync::{Notify, OwnedSemaphorePermit, mpsc, oneshot};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::crypto::NodeKeypair;
use crate::router::admission::{IngressBudget, IngressPermit};
use crate::types::PeerId;

use super::FlowId;
use super::security::{
    self, ControlStream, EndpointBinding, Epochs, KIND_ACK, KIND_DATA, KIND_REKEY, KIND_SYNC,
    OVERHEAD, RecordError, RecordKeys, Role,
};

pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
pub(crate) const DATAGRAM_BUFFER: usize = 64 * 1024;
const MAX_TTL: Duration = Duration::from_secs(2);
const SYNC_LIFETIME: Duration = Duration::from_secs(300);
const MAX_PAYLOAD: usize = 4096;
const MAX_INCOMING_ITEMS: usize = 128;
const MAX_INCOMING_BYTES: usize = 256 * 1024;
const PACKETS_PER_SEC: f64 = 10_000.0;
const BURST: f64 = 32.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowError {
    Closed,
    Expired,
    ClockUncertain,
    TooLarge,
    QueueFull,
    Paced,
    Transport,
    Unsupported,
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Flow {self:?}")
    }
}
impl std::error::Error for FlowError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowCapabilities {
    pub unordered_realtime: bool,
    pub ordered_control: bool,
}

#[derive(Clone, Debug)]
pub struct FlowLink {
    pub peer: PeerId,
    pub remote: SocketAddr,
    pub rtt: Duration,
    pub capabilities: FlowCapabilities,
}

#[derive(Clone, Copy, Default, Debug)]
pub struct FlowMetrics {
    pub transport_admitted: u64,
    pub authenticated: u64,
    pub delivered: u64,
    pub invalid: u64,
    pub replay: u64,
    pub queue_age_us_total: u64,
    pub queue_age_us_max: u64,
    pub expired: u64,
    pub overloaded: u64,
    pub paced: u64,
}

#[derive(Default)]
struct Counters {
    transport_admitted: AtomicU64,
    authenticated: AtomicU64,
    delivered: AtomicU64,
    invalid: AtomicU64,
    replay: AtomicU64,
    queue_age_us_total: AtomicU64,
    queue_age_us_max: AtomicU64,
    expired: AtomicU64,
    overloaded: AtomicU64,
    paced: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> FlowMetrics {
        let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
        FlowMetrics {
            transport_admitted: load(&self.transport_admitted),
            authenticated: load(&self.authenticated),
            delivered: load(&self.delivered),
            invalid: load(&self.invalid),
            replay: load(&self.replay),
            queue_age_us_total: load(&self.queue_age_us_total),
            queue_age_us_max: load(&self.queue_age_us_max),
            expired: load(&self.expired),
            overloaded: load(&self.overloaded),
            paced: load(&self.paced),
        }
    }
}

struct Clock {
    epoch: Instant,
    wall: SystemTime,
}

impl Clock {
    fn new() -> Self {
        Self {
            epoch: Instant::now(),
            wall: SystemTime::now(),
        }
    }

    fn timestamp(&self, instant: Instant) -> u64 {
        instant.saturating_duration_since(self.epoch).as_micros() as u64
    }

    fn now(&self) -> Result<u64, FlowError> {
        let monotonic = self.epoch.elapsed();
        let wall = self.wall.elapsed().map_err(|_| FlowError::ClockUncertain)?;
        if monotonic.abs_diff(wall) > Duration::from_millis(50) {
            return Err(FlowError::ClockUncertain);
        }
        Ok(monotonic.as_micros() as u64)
    }
}

#[derive(Clone, Copy)]
struct ClockBound {
    peer_minus_local_max: i64,
    calibrated: Instant,
}

impl ClockBound {
    fn peer_upper_now(&self, clock: &Clock) -> Result<u64, FlowError> {
        let age = self.calibrated.elapsed();
        if age > SYNC_LIFETIME {
            return Err(FlowError::ClockUncertain);
        }
        // Allow 400 ppm relative drift and 1 ms timestamping error during
        // this bounded calibration interval. Suspension invalidates the clock.
        let error = age.as_micros() as i128 / 2500 + 1000;
        let upper = i128::from(clock.now()?) + i128::from(self.peer_minus_local_max) + error;
        Ok(upper.max(0) as u64)
    }
}

fn unpack_times<const N: usize>(data: &[u8]) -> Result<[u64; N]> {
    ensure!(data.len() == N * 8, "wrong clock confirmation size");
    Ok(std::array::from_fn(|i| {
        u64::from_be_bytes(data[i * 8..i * 8 + 8].try_into().unwrap())
    }))
}

fn times_bytes(values: &[u64]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_be_bytes()).collect()
}

async fn read_control(
    control: &mut ControlStream,
    keys: &mut RecordKeys,
    kind: u8,
) -> Result<Vec<u8>> {
    let (expires, payload) = keys
        .open(kind, &control.read().await?)
        .map_err(|e| anyhow::anyhow!("bad encrypted control record: {e:?}"))?;
    ensure!(expires == 0, "invalid control deadline");
    Ok(payload)
}

async fn confirm(
    control: &mut ControlStream,
    keys: &mut RecordKeys,
    clock: &Clock,
    role: Role,
) -> Result<ClockBound> {
    let bound = match role {
        Role::Initiator => {
            let i1 = clock.now()?;
            control
                .write(&keys.seal(KIND_SYNC, 0, &i1.to_be_bytes())?)
                .await?;
            let reply = read_control(control, keys, KIND_ACK).await?;
            let i4 = clock.now()?;
            let [echo, r2, r3] = unpack_times(&reply)?;
            ensure!(
                echo == i1 && r3 >= r2 && i4 >= i1,
                "invalid clock confirmation reply"
            );
            control
                .write(&keys.seal(KIND_SYNC, 0, &times_bytes(&[i1, r2, r3, i4]))?)
                .await?;
            ensure!(
                read_control(control, keys, KIND_ACK).await?.is_empty(),
                "invalid key confirmation"
            );
            i128::from(r2) - i128::from(i1)
        }
        Role::Responder => {
            let [i1] = unpack_times(&read_control(control, keys, KIND_SYNC).await?)?;
            let r2 = clock.now()?;
            let r3 = clock.now()?;
            control
                .write(&keys.seal(KIND_ACK, 0, &times_bytes(&[i1, r2, r3]))?)
                .await?;
            let [echo, echo_r2, echo_r3, i4] =
                unpack_times(&read_control(control, keys, KIND_SYNC).await?)?;
            ensure!(
                echo == i1 && echo_r2 == r2 && echo_r3 == r3 && i4 >= i1,
                "invalid key confirmation"
            );
            control.write(&keys.seal(KIND_ACK, 0, &[])?).await?;
            i128::from(i4) - i128::from(r3)
        }
    };
    Ok(ClockBound {
        peer_minus_local_max: bound.try_into()?,
        calibrated: Instant::now(),
    })
}

struct Pacer {
    time: Instant,
    tokens: f64,
}

impl Pacer {
    fn take(&mut self, now: Instant) -> bool {
        self.tokens = (self.tokens + now.duration_since(self.time).as_secs_f64() * PACKETS_PER_SEC)
            .min(BURST);
        self.time = now;
        if self.tokens < 1.0 {
            false
        } else {
            self.tokens -= 1.0;
            true
        }
    }
}

struct Live {
    keys: Epochs,
    bound: ClockBound,
    pacer: Pacer,
}

struct FlowShared {
    connection: quinn::Connection,
    link: FlowLink,
    clock: Clock,
    closed: CancellationToken,
    live: Mutex<Option<Live>>,
    metrics: Counters,
    budget: Arc<IngressBudget>,
    incoming: ReceiveQueue,
}

impl FlowShared {
    fn path_valid(&self) -> bool {
        self.connection.remote_address() == self.link.remote
            && !self.closed.is_cancelled()
            && self.connection.close_reason().is_none()
    }

    fn stop(&self) {
        self.closed.cancel();
        self.live.lock().unwrap().take();
        self.incoming.items.lock().unwrap().clear();
        self.connection.close(0_u32.into(), b"flow closed");
    }

    fn close_on_path_change(&self) -> Result<(), FlowError> {
        if self.path_valid() {
            Ok(())
        } else {
            self.stop();
            Err(FlowError::Closed)
        }
    }
}

#[derive(Clone)]
pub struct FlowSender(Arc<FlowShared>);

impl FlowSender {
    pub fn rtt(&self) -> Duration {
        self.0.connection.rtt()
    }

    pub fn max_payload(&self) -> usize {
        self.0
            .connection
            .max_datagram_size()
            .unwrap_or_default()
            .saturating_sub(OVERHEAD)
            .min(MAX_PAYLOAD)
    }

    /// Success counts admission into the bounded QUIC buffer. Unordered
    /// datagrams can be lost or expire in flight.
    pub fn try_send(&self, data: &[u8], deadline: Instant) -> Result<(), FlowError> {
        let shared = &self.0;
        shared.close_on_path_change()?;
        let now = Instant::now();
        if deadline <= now || deadline.duration_since(now) > MAX_TTL {
            shared.metrics.expired.fetch_add(1, Ordering::Relaxed);
            return Err(FlowError::Expired);
        }
        shared.clock.now()?;
        if data.is_empty() || data.len() > self.max_payload() {
            return Err(FlowError::TooLarge);
        }
        let mut locked = shared.live.lock().unwrap();
        let live = locked.as_mut().ok_or(FlowError::Closed)?;
        live.bound.peer_upper_now(&shared.clock)?;
        if !live.pacer.take(Instant::now()) {
            shared.metrics.paced.fetch_add(1, Ordering::Relaxed);
            return Err(FlowError::Paced);
        }
        if shared.connection.datagram_send_buffer_space() < data.len() + OVERHEAD {
            shared.metrics.overloaded.fetch_add(1, Ordering::Relaxed);
            return Err(FlowError::QueueFull);
        }
        let _scratch = shared
            .budget
            .wire((data.len() + OVERHEAD) * 2 + 256)
            .ok_or_else(|| {
                shared.metrics.overloaded.fetch_add(1, Ordering::Relaxed);
                FlowError::QueueFull
            })?;
        let record = live
            .keys
            .current
            .seal(KIND_DATA, shared.clock.timestamp(deadline), data)
            .map_err(|_| FlowError::Transport)?;
        if Instant::now() >= deadline {
            shared.metrics.expired.fetch_add(1, Ordering::Relaxed);
            return Err(FlowError::Expired);
        }
        shared
            .connection
            .send_datagram(Bytes::from(record))
            .map_err(|error| match error {
                quinn::SendDatagramError::TooLarge => FlowError::TooLarge,
                quinn::SendDatagramError::ConnectionLost(_) => FlowError::Closed,
                _ => FlowError::Transport,
            })?;
        shared
            .metrics
            .transport_admitted
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn metrics(&self) -> FlowMetrics {
        self.0.metrics.snapshot()
    }
}

struct Received {
    admitted: Instant,
    bytes: Bytes,
    expiry: u64,
    _node: IngressPermit,
    _flow: OwnedSemaphorePermit,
}

#[derive(Default)]
struct ReceiveQueue {
    items: Mutex<VecDeque<Received>>,
    ready: Notify,
}

impl ReceiveQueue {
    fn prune(&self, upper: u64) -> usize {
        let mut items = self.items.lock().unwrap();
        let before = items.len();
        items.retain(|queued| queued.expiry > upper);
        before - items.len()
    }
}

enum Command {
    Exchange(Vec<u8>, oneshot::Sender<Result<Vec<u8>>>),
    Rotate(oneshot::Sender<Result<()>>),
}

pub struct Flow {
    id: FlowId,
    protocol: u16,
    role: Role,
    sender: FlowSender,
    commands: mpsc::Sender<Command>,
}

impl Flow {
    pub fn id(&self) -> FlowId {
        self.id
    }
    pub fn protocol(&self) -> u16 {
        self.protocol
    }
    pub fn link(&self) -> &FlowLink {
        &self.sender.0.link
    }
    pub fn sender(&self) -> FlowSender {
        self.sender.clone()
    }
    pub fn metrics(&self) -> FlowMetrics {
        self.sender.metrics()
    }

    pub async fn recv(&mut self) -> Result<Bytes, FlowError> {
        self.recv_with_deadline().await.map(|(bytes, _)| bytes)
    }

    /// Local monotonic expiry at application handoff. Consumers that buffer
    /// payloads can keep enforcing the authenticated sender's original TTL.
    pub async fn recv_with_deadline(&mut self) -> Result<(Bytes, Instant), FlowError> {
        let shared = &self.sender.0;
        loop {
            let item = loop {
                let ready = shared.incoming.ready.notified();
                tokio::pin!(ready);
                ready.as_mut().enable();
                if shared.closed.is_cancelled() {
                    return Err(FlowError::Closed);
                }
                let item = shared.incoming.items.lock().unwrap().pop_front();
                if let Some(item) = item {
                    break item;
                }
                tokio::select! {
                    _ = shared.closed.cancelled() => return Err(FlowError::Closed),
                    _ = &mut ready => {}
                }
            };
            let observed = Instant::now();
            let upper = shared
                .live
                .lock()
                .unwrap()
                .as_ref()
                .ok_or(FlowError::Closed)?
                .bound
                .peer_upper_now(&shared.clock)?;
            if upper >= item.expiry {
                shared.metrics.expired.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let age = item.admitted.elapsed().as_micros() as u64;
            shared
                .metrics
                .queue_age_us_total
                .fetch_add(age, Ordering::Relaxed);
            shared
                .metrics
                .queue_age_us_max
                .fetch_max(age, Ordering::Relaxed);
            shared.metrics.delivered.fetch_add(1, Ordering::Relaxed);
            // Same 400 ppm relative clock drift allowance used at calibration.
            let remain = (item.expiry - upper) * 2500 / 2501;
            return Ok((item.bytes, observed + Duration::from_micros(remain)));
        }
    }

    pub fn control(&self) -> FlowControl {
        FlowControl {
            commands: self.commands.clone(),
            initiator: self.role == Role::Initiator,
        }
    }
    pub async fn rotate_keys(&self) -> Result<()> {
        self.control().rotate_keys().await
    }

    pub fn close(&mut self) {
        self.sender.0.stop();
    }
}

/// Bounded ordered request/reply for applications which negotiated this feature
/// through their application protocol ID. Independent of datagram reception.
#[derive(Clone)]
pub struct FlowControl {
    commands: mpsc::Sender<Command>,
    initiator: bool,
}

impl FlowControl {
    pub async fn exchange(&self, local: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            (1..=512).contains(&local.len()),
            "invalid control payload length"
        );
        let (reply, result) = oneshot::channel();
        self.commands
            .try_send(Command::Exchange(local.to_vec(), reply))
            .map_err(|_| FlowError::QueueFull)?;
        tokio::time::timeout(HANDSHAKE_TIMEOUT + Duration::from_secs(2), result).await??
    }

    /// The initiator can request an authenticated fresh Noise handshake on
    /// the independent reliable control stream.
    pub async fn rotate_keys(&self) -> Result<()> {
        ensure!(self.initiator, "only initiator can rotate Flow keys");
        let (reply, result) = oneshot::channel();
        self.commands
            .try_send(Command::Rotate(reply))
            .map_err(|_| FlowError::QueueFull)?;
        tokio::time::timeout(HANDSHAKE_TIMEOUT + Duration::from_secs(1), result).await??
    }
}

impl Drop for Flow {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) struct FlowLifetime {
    pub(crate) budget: Arc<IngressBudget>,
    pub(crate) native: Option<IngressPermit>,
    pub(crate) pre_auth: Option<IngressPermit>,
    pub(crate) end: CancellationToken,
    pub(crate) tasks: TaskTracker,
    pub(crate) slots: OwnedSemaphorePermit,
}

pub(crate) struct FlowRequest<'a> {
    pub(crate) peer: &'a str,
    pub(crate) protocol: u16,
}

pub(crate) async fn establish(
    endpoint: Arc<quinn::Endpoint>,
    connection: quinn::Connection,
    identity: Arc<NodeKeypair>,
    outbound: Option<FlowRequest<'_>>,
    allows: impl Fn(&str, u16) -> bool,
    mut lifetime: FlowLifetime,
) -> Result<Flow> {
    ensure!(
        connection
            .max_datagram_size()
            .is_some_and(|size| size > OVERHEAD),
        "peer has no usable QUIC DATAGRAM"
    );
    let clock = Clock::new();
    let progress = async {
        let outbound = match outbound {
            Some(request) => {
                let mut id = [0; 16];
                OsRng.try_fill_bytes(&mut id)?;
                Some((request.peer, FlowId(id), request.protocol))
            }
            None => None,
        };
        let (send, recv) = if outbound.is_some() {
            connection.open_bi().await?
        } else {
            connection.accept_bi().await?
        };
        let mut control = ControlStream { send, recv };
        let binding =
            security::authenticate_link(&connection, &mut control, &identity, outbound, allows)
                .await?;
        let peer_permit = lifetime
            .budget
            .admit_flow(binding.remote())
            .ok_or(FlowError::QueueFull)?;
        let mut keys = security::noise_xx(&mut control, &binding, &identity, 0).await?;
        let bound = confirm(&mut control, &mut keys, &clock, binding.role).await?;
        Ok::<_, anyhow::Error>((control, binding, keys, bound, peer_permit))
    };
    let established = tokio::select! {
        biased;
        _ = lifetime.end.cancelled() => Err(FlowError::Closed.into()),
        result = tokio::time::timeout(HANDSHAKE_TIMEOUT, progress) => result.map_err(anyhow::Error::from).and_then(|r| r),
    };
    let (control, binding, keys, bound, peer_permit) = match established {
        Ok(v) => v,
        Err(error) => {
            connection.close(1_u32.into(), b"flow negotiation failed");
            return Err(error);
        }
    };
    drop(lifetime.pre_auth.take());
    let closed = lifetime.end.child_token();
    let shared = Arc::new(FlowShared {
        link: FlowLink {
            peer: PeerId::from(binding.remote()),
            remote: connection.remote_address(),
            rtt: connection.rtt(),
            capabilities: FlowCapabilities {
                unordered_realtime: true,
                ordered_control: true,
            },
        },
        connection,
        clock,
        closed,
        live: Mutex::new(Some(Live {
            keys: Epochs::new(keys),
            bound,
            pacer: Pacer {
                time: Instant::now(),
                tokens: BURST,
            },
        })),
        metrics: Counters::default(),
        budget: lifetime.budget.clone(),
        incoming: ReceiveQueue::default(),
    });
    let (commands, controls) = mpsc::channel(1);
    let task_shared = shared.clone();
    let id = binding.id;
    let protocol = binding.protocol;
    let role = binding.role;
    let tracker = lifetime.tasks.clone();
    tracker.spawn(async move {
        let _lifetime = (endpoint, lifetime.native, lifetime.slots, peer_permit);
        let control_shared = task_shared.clone();
        let control_task = control_loop(control_shared, control, identity, binding, controls);
        let receive_task = receive_loop(&task_shared);
        tokio::select! {
            _ = task_shared.closed.cancelled() => {}
            _ = task_shared.connection.closed() => {}
            _ = control_task => {}
            _ = receive_task => {}
        }
        task_shared.stop();
    });
    Ok(Flow {
        id,
        protocol,
        role,
        sender: FlowSender(shared),
        commands,
    })
}

async fn receive_loop(shared: &FlowShared) -> Result<()> {
    let flow_budget = Arc::new(tokio::sync::Semaphore::new(MAX_INCOMING_BYTES));
    let mut retire = tokio::time::interval(Duration::from_millis(40));
    loop {
        let wire = tokio::select! {
            _ = retire.tick() => {
                let upper = {
                    let mut state = shared.live.lock().unwrap();
                    let live = state.as_mut().ok_or(FlowError::Closed)?;
                    live.keys.retire(Instant::now());
                    live.bound.peer_upper_now(&shared.clock)?
                };
                let n = shared.incoming.prune(upper);
                shared.metrics.expired.fetch_add(n as u64, Ordering::Relaxed);
                shared.close_on_path_change()?;
                continue;
            }
            result = shared.connection.read_datagram() => result?,
        };
        shared.close_on_path_change()?;
        let Some(mut node) = shared.budget.wire(3 * wire.len() + 256) else {
            shared.metrics.overloaded.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let (upper, record) = {
            let mut slot = shared.live.lock().unwrap();
            let live = slot.as_mut().ok_or(FlowError::Closed)?;
            (
                live.bound.peer_upper_now(&shared.clock)?,
                live.keys.open_data(&wire, Instant::now()),
            )
        };
        let (expiry, data) = match record {
            Ok(msg) => msg,
            Err(error) => {
                let counter = if error == RecordError::Replay {
                    &shared.metrics.replay
                } else {
                    &shared.metrics.invalid
                };
                counter.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        drop(wire);
        shared.metrics.authenticated.fetch_add(1, Ordering::Relaxed);
        if expiry <= upper {
            shared.metrics.expired.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if expiry > upper.saturating_add(MAX_TTL.as_micros() as u64) {
            shared.metrics.invalid.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let charge = data.capacity() + 256;
        let Ok(flow) = flow_budget.clone().try_acquire_many_owned(charge as u32) else {
            shared.metrics.overloaded.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        node.shrink(charge);
        let mut items = shared.incoming.items.lock().unwrap();
        if shared.closed.is_cancelled() {
            return Ok(());
        }
        if items.len() >= MAX_INCOMING_ITEMS {
            shared.metrics.overloaded.fetch_add(1, Ordering::Relaxed);
        } else {
            items.push_back(Received {
                admitted: Instant::now(),
                expiry,
                bytes: Bytes::from(data),
                _node: node,
                _flow: flow,
            });
            shared.incoming.ready.notify_one();
        }
    }
}

fn current_epoch(shared: &FlowShared) -> Result<u32> {
    Ok(shared
        .live
        .lock()
        .unwrap()
        .as_ref()
        .ok_or(FlowError::Closed)?
        .keys
        .current
        .epoch())
}

fn rekey_proof(shared: &FlowShared, epoch: u32) -> Result<Vec<u8>> {
    Ok(shared
        .live
        .lock()
        .unwrap()
        .as_mut()
        .ok_or(FlowError::Closed)?
        .keys
        .current
        .seal(KIND_REKEY, 0, &epoch.to_be_bytes())?)
}

fn check_rekey(shared: &FlowShared, wire: &[u8], expected: u32) -> Result<()> {
    let (expiry, data) = shared
        .live
        .lock()
        .unwrap()
        .as_mut()
        .ok_or(FlowError::Closed)?
        .keys
        .current
        .open(KIND_REKEY, wire)
        .map_err(|_| anyhow::anyhow!("invalid rekey proof"))?;
    ensure!(
        expiry == 0 && data == expected.to_be_bytes(),
        "invalid rekey epoch"
    );
    Ok(())
}

const KIND_APP: u8 = 5;

fn app_record(shared: &FlowShared, data: &[u8]) -> Result<Vec<u8>> {
    shared
        .live
        .lock()
        .unwrap()
        .as_mut()
        .ok_or(FlowError::Closed)?
        .keys
        .current
        .seal(KIND_APP, 0, data)
}

fn open_app(shared: &FlowShared, wire: &[u8]) -> Result<Vec<u8>> {
    let (expiry, payload) = shared
        .live
        .lock()
        .unwrap()
        .as_mut()
        .ok_or(FlowError::Closed)?
        .keys
        .current
        .open(KIND_APP, wire)
        .map_err(|e| anyhow::anyhow!("control: {e:?}"))?;
    ensure!(
        expiry == 0 && (1..=512).contains(&payload.len()),
        "invalid app control"
    );
    Ok(payload)
}

async fn control_loop(
    shared: Arc<FlowShared>,
    mut control: ControlStream,
    identity: Arc<NodeKeypair>,
    binding: EndpointBinding,
    mut commands: mpsc::Receiver<Command>,
) -> Result<()> {
    loop {
        if binding.role == Role::Initiator {
            let Some(command) = commands.recv().await else {
                return Ok(());
            };
            let reply = match command {
                Command::Rotate(reply) => reply,
                Command::Exchange(local, reply) => {
                    if reply.is_closed() {
                        return Ok(());
                    }
                    let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
                        control.write(&app_record(&shared, &local)?).await?;
                        open_app(&shared, &control.read().await?)
                    })
                    .await
                    .map_err(anyhow::Error::from)
                    .and_then(|r| r);
                    let failed = result.is_err();
                    let abandoned = reply.send(result).is_err();
                    if failed || abandoned {
                        return Ok(());
                    }
                    continue;
                }
            };
            let outcome = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
                let next = current_epoch(&shared)?
                    .checked_add(1)
                    .ok_or(FlowError::Transport)?;
                control.write(&rekey_proof(&shared, next)?).await?;
                check_rekey(&shared, &control.read().await?, next)?;
                rotate(&shared, &mut control, &identity, &binding, next).await
            })
            .await;
            let result = outcome.map_err(anyhow::Error::from).and_then(|inner| inner);
            let fatal = result.is_err();
            let _ = reply.send(result);
            if fatal {
                return Ok(());
            }
        } else {
            let proof = control.read().await?;
            if let Ok(remote) = open_app(&shared, &proof) {
                let Some(Command::Exchange(local, reply)) =
                    tokio::time::timeout(HANDSHAKE_TIMEOUT, commands.recv()).await?
                else {
                    return Ok(());
                };
                if reply.is_closed() {
                    return Ok(());
                }
                tokio::time::timeout(
                    HANDSHAKE_TIMEOUT,
                    control.write(&app_record(&shared, &local)?),
                )
                .await??;
                if reply.send(Ok(remote)).is_err() {
                    return Ok(());
                }
                continue;
            }
            tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
                let next = current_epoch(&shared)?
                    .checked_add(1)
                    .ok_or(FlowError::Transport)?;
                check_rekey(&shared, &proof, next)?;
                control.write(&rekey_proof(&shared, next)?).await?;
                rotate(&shared, &mut control, &identity, &binding, next).await
            })
            .await??;
        }
    }
}

async fn rotate(
    shared: &FlowShared,
    control: &mut ControlStream,
    identity: &NodeKeypair,
    binding: &EndpointBinding,
    next: u32,
) -> Result<()> {
    let _scratch = shared
        .budget
        .verified_control(binding.remote(), 16 * 1024)
        .ok_or(FlowError::QueueFull)?;
    let mut keys = security::noise_xx(control, binding, identity, next).await?;
    let bound = confirm(control, &mut keys, &shared.clock, binding.role).await?;
    let mut slot = shared.live.lock().unwrap();
    let live = slot.as_mut().ok_or(FlowError::Closed)?;
    live.keys.install(keys, Instant::now())?;
    live.bound = bound;
    Ok(())
}
