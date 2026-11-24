use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;

use crate::sessions::{IncomingPacket, manager::SessionManager};
use crate::types::SessionId;

const MIB: usize = 1024 * 1024;
const DATA_LIMIT: usize = 256 * MIB;
const FANOUT_LIMIT: usize = 128 * MIB;
const NATIVE_LIMIT: usize = 256 * MIB;
const PRE_AUTH_LIMIT: usize = 16 * MIB;
const CONTROL_LIMIT: usize = 2 * MIB;
const CONTROL_PEER_LIMIT: usize = 256 * 1024;
const SESSION_LIMIT: usize = 144 * MIB;
const PEER_LIMIT: usize = 160 * MIB;
const SUBSCRIBER_LIMIT: usize = 48 * MIB;
const ADMISSION_WAIT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
enum Pool {
    Ingress,
    Fanout,
    Native,
    PreAuth,
    Control,
}

impl Pool {
    fn limit(self) -> usize {
        match self {
            Self::Ingress => DATA_LIMIT,
            Self::Fanout => FANOUT_LIMIT,
            Self::Native => NATIVE_LIMIT,
            Self::PreAuth => PRE_AUTH_LIMIT,
            Self::Control => CONTROL_LIMIT,
        }
    }
}

#[derive(Clone, Default)]
struct Scope {
    session: Option<Arc<str>>,
    peer: Option<Arc<str>>,
    subscriber: Option<u64>,
}

#[derive(Default)]
struct Usage {
    ingress: usize,
    fanout: usize,
    native: usize,
    pre_auth: usize,
    control: usize,
    control_peers: HashMap<Arc<str>, usize>,
    live_flows: HashMap<Arc<str>, usize>,
    peak: usize,
    refused: u64,
    reliable_refused: u64,
    sessions: HashMap<Arc<str>, usize>,
    peers: HashMap<Arc<str>, usize>,
    subscribers: HashMap<u64, usize>,
}

impl Usage {
    fn pool(&mut self, pool: Pool) -> &mut usize {
        match pool {
            Pool::Ingress => &mut self.ingress,
            Pool::Fanout => &mut self.fanout,
            Pool::Native => &mut self.native,
            Pool::PreAuth => &mut self.pre_auth,
            Pool::Control => &mut self.control,
        }
    }
}

#[derive(Default)]
pub(crate) struct IngressBudget {
    usage: Mutex<Usage>,
    released: Notify,
    contention: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IngressMemory {
    pub ingress_bytes: usize,
    pub fanout_bytes: usize,
    pub native_credit_bytes: usize,
    pub pre_auth_bytes: usize,
    pub control_bytes: usize,
    pub peak_bytes: usize,
    pub refused: u64,
    pub reliable_refused: u64,
    pub contended: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressAdmissionError {
    Oversize,
    Overloaded,
    Closed,
}

impl std::fmt::Display for IngressAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Oversize => "ingress reservation exceeds its byte limit",
            Self::Overloaded => "ingress admission exhausted its budget",
            Self::Closed => "ingress closed",
        })
    }
}

impl std::error::Error for IngressAdmissionError {}

impl IngressBudget {
    fn lock(&self) -> MutexGuard<'_, Usage> {
        match self.usage.try_lock() {
            Ok(usage) => usage,
            Err(std::sync::TryLockError::WouldBlock) => {
                self.contention.fetch_add(1, Ordering::Relaxed);
                self.usage.lock().unwrap()
            }
            Err(std::sync::TryLockError::Poisoned(err)) => {
                panic!("ingress accounting poisoned: {err}")
            }
        }
    }

    pub(crate) fn snapshot(&self) -> IngressMemory {
        let usage = self.lock();
        IngressMemory {
            ingress_bytes: usage.ingress,
            fanout_bytes: usage.fanout,
            native_credit_bytes: usage.native,
            pre_auth_bytes: usage.pre_auth,
            control_bytes: usage.control,
            peak_bytes: usage.peak,
            refused: usage.refused,
            reliable_refused: usage.reliable_refused,
            contended: self.contention.load(Ordering::Relaxed),
        }
    }

    fn refuse(&self) {
        self.lock().refused += 1;
    }

    fn refuse_reliable(&self) {
        self.lock().reliable_refused += 1;
    }

    // All limits are tested and reserved atomically. No task waits holding
    // partial capacity at one scope while trying to acquire a second scope.
    fn try_acquire(
        self: &Arc<Self>,
        pool: Pool,
        scope: &Scope,
        bytes: usize,
    ) -> Option<IngressPermit> {
        let bytes = bytes.max(1);
        let mut usage = self.lock();
        if bytes > pool.limit().saturating_sub(*usage.pool(pool))
            || !fits(
                &usage.sessions,
                scope.session.as_ref(),
                bytes,
                SESSION_LIMIT,
            )
            || if matches!(pool, Pool::Control) {
                !fits(
                    &usage.control_peers,
                    scope.peer.as_ref(),
                    bytes,
                    CONTROL_PEER_LIMIT,
                )
            } else {
                !fits(&usage.peers, scope.peer.as_ref(), bytes, PEER_LIMIT)
            }
            || !fits(
                &usage.subscribers,
                scope.subscriber.as_ref(),
                bytes,
                SUBSCRIBER_LIMIT,
            )
        {
            return None;
        }
        *usage.pool(pool) += bytes;
        add(&mut usage.sessions, scope.session.as_ref(), bytes);
        if matches!(pool, Pool::Control) {
            add(&mut usage.control_peers, scope.peer.as_ref(), bytes);
        } else {
            add(&mut usage.peers, scope.peer.as_ref(), bytes);
        }
        add(&mut usage.subscribers, scope.subscriber.as_ref(), bytes);
        usage.peak = usage
            .peak
            .max(usage.ingress + usage.fanout + usage.pre_auth + usage.control);
        Some(IngressPermit {
            budget: self.clone(),
            pool,
            scope: scope.clone(),
            bytes,
        })
    }

    async fn acquire(
        self: &Arc<Self>,
        scope: Scope,
        bytes: usize,
        reliable: bool,
    ) -> Result<IngressPermit, IngressAdmissionError> {
        if bytes > DATA_LIMIT
            || scope.session.is_some() && bytes > SESSION_LIMIT
            || scope.peer.is_some() && bytes > PEER_LIMIT
        {
            self.refuse();
            return Err(IngressAdmissionError::Oversize);
        }
        let wait = async {
            loop {
                let released = self.released.notified();
                tokio::pin!(released);
                released.as_mut().enable();
                if let Some(permit) = self.try_acquire(Pool::Ingress, &scope, bytes) {
                    return Some(permit);
                }
                if !reliable {
                    return None;
                }
                released.await;
            }
        };
        match tokio::time::timeout_at(Instant::now() + ADMISSION_WAIT, wait).await {
            Ok(Some(permit)) => Ok(permit),
            _ => {
                self.refuse();
                Err(IngressAdmissionError::Overloaded)
            }
        }
    }

    pub(crate) fn wire(self: &Arc<Self>, bytes: usize) -> Option<IngressPermit> {
        self.reserve_aux(Pool::Ingress, Scope::default(), bytes)
    }

    pub(crate) fn admit_flow(self: &Arc<Self>, peer: &str) -> Option<FlowPeerPermit> {
        let mut usage = self.lock();
        if usage.live_flows.get(peer).is_some_and(|count| *count >= 4) {
            usage.refused += 1;
            return None;
        }
        let peer: Arc<str> = peer.into();
        *usage.live_flows.entry(peer.clone()).or_default() += 1;
        Some(FlowPeerPermit {
            budget: self.clone(),
            peer,
        })
    }

    pub(crate) fn native(self: &Arc<Self>, bytes: usize) -> Option<IngressPermit> {
        self.reserve_aux(Pool::Native, Scope::default(), bytes)
    }

    pub(crate) fn pre_auth(self: &Arc<Self>, bytes: usize) -> Option<IngressPermit> {
        self.reserve_aux(Pool::PreAuth, Scope::default(), bytes)
    }

    pub(crate) fn verified_control(
        self: &Arc<Self>,
        peer: &str,
        bytes: usize,
    ) -> Option<IngressPermit> {
        self.reserve_aux(
            Pool::Control,
            Scope {
                peer: Some(peer.into()),
                ..Scope::default()
            },
            bytes,
        )
    }

    fn reserve_aux(
        self: &Arc<Self>,
        pool: Pool,
        scope: Scope,
        bytes: usize,
    ) -> Option<IngressPermit> {
        let permit = self.try_acquire(pool, &scope, bytes);
        if permit.is_none() {
            self.refuse();
        }
        permit
    }

    pub(crate) fn fanout(
        self: &Arc<Self>,
        bytes: usize,
        subscriber: Option<u64>,
    ) -> Option<IngressPermit> {
        let scope = Scope {
            subscriber,
            ..Scope::default()
        };
        let permit = self.try_acquire(Pool::Fanout, &scope, bytes);
        if permit.is_none() {
            self.refuse();
        }
        permit
    }

    pub(crate) fn legacy(
        self: &Arc<Self>,
        session: &str,
        peer: Option<&str>,
        bytes: usize,
    ) -> Option<IngressPermit> {
        let scope = Scope {
            session: Some(session.into()),
            peer: peer.map(Arc::from),
            subscriber: None,
        };
        let permit = self.try_acquire(Pool::Ingress, &scope, bytes);
        if permit.is_none() {
            self.refuse();
        }
        permit
    }
}

fn fits<K: Eq + std::hash::Hash>(
    entries: &HashMap<K, usize>,
    key: Option<&K>,
    bytes: usize,
    limit: usize,
) -> bool {
    key.is_none_or(|key| {
        bytes <= limit.saturating_sub(entries.get(key).copied().unwrap_or_default())
    })
}

fn add<K: Clone + Eq + std::hash::Hash>(
    entries: &mut HashMap<K, usize>,
    key: Option<&K>,
    bytes: usize,
) {
    if let Some(key) = key {
        *entries.entry(key.clone()).or_default() += bytes;
    }
}

fn release<K: Eq + std::hash::Hash>(
    entries: &mut HashMap<K, usize>,
    key: Option<&K>,
    bytes: usize,
) {
    if let Some(key) = key
        && let Some(usage) = entries.get_mut(key)
    {
        *usage -= bytes;
        if *usage == 0 {
            entries.remove(key);
        }
    }
}

pub(crate) struct FlowPeerPermit {
    budget: Arc<IngressBudget>,
    peer: Arc<str>,
}

impl Drop for FlowPeerPermit {
    fn drop(&mut self) {
        release(&mut self.budget.lock().live_flows, Some(&self.peer), 1);
    }
}

pub(crate) struct IngressPermit {
    budget: Arc<IngressBudget>,
    pool: Pool,
    scope: Scope,
    bytes: usize,
}

impl IngressPermit {
    pub(crate) fn shrink(&mut self, bytes: usize) {
        if let Some(released) = self.bytes.checked_sub(bytes)
            && released != 0
        {
            self.bytes = bytes;
            self.release(released);
        }
    }

    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(crate) fn try_resize(&mut self, bytes: usize) -> bool {
        if let Some(additional) = bytes.checked_sub(self.bytes).filter(|delta| *delta != 0) {
            let Some(mut extra) = self.try_copy(additional) else {
                return false;
            };
            self.bytes = bytes;
            extra.bytes = 0;
        } else {
            self.shrink(bytes);
        }
        true
    }

    pub(crate) fn try_copy(&self, bytes: usize) -> Option<Self> {
        let permit = self.budget.try_acquire(self.pool, &self.scope, bytes);
        if permit.is_none() {
            self.budget.refuse();
        }
        permit
    }

    fn release(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let mut usage = self.budget.lock();
        *usage.pool(self.pool) -= bytes;
        release(&mut usage.sessions, self.scope.session.as_ref(), bytes);
        if matches!(self.pool, Pool::Control) {
            release(&mut usage.control_peers, self.scope.peer.as_ref(), bytes);
        } else {
            release(&mut usage.peers, self.scope.peer.as_ref(), bytes);
        }
        release(
            &mut usage.subscribers,
            self.scope.subscriber.as_ref(),
            bytes,
        );
        drop(usage);
        self.budget.released.notify_waiters();
    }
}

impl Drop for IngressPermit {
    fn drop(&mut self) {
        self.release(self.bytes);
    }
}

pub(crate) struct AdmittedPacket {
    pub(crate) incoming: IncomingPacket,
    pub(crate) permit: IngressPermit,
}

/// Additive reader admission for built-in sessions. The raw legacy sender is
/// available to older transports via the default Session implementation.
#[derive(Clone)]
pub struct SessionIngress {
    budget: Arc<IngressBudget>,
    manager: Weak<SessionManager>,
    tx: mpsc::Sender<AdmittedPacket>,
    legacy: mpsc::Sender<IncomingPacket>,
    session: SessionId,
    session_key: Arc<str>,
    reliable: bool,
}

impl SessionIngress {
    pub(crate) fn new(
        budget: Arc<IngressBudget>,
        manager: Arc<SessionManager>,
        tx: mpsc::Sender<AdmittedPacket>,
        legacy: mpsc::Sender<IncomingPacket>,
        session: SessionId,
        reliable: bool,
    ) -> Self {
        let session_key = Arc::from(session.as_str());
        Self {
            budget,
            manager: Arc::downgrade(&manager),
            tx,
            legacy,
            session,
            session_key,
            reliable,
        }
    }

    pub fn legacy_sender(&self) -> mpsc::Sender<IncomingPacket> {
        self.legacy.clone()
    }

    pub(crate) async fn reserve_decode(
        &self,
        bytes: usize,
    ) -> Result<IngressPermit, IngressAdmissionError> {
        let scope = Scope {
            session: Some(self.session_key.clone()),
            peer: self
                .manager
                .upgrade()
                .and_then(|manager| manager.get_peer_for_session(&self.session))
                .map(|p| Arc::from(p.as_str())),
            subscriber: None,
        };
        let result = tokio::select! {
            _ = self.tx.closed() => Err(IngressAdmissionError::Closed),
            result = self.budget.acquire(scope, bytes, self.reliable) => result,
        };
        if self.reliable
            && matches!(
                result,
                Err(IngressAdmissionError::Overloaded | IngressAdmissionError::Oversize)
            )
        {
            self.budget.refuse_reliable();
        }
        result
    }

    pub(crate) async fn submit(
        &self,
        incoming: IncomingPacket,
        mut permit: IngressPermit,
    ) -> Result<(), IngressAdmissionError> {
        let bytes = decode_retained_bytes(&incoming);
        if bytes > permit.bytes() {
            self.budget.refuse();
            if self.reliable {
                self.budget.refuse_reliable();
            }
            return Err(IngressAdmissionError::Oversize);
        }
        permit.shrink(bytes);
        let admitted = AdmittedPacket { incoming, permit };
        if !self.reliable {
            return self.tx.try_send(admitted).map_err(|error| {
                self.budget.refuse();
                match error {
                    mpsc::error::TrySendError::Full(_) => IngressAdmissionError::Overloaded,
                    mpsc::error::TrySendError::Closed(_) => IngressAdmissionError::Closed,
                }
            });
        }
        match tokio::time::timeout(ADMISSION_WAIT, self.tx.send(admitted)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(IngressAdmissionError::Closed),
            Err(_) => {
                self.budget.refuse();
                self.budget.refuse_reliable();
                Err(IngressAdmissionError::Overloaded)
            }
        }
    }
}

/// Includes heap capacities and a fixed allowance for queue/Arc and map cells.
pub(crate) fn retained_bytes(ip: &IncomingPacket) -> usize {
    retained_packet_bytes(
        ip.session_id.capacity(),
        ip.from_node.as_ref().map_or(0, String::capacity),
        &ip.packet,
    )
}

pub(crate) fn retained_packet_bytes(session: usize, peer: usize, packet: &crate::Packet) -> usize {
    256 + std::mem::size_of::<IncomingPacket>()
        + session
        + peer
        + packet.data.capacity()
        + packet.signature.as_ref().map_or(0, String::capacity)
        + packet.sender.capacity()
        + packet.receiver.capacity()
        + packet.nodes.capacity() * std::mem::size_of::<String>()
        + packet.nodes.iter().map(String::capacity).sum::<usize>()
}

/// Legacy signature serialization and AEAD run sequentially. Reserve a
/// conservative upper bound for whichever temporary representation is larger.
pub(crate) fn decode_retained_bytes(ip: &IncomingPacket) -> usize {
    retained_bytes(ip).saturating_add(2 * ip.packet.wire_size_estimate() as usize + 1024)
}

pub(crate) enum ReaderIngress {
    Legacy(mpsc::Sender<IncomingPacket>),
    Budgeted(SessionIngress),
}

impl ReaderIngress {
    pub(crate) async fn reserve(&self, bytes: usize) -> anyhow::Result<Option<IngressPermit>> {
        match self {
            Self::Legacy(_) => Ok(None),
            Self::Budgeted(ingress) => Ok(Some(ingress.reserve_decode(bytes).await?)),
        }
    }

    pub(crate) async fn submit(
        &self,
        incoming: IncomingPacket,
        permit: Option<IngressPermit>,
    ) -> Result<(), IngressAdmissionError> {
        match self {
            Self::Legacy(tx) => tx
                .send(incoming)
                .await
                .map_err(|_| IngressAdmissionError::Closed),
            Self::Budgeted(ingress) => {
                ingress
                    .submit(incoming, permit.expect("budgeted reader reservation"))
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn quota_is_atomic_and_released_after_move_cancel_and_shrink() {
        let budget = Arc::new(IngressBudget::default());
        let scope = Scope {
            session: Some("session".into()),
            peer: Some("peer".into()),
            subscriber: None,
        };
        let mut held = budget
            .acquire(scope.clone(), SESSION_LIMIT, true)
            .await
            .unwrap();
        assert!(matches!(
            budget.acquire(scope.clone(), 1, false).await,
            Err(IngressAdmissionError::Overloaded)
        ));
        let wait = budget.acquire(scope.clone(), 2, true);
        tokio::pin!(wait);
        assert!(futures::poll!(&mut wait).is_pending());
        held.shrink(SESSION_LIMIT - 2);
        let permit = wait.await.unwrap();
        drop(held);
        assert_eq!(budget.snapshot().ingress_bytes, 2);
        drop(permit);
        let usage = budget.usage.lock().unwrap();
        assert_eq!(usage.ingress, 0);
        assert!(usage.sessions.is_empty() && usage.peers.is_empty());
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use crate::event_core::prelude::{CoreEvent, TransportEvent};
    use crate::node::{NodeBuilder, NodeOptions};
    use crate::protocol::control::NetworkControlPayload;
    use crate::transport::tcp::TcpTransport;

    #[test]
    fn native_preauth_and_verified_control_have_independent_bounded_capacity() {
        let budget = Arc::new(IngressBudget::default());
        let credit = budget.native(NATIVE_LIMIT).unwrap();
        let data = budget.wire(DATA_LIMIT).unwrap();
        let pre_auth = budget.pre_auth(PRE_AUTH_LIMIT).unwrap();
        assert!(budget.native(1).is_none());
        assert!(budget.wire(1).is_none());
        assert!(budget.pre_auth(1).is_none());
        let verified = budget.verified_control("a", CONTROL_PEER_LIMIT).unwrap();
        assert!(budget.verified_control("a", 1).is_none());
        let other = budget.verified_control("b", 128).unwrap();
        drop((verified, other, credit, data, pre_auth));
        let usage = budget.snapshot();
        assert_eq!(
            usage.ingress_bytes
                + usage.native_credit_bytes
                + usage.pre_auth_bytes
                + usage.control_bytes,
            0
        );
    }

    #[tokio::test]
    async fn udp_listener_scratch_lifetime_is_in_the_shared_ledger() {
        let mut options = NodeOptions::empty().with_listen("udp", "127.0.0.1:0".parse().unwrap());
        options.enable_topology_maintenance = false;
        options.lan_discovery.enabled = false;
        let mut node = NodeBuilder::new()
            .add_transport(Arc::new(crate::transport::udp::UdpTransport::new()))
            .build(options)
            .unwrap();
        let mut events = node.core_bus().subscribe_events();
        node.start().await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if matches!(
                    events.recv().await.unwrap(),
                    CoreEvent::Transport(TransportEvent::Ready(_))
                ) {
                    break;
                }
            }
        })
        .await
        .unwrap();
        let router = node.router().unwrap();
        assert_eq!(router.ingress_memory().ingress_bytes, 65_507 + 256);
        node.stop().await.unwrap();
        assert_eq!(router.ingress_memory().ingress_bytes, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mixed_reliable_burst_reports_native_ingress_refusal_and_closes_link() {
        let options = || {
            let mut opts = NodeOptions::empty()
                .allow_unsigned_packets(false)
                .with_logger_options(crate::logger::LoggerOptions::new().file_enabled(false));
            opts.enable_topology_maintenance = false;
            opts.lan_discovery.enabled = false;
            opts
        };
        let mut rx = NodeBuilder::new()
            .add_transport(Arc::new(TcpTransport::new()))
            .build(options().with_listen("tcp", "127.0.0.1:0".parse().unwrap()))
            .unwrap();
        let mut events = rx.core_bus().subscribe_events();
        rx.start().await.unwrap();
        let addr = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let CoreEvent::Transport(TransportEvent::Ready(ready)) =
                    events.recv().await.unwrap()
                {
                    break ready.listen_addr.unwrap();
                }
            }
        })
        .await
        .unwrap();
        let mut tx = NodeBuilder::new()
            .add_transport(Arc::new(TcpTransport::new_dial()))
            .build(options())
            .unwrap();
        tx.start().await.unwrap();
        let sid = tx.connect("tcp", addr).await.unwrap();
        let receiver = rx.router().unwrap();
        let origin = tx.peer_id();
        let target = rx.peer_id();
        tokio::time::timeout(Duration::from_secs(3), async {
            while !receiver
                .connected_peers()
                .iter()
                .any(|peer| peer.as_str() == origin)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        // Simulate outstanding legitimate allocations without allocating 256 MiB.
        let held = loop {
            let free = DATA_LIMIT - receiver.ingress_memory().ingress_bytes;
            if let Some(held) = receiver.ingress_budget().wire(free) {
                break held;
            }
        };
        let sender = tx.router().unwrap();
        let frame = |protocol_id, payload| crate::Packet {
            signature: None,
            data: payload,
            nodes: vec![],
            sender: origin.into(),
            receiver: target.into(),
            max_hops: 1,
            request_id: None,
            protocol_id,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };
        let file = sender.send_to_session(
            sid.clone(),
            frame(
                Some(crate::storage::block_transfer::BLOCK_PROTOCOL_ID),
                vec![0x42; 256 * 1024],
            ),
        );
        let chat = sender.send_to_session(sid.clone(), frame(Some(0x4c46), b"message".to_vec()));
        let topology = sender.send_to_session(
            sid.clone(),
            frame(
                None,
                NetworkControlPayload::RequestAdjacency {}.encode().unwrap(),
            ),
        );
        let (file, chat, topology) = tokio::join!(file, chat, topology);
        assert!(
            file.is_ok() && chat.is_ok() && topology.is_ok(),
            "writer offers initially succeed"
        );
        tokio::time::timeout(Duration::from_secs(6), async {
            while receiver.ingress_memory().reliable_refused == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            loop {
                if sender
                    .send_to_session(sid.clone(), frame(Some(0x4c46), b"after refusal".to_vec()))
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the reliable ingress failure must become observable");
        drop(held);
        tx.stop().await.unwrap();
        rx.stop().await.unwrap();
        assert_eq!(receiver.ingress_memory().ingress_bytes, 0);
    }
}
