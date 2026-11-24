use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lp2ln_core_v2::crypto::NodeKeypair;
use lp2ln_core_v2::event_core::prelude::{CoreEvent, TransportEvent};
use lp2ln_core_v2::flow::{Flow, FlowError, FlowSender};
use lp2ln_core_v2::logger::LoggerOptions;
use lp2ln_core_v2::node::{NodeBuilder, NodeOptions, NodeRuntime};
use lp2ln_core_v2::transport::quic::{QuicTransport, QuicTransportOptions};
use lp2ln_core_v2::{Packet, PeerId};

const PROTOCOL: u16 = 0xff81;
const MAX_WAIT: Duration = Duration::from_secs(12);

fn options() -> NodeOptions {
    let mut opts = NodeOptions::empty()
        .allow_unsigned_packets(false)
        .with_logger_options(
            LoggerOptions::new()
                .file_enabled(false)
                .show_debug(false)
                .show_info(false),
        );
    opts.enable_topology_maintenance = false;
    opts.lan_discovery.enabled = false;
    opts.experimental.content = false;
    opts.experimental.dht = false;
    opts
}

async fn listener(enable: bool) -> (NodeRuntime, SocketAddr) {
    let config = QuicTransportOptions {
        enable_realtime_flows: enable,
        ..Default::default()
    };
    let mut node = NodeBuilder::new()
        .add_transport(Arc::new(QuicTransport::new_listener(None, config)))
        .build(options().with_listen("quic", "127.0.0.1:0".parse().unwrap()))
        .unwrap();
    let mut events = node.core_bus().subscribe_events();
    node.start().await.unwrap();
    let bound = tokio::time::timeout(MAX_WAIT, async {
        loop {
            if let CoreEvent::Transport(TransportEvent::Ready(ready)) = events.recv().await.unwrap()
                && let Some(bound) = ready.listen_addr
            {
                return bound;
            }
        }
    })
    .await
    .unwrap();
    (node, bound)
}

async fn dialer() -> NodeRuntime {
    let config = QuicTransportOptions {
        enable_realtime_flows: true,
        ..Default::default()
    };
    let mut node = NodeBuilder::new()
        .add_transport(Arc::new(QuicTransport::new_dial(config)))
        .build(options())
        .unwrap();
    node.start().await.unwrap();
    node
}

async fn open(a: &NodeRuntime, b: &NodeRuntime, address: SocketAddr) -> (Flow, Flow) {
    b.authorize_realtime_peer(&PeerId::from(a.peer_id()), PROTOCOL)
        .unwrap();
    let peer = PeerId::from(b.peer_id());
    let (a, b) = tokio::time::timeout(MAX_WAIT, async {
        tokio::join!(
            a.open_realtime_flow(&peer, address, PROTOCOL),
            b.accept_realtime_flow()
        )
    })
    .await
    .unwrap();
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a.id(), b.id());
    assert_eq!(a.protocol(), PROTOCOL);
    assert_eq!(a.link().peer, peer);
    assert!(a.link().capabilities.unordered_realtime && b.link().capabilities.ordered_control);
    (a, b)
}

async fn fire(tx: FlowSender, size: usize, n: u16, period: Duration, ttl: Duration) {
    assert!(tx.max_payload() >= size, "MTU holds {}", tx.max_payload());
    let mut timer = tokio::time::interval(period);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    for seq in 0..n {
        timer.tick().await;
        let mut data = vec![0x42; size];
        data[..2].copy_from_slice(&seq.to_be_bytes());
        tx.try_send(&data, Instant::now() + ttl).unwrap();
    }
}

async fn observe(rx: &mut Flow, size: usize, n: u16) -> usize {
    let mut seen = std::collections::BTreeSet::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while seen.len() < usize::from(n) {
            let item = rx.recv().await.unwrap();
            assert_eq!(item.len(), size);
            assert!(item[2..].iter().all(|&b| b == 0x42));
            let seq = u16::from_be_bytes(item[..2].try_into().unwrap());
            assert!(seq < n && seen.insert(seq));
        }
    })
    .await
    .ok();
    seen.len()
}

async fn duplex(
    a: &mut Flow,
    b: &mut Flow,
    size: usize,
    frames: u16,
    period: Duration,
    minimum: usize,
) {
    let a_tx = a.sender();
    let b_tx = b.sender();
    let ttl = Duration::from_millis(650);
    let (_, _, a_count, b_count) = tokio::join!(
        fire(a_tx, size, frames, period, ttl),
        fire(b_tx, size, frames, period, ttl),
        observe(a, size, frames),
        observe(b, size, frames),
    );
    eprintln!(
        "size={size} period_us={} min={minimum} observed={a_count}/{b_count}",
        period.as_micros()
    );
    assert!(a_count >= minimum && b_count >= minimum);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn bidirectional_flow_50_pps_bulk_and_rotation() {
    let (receiver, addr) = listener(true).await;
    let sender = dialer().await;
    let (mut a, mut b) = open(&sender, &receiver, addr).await;

    let legacy = sender.connect("quic", addr).await.unwrap();
    let source = sender.router().unwrap();
    let target_router = receiver.router().unwrap();
    let mut observed_bulk = target_router.subscribe_authenticated();
    let bulk = async {
        for id in 1..=240 {
            let packet = Packet {
                signature: None,
                data: vec![0x61; 64 * 1024],
                nodes: vec![],
                sender: sender.peer_id().into(),
                receiver: receiver.peer_id().into(),
                max_hops: 1,
                request_id: Some(id),
                chunk_stream_id: None,
                chunk_index: None,
                total_chunks: None,
                protocol_id: Some(lp2ln_core_v2::storage::block_transfer::BLOCK_PROTOCOL_ID),
            };
            source
                .send_to_session(legacy.clone(), packet)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(4)).await;
        }
    };
    let bulk_receive = async {
        let mut ids = std::collections::BTreeSet::new();
        tokio::time::timeout(MAX_WAIT, async {
            while ids.len() < 240 {
                let item = observed_bulk.recv().await.unwrap();
                if item.packet.protocol_id
                    == Some(lp2ln_core_v2::storage::block_transfer::BLOCK_PROTOCOL_ID)
                {
                    assert_eq!(item.packet.data.len(), 64 * 1024);
                    assert!(ids.insert(item.packet.request_id.unwrap()));
                }
            }
        })
        .await
        .unwrap();
    };
    tokio::join!(
        bulk,
        bulk_receive,
        duplex(&mut a, &mut b, 60, 50, Duration::from_millis(20), 50)
    );
    for size in [120, 300, 1000] {
        duplex(&mut a, &mut b, size, 50, Duration::from_millis(20), 50).await;
    }
    let id = a.id();
    a.rotate_keys().await.unwrap();
    assert_eq!(a.id(), id);
    duplex(&mut a, &mut b, 1000, 400, Duration::from_millis(2), 395).await;
    eprintln!("counts_a={:?} counts_b={:?}", a.metrics(), b.metrics());
    assert_eq!(a.metrics().invalid + b.metrics().invalid, 0);
    assert_eq!(a.metrics().replay + b.metrics().replay, 0);
    sender.stop().await.unwrap();
    assert!(matches!(a.recv().await, Err(FlowError::Closed)));
    receiver.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deadlines_overload_and_shutdown_have_observable_outcomes() {
    let (receiver, addr) = listener(true).await;
    let sender = dialer().await;
    let (mut a, mut b) = open(&sender, &receiver, addr).await;
    assert_eq!(
        a.sender().try_send(b"stale", Instant::now()),
        Err(FlowError::Expired)
    );
    assert_eq!(
        a.sender().try_send(
            &vec![0; a.sender().max_payload() + 1],
            Instant::now() + Duration::from_secs(1)
        ),
        Err(FlowError::TooLarge)
    );
    // Keep the receiver idle long enough to shed a full burst after expiry.
    let tx = a.sender();
    for _ in 0..20 {
        for _ in 0..20 {
            let _ = tx.try_send(&[1; 300], Instant::now() + Duration::from_millis(350));
        }
        tokio::time::sleep(Duration::from_millis(4)).await;
    }
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert!(b.metrics().overloaded > 0);
    assert!(b.metrics().expired > 0);
    let receiver_budget = receiver.router().unwrap();
    assert_eq!(receiver_budget.ingress_memory().ingress_bytes, 0);
    let deadline = Instant::now() + Duration::from_secs(1);
    tx.try_send(b"still live", deadline).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), b.recv())
            .await
            .unwrap()
            .unwrap(),
        b"still live".as_slice()
    );
    a.close();
    assert_eq!(tx.try_send(b"closed", deadline), Err(FlowError::Closed));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), b.recv())
            .await
            .unwrap(),
        Err(FlowError::Closed)
    ));
    sender.stop().await.unwrap();
    receiver.stop().await.unwrap();
    assert_eq!(receiver_budget.ingress_memory().native_credit_bytes, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authorization_expected_peer_and_downgrade_fail_closed() {
    let (receiver, addr) = listener(true).await;
    let sender = dialer().await;
    let expected = PeerId::from(receiver.peer_id());
    let unrelated = PeerId::from(NodeKeypair::generate().peer_id());
    assert!(
        sender
            .open_realtime_flow(&expected, addr, PROTOCOL)
            .await
            .is_err()
    );
    receiver
        .authorize_realtime_peer(&PeerId::from(sender.peer_id()), PROTOCOL)
        .unwrap();
    assert!(
        sender
            .open_realtime_flow(&unrelated, addr, PROTOCOL)
            .await
            .is_err()
    );
    assert!(
        sender
            .open_realtime_flow(&expected, addr, PROTOCOL + 1)
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receiver.accept_realtime_flow())
            .await
            .is_err()
    );
    let (legacy, legacy_addr) = listener(false).await;
    assert!(
        sender
            .open_realtime_flow(&PeerId::from(legacy.peer_id()), legacy_addr, PROTOCOL)
            .await
            .is_err()
    );
    assert!(sender.connect("quic", legacy_addr).await.is_ok());
    let (a, b) = open(&sender, &receiver, addr).await;
    drop((a, b));
    sender.stop().await.unwrap();
    receiver.stop().await.unwrap();
    legacy.stop().await.unwrap();
}

struct Shaper {
    addr: SocketAddr,
    active: Arc<std::sync::atomic::AtomicBool>,
    dropped: Arc<std::sync::atomic::AtomicU64>,
    reordered: Arc<std::sync::atomic::AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Shaper {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn shaper(server: SocketAddr, bps_per_direction: u64) -> Shaper {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use tokio::net::UdpSocket;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let active = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicU64::new(0));
    let reordered = Arc::new(AtomicU64::new(0));
    let task = tokio::spawn({
        let (active, dropped, reordered) = (active.clone(), dropped.clone(), reordered.clone());
        async move {
            let mut source = None;
            let mut pending = Vec::<(Instant, SocketAddr, Vec<u8>, u64)>::new();
            let mut timer = tokio::time::interval(Duration::from_millis(1));
            let mut buffer = vec![0; 65536];
            let mut number = 0_u64;
            let mut highest = 0;
            let mut available = [Instant::now(); 2];
            loop {
                tokio::select! {
                    packet = socket.recv_from(&mut buffer) => {
                        let (n, from) = packet.unwrap();
                        let target = if from == server {
                            let Some(client) = source else { continue; };
                            client
                        } else {
                            source = Some(from);
                            server
                        };
                        if !active.load(Ordering::Relaxed) {
                            socket.send_to(&buffer[..n], target).await.unwrap();
                            continue;
                        }
                        number += 1;
                        if number % 13 == 0 || pending.len() >= 128 {
                            dropped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let delay = Duration::from_millis(5 + (number % 5) * 4);
                        let link = usize::from(from == server);
                        let start = Instant::now().max(available[link]);
                        if bps_per_direction > 0 {
                            available[link] = start + Duration::from_micros((n as u64 * 8_000_000).div_ceil(bps_per_direction));
                        }
                        pending.push((available[link].max(Instant::now()) + delay, target, buffer[..n].to_vec(), number));
                    }
                    _ = timer.tick() => {
                        let mut i = 0;
                        while i < pending.len() {
                            if pending[i].0 > Instant::now() { i += 1; continue; }
                            let (_, to, bytes, seq) = pending.swap_remove(i);
                            if seq < highest { reordered.fetch_add(1, Ordering::Relaxed); }
                            highest = highest.max(seq);
                            socket.send_to(&bytes, to).await.unwrap();
                        }
                    }
                }
            }
        }
    });
    Shaper {
        addr,
        active,
        dropped,
        reordered,
        task,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn real_quic_duplex_with_transport_loss_jitter_and_reordering() {
    use std::sync::atomic::Ordering;
    let (receiver, addr) = listener(true).await;
    let sender = dialer().await;
    let network = shaper(addr, 500_000).await;
    let (mut a, mut b) = open(&sender, &receiver, network.addr).await;
    network.active.store(true, Ordering::Relaxed);
    duplex(&mut a, &mut b, 300, 75, Duration::from_millis(20), 54).await;
    eprintln!(
        "shaper_dropped={} shaper_reordered={}",
        network.dropped.load(Ordering::Relaxed),
        network.reordered.load(Ordering::Relaxed)
    );
    assert!(network.dropped.load(Ordering::Relaxed) > 0);
    assert!(network.reordered.load(Ordering::Relaxed) > 0);
    assert_eq!(a.metrics().invalid + b.metrics().invalid, 0);
    assert_eq!(a.metrics().replay + b.metrics().replay, 0);
    sender.stop().await.unwrap();
    receiver.stop().await.unwrap();
}

/// LP2LN_SOAK_SECONDS defaults to a twenty minute duplex run. One clock for
/// both endpoints permits latency measurements without cross-device clock bias.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "long-running M1 endurance test"]
async fn simultaneous_flow_endurance() {
    let seconds: u64 = std::env::var("LP2LN_SOAK_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1200);
    assert!((4..=1800).contains(&seconds));
    let (listener, addr) = listener(true).await;
    let sender = dialer().await;
    let audio = open(&sender, &listener, addr).await;
    let fast = open(&sender, &listener, addr).await;
    let start = Instant::now();
    let resources = tokio::spawn(async move {
        while start.elapsed().as_secs() < seconds {
            if let (Ok(status), Ok(stat)) = (
                std::fs::read_to_string("/proc/self/status"),
                std::fs::read_to_string("/proc/self/stat"),
            ) {
                let rss = status
                    .lines()
                    .find(|l| l.starts_with("VmRSS:"))
                    .unwrap_or("");
                let fields: Vec<_> = stat
                    .rsplit_once(") ")
                    .unwrap()
                    .1
                    .split_whitespace()
                    .collect();
                eprintln!(
                    "resource elapsed_s={} {rss} user_ticks={} sys_ticks={}",
                    start.elapsed().as_secs(),
                    fields[11],
                    fields[12]
                );
            }
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    });
    async fn endpoint(mut rx: Flow, start: Instant, seconds: u64, pps: u64, rotate: bool) {
        let tx = rx.sender();
        let send = async {
            let mut interval = tokio::time::interval(Duration::from_micros(1_000_000 / pps));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut offers = 0u64;
            while start.elapsed().as_secs() < seconds {
                interval.tick().await;
                let mut data = [0u8; 120];
                data[..8].copy_from_slice(&(start.elapsed().as_micros() as u64).to_be_bytes());
                data[8..16].copy_from_slice(&offers.to_be_bytes());
                let _ = tx.try_send(&data, Instant::now() + Duration::from_millis(180));
                offers += 1;
            }
            offers
        };
        let receive = async {
            let mut latency = [0u64; 2001];
            let mut received = 0;
            let mut jitter = 0.;
            let mut previous = None::<u64>;
            let mut rotation = 3;
            while start.elapsed() < Duration::from_secs(seconds) + Duration::from_millis(250) {
                if rotate && start.elapsed().as_secs() >= rotation {
                    rx.rotate_keys().await.unwrap();
                    rotation += 60;
                }
                if let Ok(result) = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await
                {
                    let data = result.unwrap();
                    let sent = u64::from_be_bytes(data[..8].try_into().unwrap());
                    let age = start.elapsed().as_micros() as u64 - sent;
                    if let Some(old) = previous {
                        jitter += (age.abs_diff(old) as f64 - jitter) / 16.;
                    }
                    previous = Some(age);
                    latency[(age / 100).min(2000) as usize] += 1;
                    received += 1;
                }
            }
            let quantile = |p| {
                let mut cumulative = 0;
                latency
                    .iter()
                    .position(|&n| {
                        cumulative += n;
                        cumulative * 100 >= received * p
                    })
                    .unwrap()
                    * 100
                    + 100
            };
            eprintln!(
                "pps={pps} initiator={rotate} seconds={seconds} received={received} payload_Bps={} latency_us_upper={}/{}/{} jitter_us={jitter:.1} metrics={:?}",
                received * 120 / seconds,
                quantile(50),
                quantile(95),
                quantile(99),
                rx.metrics()
            );
            assert!(received > seconds * pps * 9 / 10);
            assert_eq!(rx.metrics().invalid + rx.metrics().replay, 0);
        };
        let (offered, _) = tokio::join!(send, receive);
        eprintln!("pps={pps} initiator={rotate} offered={offered}");
        // Keep peer alive until both terminal observation windows have elapsed.
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    tokio::join!(
        endpoint(audio.0, start, seconds, 50, true),
        endpoint(audio.1, start, seconds, 50, false),
        endpoint(fast.0, start, seconds, 500, true),
        endpoint(fast.1, start, seconds, 500, false)
    );
    resources.abort();
    sender.stop().await.unwrap();
    listener.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn control_exchange_cancellation_and_revocation() {
    let (listener, addr) = listener(true).await;
    let client = dialer().await;
    let (x, y) = open(&client, &listener, addr).await;
    let (a, b) = (x.control(), y.control());
    assert!(a.exchange(&[0; 513]).await.is_err());
    let (left, right) = tokio::join!(a.exchange(b"left"), b.exchange(b"right"));
    assert_eq!(left.unwrap(), b"right");
    assert_eq!(right.unwrap(), b"left");
    listener
        .revoke_realtime_peer(&PeerId::from(client.peer_id()), PROTOCOL)
        .unwrap();
    assert!(
        client
            .open_realtime_flow(&PeerId::from(listener.peer_id()), addr, PROTOCOL)
            .await
            .is_err()
    );
    let task = tokio::spawn(async move { a.exchange(b"pending").await });
    tokio::task::yield_now().await;
    drop(y);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    drop(x);
    let router = listener.router().unwrap();
    client.stop().await.unwrap();
    listener.stop().await.unwrap();
    assert_eq!(router.ingress_memory().native_credit_bytes, 0);
}
