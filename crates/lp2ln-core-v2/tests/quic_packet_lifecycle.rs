#![cfg(feature = "packet-trace")]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lp2ln_core_v2::event_core::prelude::{CoreEvent, TransportEvent};
use lp2ln_core_v2::logger::LoggerOptions;
use lp2ln_core_v2::node::{NodeBuilder, NodeOptions, NodeRuntime};
use lp2ln_core_v2::packet::Packet;
use lp2ln_core_v2::packet_trace::{LinkEvent, PacketTrace, Stage};
use lp2ln_core_v2::transport::quic::{QuicTransport, QuicTransportOptions};
use tokio::sync::broadcast::error::RecvError;

const DEADLINE: Duration = Duration::from_secs(8);
const STAGES: [Stage; 12] = [
    Stage::WriterAdmitted,
    Stage::StreamWritten,
    Stage::Decoded,
    Stage::RouterReceived,
    Stage::ProcessorAdmitted,
    Stage::Processing,
    Stage::SignatureRejected,
    Stage::ReplayRejected,
    Stage::RelayDuplicate,
    Stage::EnvelopeAccepted,
    Stage::Published,
    Stage::Observed,
];

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

async fn listener(workers: usize) -> (NodeRuntime, SocketAddr) {
    let mut opts = options().with_listen("quic", "127.0.0.1:0".parse().unwrap());
    opts.router_process_concurrency = workers;
    let mut node = NodeBuilder::new()
        .add_transport(Arc::new(QuicTransport::new_listener(
            None,
            QuicTransportOptions::default(),
        )))
        .build(opts)
        .unwrap();
    let mut events = node.core_bus().subscribe_events();
    node.start().await.unwrap();
    let addr = tokio::time::timeout(DEADLINE, async {
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
    (node, addr)
}

fn packet(sender: &str, receiver: &str, id: u64, size: usize, tagged: bool) -> Packet {
    Packet {
        signature: None,
        data: vec![0x42; size],
        nodes: Vec::new(),
        sender: sender.to_owned(),
        receiver: receiver.to_owned(),
        max_hops: 1,
        request_id: Some(id),
        protocol_id: tagged.then_some(0xffe3),
        chunk_stream_id: None,
        chunk_index: None,
        total_chunks: None,
    }
}

async fn run(size: usize, count: usize, writers: usize, workers: usize, background: usize) -> bool {
    let (receiver, addr) = listener(workers).await;
    let mut sender = NodeBuilder::new()
        .add_transport(Arc::new(QuicTransport::new_dial(
            QuicTransportOptions::default(),
        )))
        .build(options())
        .unwrap();
    sender.start().await.unwrap();
    let session = tokio::time::timeout(DEADLINE, sender.connect("quic", addr))
        .await
        .unwrap()
        .unwrap();
    let rx_router = receiver.router().unwrap();
    let tx_router = sender.router().unwrap();
    let mut incoming = rx_router.subscribe_authenticated();
    let origin = sender.peer_id();
    let target = receiver.peer_id();
    let trace = PacketTrace::start(origin.to_owned(), 1, count + background).unwrap();
    let started = Instant::now();

    let send = async {
        let lanes = (0..writers).map(|lane| {
            let tx_router = tx_router.clone();
            let session = session.clone();
            async move {
                for i in (lane..count).step_by(writers) {
                    tx_router
                        .send_to_session(
                            session.clone(),
                            packet(origin, target, 1 + i as u64, size, true),
                        )
                        .await
                        .unwrap();
                }
            }
        });
        let competing = async {
            for i in 0..background {
                // Same QUIC connection. Exercise the legacy reserved lane with
                // small untagged messages and the regular lane with large frames.
                let size = if i % 2 == 0 { 100 } else { 64 * 1024 };
                tx_router
                    .send_to_session(
                        session.clone(),
                        packet(origin, target, (count + i + 1) as u64, size, size > 100),
                    )
                    .await
                    .unwrap();
            }
        };
        tokio::join!(futures::future::join_all(lanes), competing);
    };

    let mut seen = BTreeSet::new();
    let mut lagged = 0;
    let mut background_seen = BTreeSet::new();
    let collect = async {
        while seen.len() < count || background_seen.len() < background {
            match incoming.recv().await {
                Ok(incoming) => {
                    let p = &incoming.packet;
                    if p.sender != origin || p.receiver != target {
                        continue;
                    }
                    match p.request_id {
                        Some(id) if (1..=count as u64).contains(&id) => {
                            assert_eq!(p.data.len(), size);
                            assert!(p.data.iter().all(|&byte| byte == 0x42));
                            assert_eq!(p.protocol_id, Some(0xffe3));
                            trace.observe(p);
                            assert!(seen.insert(id), "duplicate test packet {id}");
                        }
                        Some(id)
                            if ((count + 1) as u64..=(count + background) as u64).contains(&id) =>
                        {
                            let size = if (id - count as u64 - 1) % 2 == 0 {
                                100
                            } else {
                                64 * 1024
                            };
                            assert_eq!(p.data.len(), size);
                            trace.observe(p);
                            assert!(
                                background_seen.insert(id),
                                "duplicate background packet {id}"
                            );
                        }
                        _ => {}
                    }
                }
                Err(RecvError::Lagged(n)) => lagged += n,
                Err(RecvError::Closed) => break,
            }
        }
    };

    let (sent, received) = tokio::join!(
        tokio::time::timeout(DEADLINE, send),
        tokio::time::timeout(DEADLINE, collect)
    );
    let missing: Vec<_> = (1..=(count + background) as u64)
        .filter(|id| !seen.contains(id) && !background_seen.contains(id))
        .collect();
    eprintln!(
        "size={size} writes={writers} workers={workers} background={background} delivered={}/{count} background_delivered={} elapsed_ms={} lagged={} router={:?}",
        seen.len(),
        background_seen.len(),
        started.elapsed().as_millis(),
        lagged,
        rx_router.ingress_metrics()
    );
    for id in missing.iter().take(12) {
        let reached: Vec<_> = STAGES
            .into_iter()
            .filter(|stage| trace.reached(*id, *stage))
            .collect();
        eprintln!(
            "missing {id}: {reached:?}, decoded_behind={:?}",
            trace.decoded_displacement(*id)
        );
    }
    for event in [
        LinkEvent::ReadFrame,
        LinkEvent::DecodeFailed,
        LinkEvent::ReadEnded,
        LinkEvent::WriteFailed,
    ] {
        eprintln!("{event:?}={}", trace.link_events(event));
    }
    sender.stop().await.unwrap();
    receiver.stop().await.unwrap();
    sent.is_ok()
        && received.is_ok()
        && missing.is_empty()
        && background_seen.len() == background
        && lagged == 0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn authenticated_quic_packet_lifecycle_matrix() {
    let mut all_delivered = true;
    for (size, count, writers, workers, background) in [
        (100, 200, 1, 256, 0),
        (1200, 800, 4, 16, 0),
        (64 * 1024, 200, 4, 64, 0),
        (8 * 1024, 600, 4, 256, 700),
    ] {
        all_delivered &= run(size, count, writers, workers, background).await;
    }
    assert!(
        all_delivered,
        "QUIC test packets did not all reach the subscriber"
    );
}

#[tokio::test]
async fn incomplete_stream_releases_predecode_reservation_on_shutdown() {
    use lp2ln_core_v2::transport::quic::build_client_config;
    let (receiver, addr) = listener(2).await;
    let router = receiver.router().unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint
        .set_default_client_config(build_client_config(&QuicTransportOptions::default()).unwrap());
    let connection = endpoint
        .connect(addr, "lp2ln.local")
        .unwrap()
        .await
        .unwrap();
    let (mut send, _recv) = connection.open_bi().await.unwrap();
    send.write_all(&(10u32 * 1024 * 1024).to_be_bytes())
        .await
        .unwrap();
    tokio::time::timeout(DEADLINE, async {
        while router.ingress_memory().ingress_bytes < 20 * 1024 * 1024 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reader must reserve decode bytes before receiving the body");
    receiver.stop().await.unwrap();
    assert_eq!(router.ingress_memory().ingress_bytes, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_quic_recipients_have_independent_writer_gates() {
    let (rx_a, addr_a) = listener(16).await;
    let (rx_b, addr_b) = listener(16).await;
    let mut sender = NodeBuilder::new()
        .add_transport(Arc::new(QuicTransport::new_dial(
            QuicTransportOptions::default(),
        )))
        .build(options())
        .unwrap();
    sender.start().await.unwrap();
    let session_a = sender.connect("quic", addr_a).await.unwrap();
    let session_b = sender.connect("quic", addr_b).await.unwrap();
    let router = sender.router().unwrap();
    let transfer = |rx: Arc<lp2ln_core_v2::router::Router>,
                    target: String,
                    session: lp2ln_core_v2::SessionId,
                    bytes| {
        let sender_id = sender.peer_id().to_owned();
        let router = router.clone();
        async move {
            let mut reader = rx.subscribe_authenticated();
            let send = async {
                for id in 1..=250_u64 {
                    router
                        .send_to_session(
                            session.clone(),
                            packet(&sender_id, &target, id, bytes, true),
                        )
                        .await
                        .unwrap();
                }
            };
            let receive = async {
                let mut ids = BTreeSet::new();
                while ids.len() < 250 {
                    let msg = reader.recv().await.unwrap();
                    if msg.packet.protocol_id == Some(0xffe3) {
                        assert_eq!(msg.packet.data.len(), bytes);
                        assert_eq!(msg.packet.receiver, target);
                        assert!(ids.insert(msg.packet.request_id.unwrap()));
                    }
                }
            };
            tokio::join!(send, receive);
        }
    };
    tokio::time::timeout(DEADLINE, async {
        tokio::join!(
            transfer(
                rx_a.router().unwrap(),
                rx_a.peer_id().to_owned(),
                session_a,
                100
            ),
            transfer(
                rx_b.router().unwrap(),
                rx_b.peer_id().to_owned(),
                session_b,
                64 * 1024
            ),
        );
    })
    .await
    .unwrap();
    sender.stop().await.unwrap();
    rx_a.stop().await.unwrap();
    rx_b.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_packet_on_another_quic_link_cannot_pass_replay_window() {
    use lp2ln_core_v2::crypto::NodeKeypair;
    use lp2ln_core_v2::crypto::secure_channel::{derive_shared_key, encode_secure_envelope};
    use lp2ln_core_v2::crypto::signature::{SignatureFormat, sign_packet_with_format};
    use lp2ln_core_v2::transport::Transport;

    let (receiver, addr) = listener(8).await;
    let router = receiver.router().unwrap();
    let dial = QuicTransport::new_dial(QuicTransportOptions::default());
    let old = dial.dial(addr).await.unwrap();
    let new = dial.dial(addr).await.unwrap();
    let who = NodeKeypair::generate();
    let origin = who.peer_id().to_string();
    let target = receiver.peer_id();
    let key = derive_shared_key(who.signing_key(), target).unwrap();
    let mut reader = router.subscribe_authenticated();
    let frame = |seq: u64| {
        let mut frame = packet(&origin, target, seq, 120, true);
        frame.data = encode_secure_envelope(&frame.data, key, seq).unwrap();
        sign_packet_with_format(&mut frame, who.signing_key(), SignatureFormat::V3Hash).unwrap();
        frame
    };
    new.send(frame(500)).await.unwrap();
    let accepted = tokio::time::timeout(DEADLINE, reader.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.packet.request_id, Some(500));

    // The pending old-link frame arrived after newer traffic advanced the same author window.
    old.send(frame(371)).await.unwrap();
    tokio::time::timeout(DEADLINE, async {
        while router.ingress_metrics().replay_or_late_rejections == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        reader.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    // A distinct unseen sequence within the existing window still accepts reordering.
    old.send(frame(499)).await.unwrap();
    let accepted = tokio::time::timeout(DEADLINE, reader.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.packet.request_id, Some(499));
    old.close().await.unwrap();
    new.close().await.unwrap();
    receiver.stop().await.unwrap();
}
