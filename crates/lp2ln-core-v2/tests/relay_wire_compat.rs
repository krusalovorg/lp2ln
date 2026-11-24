use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lp2ln_core_v2::crypto::signature::{SignatureFormat, sign_packet_with_format};
use lp2ln_core_v2::crypto::{NodeKeypair, secure_channel};
use lp2ln_core_v2::event_core::prelude::{CoreEvent, TransportEvent};
use lp2ln_core_v2::node::{NodeBuilder, NodeOptions, NodeRuntime};
use lp2ln_core_v2::packet::Packet;
use lp2ln_core_v2::sessions::IncomingPacket;
use lp2ln_core_v2::transport::tcp::TcpTransport;
use lp2ln_core_v2::types::PeerId;

async fn node(format: SignatureFormat, key: Option<NodeKeypair>) -> (NodeRuntime, SocketAddr) {
    let mut options = NodeOptions::empty()
        .allow_unsigned_packets(false)
        .with_listen("tcp", "127.0.0.1:0".parse().unwrap());
    options.enable_topology_maintenance = false;
    options.lan_discovery.enabled = false;
    options.signature_format = format;
    if let Some(key) = key {
        options = options.keypair(key);
    }
    let mut node = NodeBuilder::new()
        .add_transport(Arc::new(TcpTransport::new()))
        .build(options)
        .unwrap();
    let mut events = node.core_bus().subscribe_events();
    node.start().await.unwrap();
    let address = loop {
        if let CoreEvent::Transport(TransportEvent::Ready(ready)) = events.recv().await.unwrap() {
            if let Some(address) = ready.listen_addr {
                break address;
            }
        }
    };
    (node, address)
}

async fn connected(node: &NodeRuntime, peer: &str) {
    while !node
        .router()
        .unwrap()
        .connected_peers()
        .iter()
        .any(|id| id.as_str() == peer)
    {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn v3_direct_and_v4_relay_preserve_author_and_request_id() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let (legacy_node, legacy_address) = node(SignatureFormat::V3Hash, None).await;
        let (v3_sender, _) = node(SignatureFormat::V3Hash, None).await;
        let mut direct_delivery = legacy_node.router().unwrap().subscribe_authenticated();
        v3_sender.connect("tcp", legacy_address).await.unwrap();
        connected(&v3_sender, legacy_node.peer_id()).await;
        let direct_rid = v3_sender
            .send(PeerId::from(legacy_node.peer_id()), b"direct-v3".to_vec())
            .await
            .unwrap();
        let direct = loop {
            let frame = direct_delivery.recv().await.unwrap();
            if frame.packet.request_id == Some(direct_rid) && frame.packet.data == b"direct-v3" {
                break frame;
            }
        };
        assert_eq!(direct.packet.sender, v3_sender.peer_id());
        assert!(direct.packet.nodes.is_empty());
        assert!(direct.packet.signature.as_ref().unwrap().starts_with("v3:"));

        let (relay, relay_address) = node(SignatureFormat::V4Hash, None).await;
        let (origin, _) = node(SignatureFormat::V4Hash, None).await;
        let (destination, _) = node(SignatureFormat::V4Hash, None).await;
        origin.connect("tcp", relay_address).await.unwrap();
        destination.connect("tcp", relay_address).await.unwrap();
        connected(&origin, relay.peer_id()).await;
        connected(&relay, destination.peer_id()).await;
        connected(&destination, relay.peer_id()).await;

        let mut delivery = destination.router().unwrap().subscribe_authenticated();
        assert!(
            !origin
                .router()
                .unwrap()
                .connected_peers()
                .contains(&PeerId::from(destination.peer_id()))
        );
        let relay_rid = origin
            .send(
                PeerId::from(destination.peer_id()),
                b"through-relay".to_vec(),
            )
            .await
            .unwrap();
        let frame = loop {
            let frame = delivery.recv().await.unwrap();
            if frame.packet.request_id == Some(relay_rid) && frame.packet.data == b"through-relay" {
                break frame;
            }
        };
        assert_eq!(frame.packet.sender, origin.peer_id());
        assert_eq!(frame.packet.nodes, [relay.peer_id()]);
        assert!(frame.packet.signature.as_ref().unwrap().starts_with("v4:"));
        assert_eq!(frame.from_node.as_deref(), Some(relay.peer_id()));
        for node in [origin, destination, relay, v3_sender, legacy_node] {
            node.stop().await.unwrap();
        }
    })
    .await
    .expect("direct and relayed delivery timed out");
}

#[tokio::test]
async fn forged_relay_frame_cannot_poison_dedup_and_replay_is_not_delivered() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let receiver_key = NodeKeypair::generate();
        let origin = NodeKeypair::generate();
        let (node, _) = node(SignatureFormat::V4Hash, Some(receiver_key.clone())).await;
        let router = node.router().unwrap();
        let mut delivered = router.subscribe_authenticated();
        let mut legacy = router.subscribe();
        let key = secure_channel::derive_shared_key(origin.signing_key(), receiver_key.peer_id())
            .unwrap();
        let make_frame = |sequence| {
            let mut packet = Packet {
                signature: None,
                data: secure_channel::encode_secure_envelope(b"application", key, sequence)
                    .unwrap(),
                nodes: vec!["relay".into()],
                sender: origin.peer_id().to_string(),
                receiver: receiver_key.peer_id().to_string(),
                request_id: Some(sequence),
                protocol_id: Some(42),
                max_hops: 1,
                chunk_stream_id: None,
                chunk_index: None,
                total_chunks: None,
            };
            sign_packet_with_format(&mut packet, origin.signing_key(), SignatureFormat::V4Hash)
                .unwrap();
            IncomingPacket {
                session_id: "relay-session".into(),
                from_node: Some("relay".into()),
                packet,
            }
        };

        let frame = make_frame(1);
        let mut forged = frame.clone();
        let last = forged.packet.data.last_mut().unwrap();
        *last ^= 1;
        let tx = router.incoming_sender();
        tx.send(forged).await.unwrap();
        // Wait for the worker to process the forged frame before submitting the original.
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(router.ingress_metrics().decoded_packets, 1);
        assert_eq!(router.ingress_metrics().authenticated_packets, 0);
        tx.send(frame.clone()).await.unwrap();
        let first = delivered.recv().await.unwrap();
        assert_eq!(first.packet.request_id, Some(1));
        assert!(Arc::ptr_eq(&first, &legacy.recv().await.unwrap()));

        let mut duplicate_on_direct_link = frame;
        duplicate_on_direct_link.packet.nodes.clear();
        duplicate_on_direct_link.from_node = Some(origin.peer_id().to_string());
        for _ in 0..4 {
            tx.send(duplicate_on_direct_link.clone()).await.unwrap();
        }
        tx.send(make_frame(2)).await.unwrap();
        assert_eq!(delivered.recv().await.unwrap().packet.request_id, Some(2));
        node.stop().await.unwrap();
        let ingress = router.ingress_metrics();
        assert_eq!(ingress.decoded_packets, 7);
        assert_eq!(ingress.authenticated_packets, 2);
        assert_eq!(ingress.authenticated_local_packets, 2);
    })
    .await
    .expect("relay auth and replay checks timed out");
}
