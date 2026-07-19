use std::sync::Arc;
use std::time::Duration;

use lp2ln_core_v2::packet::Packet;
use lp2ln_core_v2::sessions::Session;
use lp2ln_core_v2::transport::quic::{QuicTransport, QuicTransportOptions};
use lp2ln_core_v2::transport::{Transport, TransportContext};
use tokio::sync::mpsc;

#[tokio::test]
async fn quic_transport_start_dial_and_exchange_packet() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let options = QuicTransportOptions::default();
    let listener = Arc::new(QuicTransport::new_listener(
        Some("127.0.0.1:0".parse().expect("valid addr")),
        options.clone(),
    ));
    let dialer = Arc::new(QuicTransport::new_dial(options));

    let (incoming_sessions_tx, mut incoming_sessions_rx) = mpsc::channel(8);
    let bound = listener
        .start(TransportContext {
            incoming_sessions_tx,
            incoming_packets_tx: mpsc::channel(8).0,
            listen_addr: None,
            event_tx: None,
            keypair: None,
            catalog: None,
        })
        .await
        .expect("start listener")
        .expect("listener bound");

    tokio::time::sleep(Duration::from_millis(50)).await;

    let outbound = dialer.dial(bound).await.expect("dial");

    let packet = Packet {
        signature: None,
        data: b"quic-smoke".to_vec(),
        nodes: vec![],
        sender: "peer-a".to_string(),
        receiver: "peer-b".to_string(),
        max_hops: 4,
        request_id: None,
        chunk_stream_id: None,
        chunk_index: None,
        total_chunks: None,
        protocol_id: None,
    };
    // Send first: the write triggers the QUIC STREAM frame, which unblocks
    // the listener's accept_bi() and makes the inbound session available.
    outbound.send(packet.clone()).await.expect("send packet");

    let inbound: Arc<dyn Session> =
        tokio::time::timeout(Duration::from_secs(5), incoming_sessions_rx.recv())
            .await
            .expect("incoming session timeout")
            .expect("incoming session channel closed");

    let (tx, mut rx) = mpsc::channel(4);
    inbound.clone().spawn_reader(tx);
    let received = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("recv timeout")
        .expect("packet received");
    assert_eq!(received.packet.data, packet.data);

    outbound.close().await.expect("close outbound");
    inbound.close().await.expect("close inbound");
    listener.stop().await.expect("stop listener");
}
