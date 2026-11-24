use std::time::Duration;

use lp2ln_core_v2::packet::Packet;
use lp2ln_core_v2::transport::udp::UdpTransport;
use lp2ln_core_v2::transport::{Transport, TransportContext};
use tokio::sync::mpsc;

fn packet(id: u64) -> Packet {
    Packet {
        signature: None,
        data: vec![42],
        nodes: Vec::new(),
        sender: format!("sender-{id}"),
        receiver: "receiver".into(),
        max_hops: 1,
        request_id: Some(id),
        protocol_id: None,
        chunk_stream_id: None,
        chunk_index: None,
        total_chunks: None,
    }
}

#[tokio::test]
async fn listener_delivers_first_datagram_and_keeps_peers_separate() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = UdpTransport::new_listener("127.0.0.1:0".parse().unwrap());
        let dialer = UdpTransport::new_dial();
        let (sessions_tx, mut sessions_rx) = mpsc::channel(8);
        let (packets_tx, mut packets_rx) = mpsc::channel(8);
        let bound = listener
            .start(TransportContext {
                incoming_sessions_tx: sessions_tx,
                incoming_packets_tx: packets_tx.clone(),
                listen_addr: None,
                event_tx: None,
                keypair: None,
                catalog: None,
            })
            .await
            .unwrap()
            .unwrap();

        let a = dialer.dial(bound).await.unwrap();
        let b = dialer.dial(bound).await.unwrap();
        a.send(packet(1)).await.unwrap();
        let inbound_a = sessions_rx.recv().await.unwrap();
        inbound_a.clone().spawn_reader(packets_tx.clone());
        let first = packets_rx.recv().await.unwrap();
        assert_eq!(first.packet.request_id, Some(1));
        assert_eq!(first.session_id, inbound_a.id());

        b.send(packet(2)).await.unwrap();
        let inbound_b = sessions_rx.recv().await.unwrap();
        inbound_b.clone().spawn_reader(packets_tx.clone());
        let second = packets_rx.recv().await.unwrap();
        assert_eq!(second.packet.request_id, Some(2));
        assert_eq!(second.session_id, inbound_b.id());
        assert_ne!(inbound_a.id(), inbound_b.id());

        for seq in 3..23 {
            let (outbound, inbound) = if seq % 2 == 0 {
                (&b, &inbound_b)
            } else {
                (&a, &inbound_a)
            };
            outbound.send(packet(seq)).await.unwrap();
            let received = packets_rx.recv().await.unwrap();
            assert_eq!(received.packet.request_id, Some(seq));
            assert_eq!(received.session_id, inbound.id());
        }

        inbound_a.close().await.unwrap();
        inbound_a.join_tasks().await;
        a.send(packet(23)).await.unwrap();
        let reconnected = sessions_rx.recv().await.unwrap();
        assert_ne!(reconnected.id(), inbound_a.id());
        reconnected.clone().spawn_reader(packets_tx);
        assert_eq!(packets_rx.recv().await.unwrap().packet.request_id, Some(23));

        for session in [a, b, inbound_b, reconnected] {
            session.close().await.unwrap();
            session.join_tasks().await;
        }
        listener.stop().await.unwrap();
    })
    .await
    .expect("UDP listener must deliver the first datagram and demultiplex both peers");
}

#[tokio::test]
async fn dedicated_socket_filters_unrelated_source_and_malformed_datagrams() {
    use lp2ln_core_v2::sessions::{LinkKind, Session};
    use lp2ln_core_v2::transport::obfuscation::Obfuscator;
    use lp2ln_core_v2::transport::udp::UdpSession;
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    tokio::time::timeout(Duration::from_secs(3), async {
        let expected = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let session = UdpSession::new_from_socket(
            socket,
            expected.local_addr().unwrap(),
            None,
            LinkKind::DirectUdp,
            Arc::new(Obfuscator::plain()),
        )
        .unwrap();
        let (tx, mut rx) = mpsc::channel(8);
        session.clone().spawn_reader(tx);
        other
            .send_to(&postcard::to_allocvec(&packet(1)).unwrap(), addr)
            .await
            .unwrap();
        expected.send_to(&[0xff], addr).await.unwrap();
        expected
            .send_to(&postcard::to_allocvec(&packet(2)).unwrap(), addr)
            .await
            .unwrap();
        assert_eq!(rx.recv().await.unwrap().packet.request_id, Some(2));
        session.close().await.unwrap();
        session.join_tasks().await;
    })
    .await
    .unwrap();
}
