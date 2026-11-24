use std::sync::Arc;
use std::time::Duration;

use lp2ln_core_v2::packet::Packet;
use lp2ln_core_v2::sessions::{LinkKind, Session};
use lp2ln_core_v2::transport::obfuscation::Obfuscator;
use lp2ln_core_v2::transport::TunnelPunchParams;
use lp2ln_core_v2::transport::udp::{UdpSession, UdpTransport};
use lp2ln_core_v2::transport::{Transport, TransportContext};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

fn packet(data: &str) -> Packet {
    Packet {
        signature: None,
        sender: "transport-test-sender".into(),
        receiver: "transport-test-receiver".into(),
        data: data.as_bytes().to_vec(),
        nodes: Vec::new(),
        max_hops: 8,
        request_id: Some(1),
        protocol_id: Some(0x1234),
        chunk_stream_id: None,
        chunk_index: None,
        total_chunks: None,
    }
}

async fn receive<T>(receiver: &mut mpsc::Receiver<T>) -> T {
    tokio::time::timeout(Duration::from_secs(3), receiver.recv())
        .await
        .expect("receive timeout")
        .expect("channel closed")
}

#[tokio::test]
async fn udp_listener_preserves_first_packet_and_demultiplexes_active_sessions() {
    let (tx, mut sessions) = mpsc::channel(8);
    let (packets_tx, mut packets) = mpsc::channel(8);
    let transport = UdpTransport::new_listener("127.0.0.1:0".parse().unwrap());
    let listen = transport
        .start(TransportContext {
            incoming_sessions_tx: tx,
            incoming_packets_tx: packets_tx.clone(),
            listen_addr: None,
            event_tx: None,
            keypair: None,
            catalog: None,
        })
        .await
        .unwrap()
        .unwrap();

    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    first
        .send_to(&postcard::to_allocvec(&packet("first")).unwrap(), listen)
        .await
        .unwrap();
    let first_session = receive(&mut sessions).await;
    first_session.clone().spawn_reader(packets_tx.clone());
    let first_frame = receive(&mut packets).await;
    assert_eq!(first_frame.packet.data, b"first");
    assert_eq!(first_frame.session_id, first_session.id());

    second
        .send_to(&postcard::to_allocvec(&packet("second")).unwrap(), listen)
        .await
        .unwrap();
    let second_session = receive(&mut sessions).await;
    second_session.clone().spawn_reader(packets_tx.clone());
    let second_frame = receive(&mut packets).await;
    assert_eq!(second_frame.packet.data, b"second");
    assert_eq!(second_frame.session_id, second_session.id());
    assert_ne!(first_frame.session_id, second_frame.session_id);

    first_session.close().await.unwrap();
    first_session.join_tasks().await;
    second
        .send_to(
            &postcard::to_allocvec(&packet("still live")).unwrap(),
            listen,
        )
        .await
        .unwrap();
    let frame = receive(&mut packets).await;
    assert_eq!(frame.packet.data, b"still live");
    assert_eq!(frame.session_id, second_session.id());

    first
        .send_to(&postcard::to_allocvec(&packet("reopened")).unwrap(), listen)
        .await
        .unwrap();
    let replacement = receive(&mut sessions).await;
    assert_ne!(replacement.id(), first_session.id());
    replacement.clone().spawn_reader(packets_tx);
    let frame = receive(&mut packets).await;
    assert_eq!(frame.packet.data, b"reopened");
    assert_eq!(frame.session_id, replacement.id());

    transport.stop().await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), second_session.join_tasks())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), replacement.join_tasks())
        .await
        .unwrap();
}

#[tokio::test]
async fn udp_dedicated_session_ignores_other_endpoints() {
    let local = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let expected = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let session = UdpSession::new_from_socket(
        local.clone(),
        expected.local_addr().unwrap(),
        None,
        LinkKind::DirectUdp,
        Arc::new(Obfuscator::plain()),
    )
    .unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    session.clone().spawn_reader(tx);
    other
        .send_to(
            &postcard::to_allocvec(&packet("other")).unwrap(),
            local.local_addr().unwrap(),
        )
        .await
        .unwrap();
    expected
        .send_to(
            &postcard::to_allocvec(&packet("expected")).unwrap(),
            local.local_addr().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(receive(&mut rx).await.packet.data, b"expected");
    session.close().await.unwrap();
    session.join_tasks().await;
}

#[tokio::test]
async fn udp_punch_uses_both_advertised_listener_ports_and_exchanges_data() {
    let a = UdpTransport::new_listener("127.0.0.1:0".parse().unwrap());
    let b = UdpTransport::new_listener("127.0.0.1:0".parse().unwrap());
    let (a_incoming, mut a_sessions) = mpsc::channel(8);
    let (b_incoming, mut b_sessions) = mpsc::channel(8);
    let (a_tx, mut a_packets) = mpsc::channel(8);
    let (b_tx, mut b_packets) = mpsc::channel(8);
    let a_addr = a
        .start(TransportContext {
            incoming_sessions_tx: a_incoming,
            incoming_packets_tx: a_tx.clone(),
            listen_addr: None,
            event_tx: None,
            keypair: None,
            catalog: None,
        })
        .await
        .unwrap()
        .unwrap();
    let b_addr = b
        .start(TransportContext {
            incoming_sessions_tx: b_incoming,
            incoming_packets_tx: b_tx.clone(),
            listen_addr: None,
            event_tx: None,
            keypair: None,
            catalog: None,
        })
        .await
        .unwrap()
        .unwrap();
    let params = |address: std::net::SocketAddr| TunnelPunchParams {
        target_ip: address.ip().to_string(),
        target_port: address.port(),
        timeout_secs: 2,
    };
    let (local, remote) = tokio::join!(
        a.punch_tunnel(params(b_addr)),
        b.punch_tunnel(params(a_addr))
    );
    let local = local.unwrap();
    let remote = remote.unwrap();
    assert_eq!(local.kind(), LinkKind::TunnelUdp);
    assert_eq!(remote.kind(), LinkKind::TunnelUdp);
    local.clone().spawn_reader(a_tx);
    remote.clone().spawn_reader(b_tx);
    local.send(packet("a to b")).await.unwrap();
    remote.send(packet("b to a")).await.unwrap();
    assert_eq!(receive(&mut b_packets).await.packet.data, b"a to b");
    assert_eq!(receive(&mut a_packets).await.packet.data, b"b to a");
    assert!(matches!(
        a_sessions.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        b_sessions.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    a.stop().await.unwrap();
    b.stop().await.unwrap();
    local.join_tasks().await;
    remote.join_tasks().await;
}
