use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::ecdh::diffie_hellman;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{EncodedPoint, PublicKey};
use quinn::{AsyncUdpSocket, UdpPoller};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum QuicObfsMode {
    #[default]
    Plain,
    QuicInitialObfs,
    /// Derive XOR key from ECDH(our_sk, peer_pk) when peer pubkey is known; plain otherwise.
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuicObfsConfig {
    #[serde(default)]
    pub mode: QuicObfsMode,
    #[serde(default)]
    pub password: Option<String>,
}

impl Default for QuicObfsConfig {
    fn default() -> Self {
        Self {
            mode: QuicObfsMode::Plain,
            password: None,
        }
    }
}

impl QuicObfsConfig {
    pub fn is_active(&self) -> bool {
        match self.mode {
            QuicObfsMode::QuicInitialObfs => self.password.is_some(),
            QuicObfsMode::Auto => true,
            QuicObfsMode::Plain => false,
        }
    }

    /// Returns the obfs mode string to announce in HandshakeFeatures.
    pub fn hello_obfs_mode(&self) -> Option<String> {
        match self.mode {
            QuicObfsMode::QuicInitialObfs if self.password.is_some() => Some("xor_v1".into()),
            QuicObfsMode::Auto => Some("xor_v1".into()),
            _ => None,
        }
    }
}

/// Derives a 32-byte XOR key from a password.
/// Using a domain-separated hash so the same password can't be repurposed across protocols.
pub fn derive_obfs_key(password: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"lp2ln-quic-obfs-v1:");
    h.update(password.as_bytes());
    h.finalize().into()
}

fn xor_datagram(buf: &mut [u8], key: &[u8; 32]) {
    for (b, k) in buf.iter_mut().zip(key.iter().cycle()) {
        *b ^= k;
    }
}

/// Derives a 32-byte XOR key from ECDH shared secret between our sk and their peer_id (compressed pubkey hex).
/// Same domain separator as `derive_obfs_key` so the wire format is uniform.
pub fn derive_obfs_key_from_ecdh(our_sk: &SigningKey, their_peer_id_hex: &str) -> Result<[u8; 32]> {
    let peer_bytes = hex::decode(their_peer_id_hex)
        .map_err(|e| anyhow::anyhow!("Invalid peer_id hex for obfs: {}", e))?;
    let point = EncodedPoint::from_bytes(&peer_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid encoded point in peer_id"))?;
    let public = PublicKey::from_encoded_point(&point)
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("Invalid public key point in peer_id"))?;
    let shared = diffie_hellman(our_sk.as_nonzero_scalar(), public.as_affine());
    let mut h = Sha256::new();
    h.update(b"lp2ln-quic-obfs-v1:");
    h.update(shared.raw_secret_bytes().as_slice());
    Ok(h.finalize().into())
}

/// Wraps a quinn UDP socket and XOR-obfuscates every datagram.
/// The same key is applied symmetrically on send and receive.
/// Both endpoints must share the same password in `quic.obfs.password`.
///
/// ponytail: GSO/GRO disabled (max_segments=1) – each datagram must be keyed from offset 0
pub struct XorObfsSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    key: [u8; 32],
}

impl XorObfsSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, password: &str) -> Self {
        Self {
            inner,
            key: derive_obfs_key(password),
        }
    }

    pub fn new_with_key(inner: Arc<dyn AsyncUdpSocket>, key: [u8; 32]) -> Self {
        Self { inner, key }
    }
}

impl fmt::Debug for XorObfsSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XorObfsSocket")
            .field("inner", &self.inner)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl AsyncUdpSocket for XorObfsSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        let mut buf = transmit.contents.to_vec();
        xor_datagram(&mut buf, &self.key);
        self.inner.try_send(&quinn::udp::Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &buf,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let n = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(n)) => n,
            other => return other,
        };
        for (buf, m) in bufs[..n].iter_mut().zip(meta[..n].iter()) {
            xor_datagram(&mut buf[..m.len], &self.key);
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_obfs_key_symmetric() {
        use crate::crypto::NodeKeypair;
        let a = NodeKeypair::generate();
        let b = NodeKeypair::generate();
        let key_ab = derive_obfs_key_from_ecdh(a.signing_key(), b.peer_id()).expect("ab");
        let key_ba = derive_obfs_key_from_ecdh(b.signing_key(), a.peer_id()).expect("ba");
        assert_eq!(key_ab, key_ba, "ECDH obfs key must be symmetric");
        // Must differ from password-derived key with same input to avoid cross-protocol reuse
        let key_pw = derive_obfs_key(b.peer_id());
        assert_ne!(key_ab, key_pw);
    }

    #[test]
    fn xor_roundtrip() {
        let key = derive_obfs_key("test-password");
        let original = b"hello-quic-initial-packet".to_vec();
        let mut buf = original.clone();
        xor_datagram(&mut buf, &key);
        // must differ from original
        assert_ne!(buf, original);
        // double-XOR restores original
        xor_datagram(&mut buf, &key);
        assert_eq!(buf, original);
    }

    #[test]
    fn xor_deterministic_on_fixed_seed() {
        // Fixed-seed test: same password always produces the same obfuscated bytes.
        // This verifies the wire format is stable and not random.
        let key = derive_obfs_key("lp2ln-test");
        let mut a = vec![0xC0u8, 0x00, 0x00, 0x01]; // QUIC long-header first bytes
        let mut b = vec![0xC0u8, 0x00, 0x00, 0x01];
        xor_datagram(&mut a, &key);
        xor_datagram(&mut b, &key);
        assert_eq!(a, b);
        // and they must differ from the QUIC magic bytes
        assert_ne!(a[0], 0xC0);
    }

    #[test]
    fn obfs_config_is_active() {
        assert!(!QuicObfsConfig::default().is_active());
        assert!(
            !QuicObfsConfig {
                mode: QuicObfsMode::QuicInitialObfs,
                password: None,
            }
            .is_active()
        );
        assert!(
            QuicObfsConfig {
                mode: QuicObfsMode::QuicInitialObfs,
                password: Some("secret".into()),
            }
            .is_active()
        );
    }

    #[tokio::test]
    async fn obfs_two_endpoints_exchange_packet() {
        use crate::packet::Packet;
        use crate::sessions::Session;
        use crate::sessions::session::LinkKind;
        use crate::transport::quic::config::{
            QuicTransportOptions, build_client_config, build_server_config,
        };
        use crate::transport::quic::session::QuicSession;
        use tokio::sync::mpsc;

        let password = "test-obfs-password";
        let mut options = QuicTransportOptions::default();
        options.obfs = QuicObfsConfig {
            mode: QuicObfsMode::QuicInitialObfs,
            password: Some(password.to_string()),
        };

        let server_config = build_server_config(&options).expect("server config");
        let client_config = build_client_config(&options).expect("client config");

        let runtime = quinn::default_runtime().expect("tokio runtime");

        let server_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind server");
        let server_addr = server_std.local_addr().unwrap();
        let server_inner = runtime.wrap_udp_socket(server_std).expect("wrap server");
        let server_obfs = Arc::new(XorObfsSocket::new(server_inner, password));
        let server_ep = Arc::new(
            quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                Some(server_config),
                server_obfs,
                runtime.clone(),
            )
            .expect("server endpoint"),
        );

        let client_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind client");
        let client_inner = runtime.wrap_udp_socket(client_std).expect("wrap client");
        let client_obfs = Arc::new(XorObfsSocket::new(client_inner, password));
        let mut client_ep = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            client_obfs,
            runtime,
        )
        .expect("client endpoint");
        client_ep.set_default_client_config(client_config);
        let client_ep = Arc::new(client_ep);

        let server_task = {
            let server_ep = server_ep.clone();
            tokio::spawn(async move {
                let incoming = server_ep.accept().await.expect("incoming");
                let conn = incoming.await.expect("connection");
                let streams = conn.accept_bi().await.expect("accept_bi");
                (server_ep, conn, streams)
            })
        };

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let conn = client_ep
            .connect(server_addr, "lp2ln.local")
            .expect("connect")
            .await
            .expect("handshake");
        let (csend, crecv) = conn.open_bi().await.expect("open_bi");

        let outbound = QuicSession::new_from_streams(
            client_ep,
            conn,
            csend,
            crecv,
            None,
            LinkKind::DirectQuic,
            None,
            None,
        )
        .expect("outbound session");

        let packet = Packet {
            signature: None,
            data: b"obfs-quic-smoke".to_vec(),
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
        outbound.send(packet.clone()).await.expect("send");

        let (server_ep, server_conn, server_streams) = server_task.await.expect("server task");
        let inbound = QuicSession::new_from_streams(
            server_ep,
            server_conn,
            server_streams.0,
            server_streams.1,
            None,
            LinkKind::DirectQuic,
            None,
            None,
        )
        .expect("inbound session");

        let (tx, mut rx) = mpsc::channel(4);
        inbound.spawn_reader(tx);
        let received = rx.recv().await.expect("packet");
        assert_eq!(received.packet.data, packet.data);
    }
}
