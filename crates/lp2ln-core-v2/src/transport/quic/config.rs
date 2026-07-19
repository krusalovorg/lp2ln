use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::TransportConfig;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, ServerConfig, VarInt};
use rcgen::{CertificateParams, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};

use super::adaptive::AdaptiveLossConfig;
use super::obfs::QuicObfsConfig;

pub const DEFAULT_QUIC_ALPN: &str = "lp2ln/1";
pub const H3_ALPN: &[u8] = b"h3";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MasqueradeMode {
    #[default]
    Static404,
    // ponytail: reverse_proxy not implemented – add when proxy_url is needed in production
    ReverseProxy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MasqueradeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: MasqueradeMode,
    #[serde(default)]
    pub proxy_url: Option<String>,
}

impl Default for MasqueradeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: MasqueradeMode::Static404,
            proxy_url: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuicTlsConfig {
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    #[serde(default = "default_quic_alpn")]
    pub alpn: Vec<String>,
}

impl Default for QuicTlsConfig {
    fn default() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            alpn: default_quic_alpn(),
        }
    }
}

fn default_quic_alpn() -> Vec<String> {
    vec![DEFAULT_QUIC_ALPN.to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuicTransportOptions {
    #[serde(default = "default_max_idle_timeout_secs")]
    pub max_idle_timeout_secs: u64,
    #[serde(default = "default_max_concurrent_bidi_streams")]
    pub max_concurrent_bidi_streams: u32,
    #[serde(default = "default_initial_mtu")]
    pub initial_mtu: u16,
    #[serde(default)]
    pub tls: QuicTlsConfig,
    #[serde(default)]
    pub masquerade: MasqueradeConfig,
    #[serde(default)]
    pub obfs: QuicObfsConfig,
    #[serde(default)]
    pub adaptive_loss: AdaptiveLossConfig,
}

impl Default for QuicTransportOptions {
    fn default() -> Self {
        Self {
            max_idle_timeout_secs: default_max_idle_timeout_secs(),
            max_concurrent_bidi_streams: default_max_concurrent_bidi_streams(),
            initial_mtu: default_initial_mtu(),
            tls: QuicTlsConfig::default(),
            masquerade: MasqueradeConfig::default(),
            obfs: QuicObfsConfig::default(),
            adaptive_loss: AdaptiveLossConfig::default(),
        }
    }
}

fn default_max_idle_timeout_secs() -> u64 {
    30
}

fn default_max_concurrent_bidi_streams() -> u32 {
    64
}

fn default_initial_mtu() -> u16 {
    1200
}

/// Quinn/rustls needs an explicit process-level CryptoProvider when more than
/// one rustls backend feature is linked. Idempotent: second call is a no-op.
fn ensure_rustls_crypto_provider() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
}

pub fn build_server_config(options: &QuicTransportOptions) -> Result<ServerConfig> {
    ensure_rustls_crypto_provider();
    let (certs, key) = load_or_generate_tls_material(&options.tls)?;
    let mut rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid QUIC server TLS material")?;
    let mut alpn = alpn_bytes(&options.tls.alpn);
    if options.masquerade.enabled && !alpn.contains(&H3_ALPN.to_vec()) {
        alpn.push(H3_ALPN.to_vec());
    }
    rustls_config.alpn_protocols = alpn;

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(rustls_config).context("quic server crypto")?,
    ));
    server_config.transport_config(Arc::new(transport_config(options)));
    Ok(server_config)
}

pub fn build_client_config(options: &QuicTransportOptions) -> Result<ClientConfig> {
    ensure_rustls_crypto_provider();
    let mut rustls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    // Use h3 ALPN when masquerade is enabled so DPI sees HTTP/3 traffic
    if options.masquerade.enabled {
        rustls_config.alpn_protocols = vec![H3_ALPN.to_vec()];
    } else {
        rustls_config.alpn_protocols = alpn_bytes(&options.tls.alpn);
    }

    let mut client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_config)?));
    client_config.transport_config(Arc::new(transport_config(options)));
    Ok(client_config)
}

fn transport_config(options: &QuicTransportOptions) -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(VarInt::from_u32(options.max_concurrent_bidi_streams));
    transport.max_idle_timeout(Some(
        idle_timeout_varint(options.max_idle_timeout_secs).into(),
    ));
    transport.initial_mtu(options.initial_mtu);
    transport
}

fn idle_timeout_varint(secs: u64) -> VarInt {
    let ms = secs.saturating_mul(1_000);
    VarInt::try_from(ms).unwrap_or(VarInt::from_u32(30_000))
}

fn alpn_bytes(alpn: &[String]) -> Vec<Vec<u8>> {
    alpn.iter().map(|s| s.as_bytes().to_vec()).collect()
}

fn load_or_generate_tls_material(
    tls: &QuicTlsConfig,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    match (&tls.cert_path, &tls.key_path) {
        (Some(cert_path), Some(key_path)) => load_tls_from_files(cert_path, key_path),
        (None, None) => generate_ephemeral_self_signed(),
        _ => Err(anyhow::anyhow!(
            "quic.tls requires both cert_path and key_path, or neither for auto-generated certs"
        )),
    }
}

fn load_tls_from_files(
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_pem =
        fs::read(cert_path).with_context(|| format!("read QUIC cert {}", cert_path.display()))?;
    let key_pem =
        fs::read(key_path).with_context(|| format!("read QUIC key {}", key_path.display()))?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .context("parse QUIC certificate PEM")?
        .into_iter()
        .map(|c| c.into_owned())
        .collect();
    if certs.is_empty() {
        return Err(anyhow::anyhow!(
            "no certificates found in {}",
            cert_path.display()
        ));
    }

    let key = to_owned_private_key(
        rustls_pemfile::private_key(&mut key_pem.as_slice())
            .context("parse QUIC private key PEM")?
            .ok_or_else(|| anyhow::anyhow!("no private keys found in {}", key_path.display()))?,
    );

    Ok((certs, key))
}

fn to_owned_private_key(key: PrivateKeyDer<'_>) -> PrivateKeyDer<'static> {
    match key {
        PrivateKeyDer::Pkcs8(k) => {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k.secret_pkcs8_der().to_vec()))
        }
        PrivateKeyDer::Pkcs1(k) => PrivateKeyDer::Pkcs1(
            rustls::pki_types::PrivatePkcs1KeyDer::from(k.secret_pkcs1_der().to_vec()),
        ),
        PrivateKeyDer::Sec1(k) => PrivateKeyDer::Sec1(rustls::pki_types::PrivateSec1KeyDer::from(
            k.secret_sec1_der().to_vec(),
        )),
        other => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(other.secret_der().to_vec())),
    }
}

fn generate_ephemeral_self_signed() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>
{
    let key_pair = KeyPair::generate().context("generate QUIC TLS key pair")?;
    let mut params = CertificateParams::new(vec!["lp2ln.local".to_string()])
        .context("build QUIC certificate params")?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "lp2ln");
    let cert = params
        .self_signed(&key_pair)
        .context("sign ephemeral QUIC certificate")?;
    Ok((
        vec![CertificateDer::from(cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
    ))
}

/// P2P mesh uses LP2LN packet signatures above TLS; accept any peer cert for slice 1.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn raw_quinn_client_open_server_accept() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let options = QuicTransportOptions::default();
        let server_config = build_server_config(&options).expect("server config");
        let client_config = build_client_config(&options).expect("client config");

        let server_endpoint = Arc::new(
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
                .expect("server endpoint"),
        );
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = {
            let server_endpoint = server_endpoint.clone();
            tokio::spawn(async move {
                let incoming = server_endpoint.accept().await.expect("incoming");
                let conn = incoming.await.expect("connection");
                conn.accept_bi().await.expect("accept_bi")
            })
        };

        let mut client_endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client endpoint");
        client_endpoint.set_default_client_config(client_config);
        let client_endpoint = Arc::new(client_endpoint);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let conn = client_endpoint
            .connect(server_addr, "lp2ln.local")
            .expect("connect")
            .await
            .expect("handshake");
        conn.open_bi().await.expect("open_bi");

        server_task.await.expect("join");
    }

    #[tokio::test]
    async fn quic_session_exchange_packet() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        use crate::packet::Packet;
        use crate::sessions::Session;
        use crate::sessions::session::LinkKind;
        use crate::transport::quic::session::QuicSession;
        use tokio::sync::mpsc;

        let options = QuicTransportOptions::default();
        let server_config = build_server_config(&options).expect("server config");
        let client_config = build_client_config(&options).expect("client config");

        let server_endpoint = Arc::new(
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
                .expect("server endpoint"),
        );
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = {
            let server_endpoint = server_endpoint.clone();
            tokio::spawn(async move {
                let incoming = server_endpoint.accept().await.expect("incoming");
                let connection = incoming.await.expect("connection");
                let streams = connection.accept_bi().await.expect("accept_bi");
                (server_endpoint, connection, streams)
            })
        };

        let mut client_endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client ep");
        client_endpoint.set_default_client_config(client_config);
        let client_endpoint = Arc::new(client_endpoint);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let conn = client_endpoint
            .connect(server_addr, "lp2ln.local")
            .expect("connect")
            .await
            .expect("handshake");
        let client_streams = conn.open_bi().await.expect("open_bi");

        // Create outbound session and send a packet BEFORE awaiting server_task.
        // open_bi() only allocates a stream ID locally; no QUIC STREAM frame is sent
        // until data is written. The send() call writes data, which triggers the
        // STREAM frame and allows server_task's accept_bi() to complete.
        let outbound = QuicSession::new_from_streams(
            client_endpoint,
            conn,
            client_streams.0,
            client_streams.1,
            None,
            LinkKind::DirectQuic,
            None,
            None,
        )
        .expect("outbound");

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
        outbound.send(packet.clone()).await.expect("send");

        let (server_endpoint, server_conn, server_streams) = server_task.await.expect("join");
        let inbound = QuicSession::new_from_streams(
            server_endpoint,
            server_conn,
            server_streams.0,
            server_streams.1,
            None,
            LinkKind::DirectQuic,
            None,
            None,
        )
        .expect("inbound");

        let (tx, mut rx) = mpsc::channel(4);
        inbound.spawn_reader(tx);
        let received = rx.recv().await.expect("packet");
        assert_eq!(received.packet.data, packet.data);
    }
}
