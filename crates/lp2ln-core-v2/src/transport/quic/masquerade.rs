use anyhow::Result;
use bytes::Bytes;
use quinn::Connection;

use super::config::{MasqueradeConfig, MasqueradeMode};

/// Serve an HTTP/3 masquerade response on a connection that arrived with ALPN `h3`.
/// Called when an active probe hits the QUIC endpoint instead of a real LP2LN peer.
pub(super) async fn serve(conn: Connection, config: MasqueradeConfig) {
    if let Err(e) = try_serve(conn, &config).await {
        crate::error!("[QuicMasquerade] masquerade error: {}", e);
    }
}

async fn try_serve(conn: Connection, config: &MasqueradeConfig) -> Result<()> {
    match config.mode {
        MasqueradeMode::Static404 => serve_static_404(conn).await,
        MasqueradeMode::ReverseProxy => {
            // ponytail: reverse_proxy stub — implement when proxy_url forwarding is needed
            crate::warn!(
                "[QuicMasquerade] reverse_proxy not implemented, closing h3 connection from {}",
                conn.remote_address()
            );
            conn.close(0u32.into(), b"not implemented");
            Ok(())
        }
    }
}

async fn serve_static_404(conn: Connection) -> Result<()> {
    let remote = conn.remote_address();
    crate::info!("[QuicMasquerade] serving HTTP/3 404 to {}", remote);
    let h3_conn = h3_quinn::Connection::new(conn);
    let mut server_conn: h3::server::Connection<_, Bytes> =
        h3::server::Connection::new(h3_conn).await?;
    loop {
        match server_conn.accept().await {
            Ok(Some((_req, mut stream))) => {
                let resp = http::Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(())
                    .unwrap();
                if let Err(e) = stream.send_response(resp).await {
                    crate::error!("[QuicMasquerade] send_response to {}: {}", remote, e);
                    break;
                }
                let _ = stream.finish().await;
            }
            Ok(None) => break,
            Err(e) => {
                crate::error!("[QuicMasquerade] h3 accept from {}: {}", remote, e);
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::quic::config::{QuicTransportOptions, build_server_config};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use std::sync::Arc;

    #[derive(Debug)]
    struct AcceptAny;

    impl ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _e: &CertificateDer<'_>,
            _i: &[CertificateDer<'_>],
            _n: &ServerName<'_>,
            _o: &[u8],
            _t: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    fn h3_client_config() -> quinn::ClientConfig {
        let mut rustls_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny))
            .with_no_client_auth();
        rustls_cfg.alpn_protocols = vec![b"h3".to_vec()];
        quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
                .expect("h3 client crypto"),
        ))
    }

    #[tokio::test]
    async fn masquerade_static_404_responds() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let opts = QuicTransportOptions {
            masquerade: MasqueradeConfig {
                enabled: true,
                mode: MasqueradeMode::Static404,
                proxy_url: None,
            },
            ..Default::default()
        };

        let server_cfg = build_server_config(&opts).expect("server config");
        let server_ep = Arc::new(
            quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap())
                .expect("server endpoint"),
        );
        let server_addr = server_ep.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = server_ep.accept().await.expect("incoming");
            let conn = incoming.await.expect("connection");
            serve(
                conn,
                MasqueradeConfig {
                    enabled: true,
                    mode: MasqueradeMode::Static404,
                    proxy_url: None,
                },
            )
            .await;
        });

        let mut client_ep =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client ep");
        client_ep.set_default_client_config(h3_client_config());
        let client_ep = Arc::new(client_ep);

        let quinn_conn = client_ep
            .connect(server_addr, "lp2ln.local")
            .expect("connect")
            .await
            .expect("handshake");

        let h3_conn = h3_quinn::Connection::new(quinn_conn);
        let (mut driver, mut send_req) = h3::client::new(h3_conn).await.expect("h3 client");
        tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });

        let req = http::Request::builder()
            .method("GET")
            .uri("https://lp2ln.local/")
            .body(())
            .unwrap();
        let mut stream = send_req.send_request(req).await.expect("send_request");
        stream.finish().await.expect("finish");
        let resp = stream.recv_response().await.expect("recv_response");
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        server_task.await.expect("server task");
    }
}
