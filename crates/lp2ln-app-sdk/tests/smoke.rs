//! Mock IPC host for SDK smoke tests (no lp2lnd dependency).

use lp2ln_app_protocol::{
    AppCapability, AppCmd, AppErrorCode, AppEvent, DEFAULT_STREAM_CREDITS, PROTOCOL_VERSION,
    decode_cmd, encode_event,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use lp2ln_app_sdk::{AppClient, ConnectOpts, OpenStreamOpts};

async fn read_cmd(stream: &mut TcpStream) -> AppCmd {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let n = u32::from_le_bytes(len_buf) as usize;
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body).await.unwrap();
    decode_cmd(&body).unwrap()
}

async fn write_ev(stream: &mut TcpStream, ev: &AppEvent) {
    stream.write_all(&encode_event(ev)).await.unwrap();
}

#[tokio::test]
async fn sdk_hello_subscribe_stream_cancel() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        match read_cmd(&mut stream).await {
            AppCmd::Hello {
                version,
                capabilities,
                ..
            } => {
                assert_eq!(version, PROTOCOL_VERSION);
                write_ev(
                    &mut stream,
                    &AppEvent::HelloAck {
                        version: PROTOCOL_VERSION,
                        capabilities,
                        error: None,
                        message: None,
                    },
                )
                .await;
            }
            other => panic!("expected Hello, got {other:?}"),
        }
        match read_cmd(&mut stream).await {
            AppCmd::Subscribe { protocol_id: 42 } => {
                write_ev(
                    &mut stream,
                    &AppEvent::Ack {
                        ok: true,
                        error: None,
                    },
                )
                .await;
            }
            other => panic!("expected Subscribe, got {other:?}"),
        }
        match read_cmd(&mut stream).await {
            AppCmd::OpenStream {
                stream_id: 7,
                protocol_id: 42,
                ..
            } => {
                write_ev(
                    &mut stream,
                    &AppEvent::Ack {
                        ok: true,
                        error: None,
                    },
                )
                .await;
                write_ev(
                    &mut stream,
                    &AppEvent::StreamWindow {
                        stream_id: 7,
                        credits: DEFAULT_STREAM_CREDITS,
                    },
                )
                .await;
            }
            other => panic!("expected OpenStream, got {other:?}"),
        }
        match read_cmd(&mut stream).await {
            AppCmd::StreamCancel { stream_id: 7 } => {
                write_ev(
                    &mut stream,
                    &AppEvent::StreamClosed {
                        stream_id: 7,
                        error: Some(AppErrorCode::Canceled),
                    },
                )
                .await;
            }
            other => panic!("expected StreamCancel, got {other:?}"),
        }
    });

    let mut client = AppClient::connect(ConnectOpts::tcp(addr.to_string()))
        .await
        .unwrap();
    let caps = client
        .hello(
            &[
                AppCapability::Subscribe,
                AppCapability::OpenStream,
            ],
            None,
        )
        .await
        .unwrap();
    assert!(caps.contains(&AppCapability::Subscribe));
    client.subscribe(42).await.unwrap();
    let window = client
        .open_stream(OpenStreamOpts {
            stream_id: 7,
            protocol_id: 42,
            peer_id: "peer".into(),
        })
        .await
        .unwrap();
    assert_eq!(window, DEFAULT_STREAM_CREDITS);
    client.stream_cancel(7).await.unwrap();

    server.await.unwrap();
}
