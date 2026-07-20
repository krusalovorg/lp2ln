//! High-level App Plane client.

use std::time::Duration;

use lp2ln_app_protocol::{
    AppCapability, AppCmd, AppErrorCode, AppEvent, PROTOCOL_VERSION, decode_event, encode_cmd,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::connect::{self, BoxConn, ConnectOpts};
use crate::error::{AppSdkError, Result};

#[derive(Debug, Clone)]
pub struct SubscribeOpts {
    pub protocol_id: u16,
}

#[derive(Debug, Clone)]
pub struct OpenStreamOpts {
    pub stream_id: u64,
    pub protocol_id: u16,
    pub peer_id: String,
}

/// Client session after connect (+ optional Hello).
pub struct AppClient {
    conn: BoxConn,
    handshaken: bool,
    granted: Vec<AppCapability>,
    read_timeout: Duration,
}

impl AppClient {
    pub async fn connect(opts: ConnectOpts) -> Result<Self> {
        let conn = connect::connect(&opts).await?;
        Ok(Self {
            conn,
            handshaken: false,
            granted: Vec::new(),
            read_timeout: Duration::from_secs(5),
        })
    }

    pub fn with_read_timeout(mut self, d: Duration) -> Self {
        self.read_timeout = d;
        self
    }

    pub fn granted_capabilities(&self) -> &[AppCapability] {
        &self.granted
    }

    pub fn is_handshaken(&self) -> bool {
        self.handshaken
    }

    /// Perform Hello / HelloAck. Must be called before other commands.
    pub async fn hello(
        &mut self,
        capabilities: &[AppCapability],
        token: Option<&str>,
    ) -> Result<&[AppCapability]> {
        self.write_cmd(&AppCmd::Hello {
            version: PROTOCOL_VERSION,
            capabilities: capabilities.to_vec(),
            token: token.map(str::to_string),
        })
        .await?;
        match self.read_event().await? {
            AppEvent::HelloAck {
                error: None,
                capabilities,
                ..
            } => {
                self.handshaken = true;
                self.granted = capabilities;
                Ok(&self.granted)
            }
            AppEvent::HelloAck {
                error: Some(code),
                message,
                ..
            } => Err(AppSdkError::Handshake(
                message.unwrap_or_else(|| code.to_string()),
            )),
            other => Err(AppSdkError::UnexpectedEvent(format!("{other:?}"))),
        }
    }

    pub async fn subscribe(&mut self, protocol_id: u16) -> Result<()> {
        self.write_cmd(&AppCmd::Subscribe { protocol_id }).await?;
        self.expect_ack().await
    }

    pub async fn unsubscribe(&mut self, protocol_id: u16) -> Result<()> {
        self.write_cmd(&AppCmd::Unsubscribe { protocol_id }).await?;
        self.expect_ack().await
    }

    pub async fn send(&mut self, peer_id: &str, protocol_id: u16, payload: Vec<u8>) -> Result<()> {
        self.write_cmd(&AppCmd::Send {
            peer_id: peer_id.to_string(),
            protocol_id,
            payload,
        })
        .await?;
        self.expect_ack().await
    }

    /// Open a bulk stream; returns the initial credit window from the host.
    pub async fn open_stream(&mut self, opts: OpenStreamOpts) -> Result<u32> {
        let stream_id = opts.stream_id;
        self.write_cmd(&AppCmd::OpenStream {
            stream_id,
            protocol_id: opts.protocol_id,
            peer_id: opts.peer_id,
        })
        .await?;
        self.expect_ack().await?;
        match self.read_event().await? {
            AppEvent::StreamWindow {
                stream_id: id,
                credits,
            } if id == stream_id => Ok(credits),
            other => Err(AppSdkError::UnexpectedEvent(format!(
                "expected StreamWindow, got {other:?}"
            ))),
        }
    }

    pub async fn stream_chunk(&mut self, stream_id: u64, seq: u64, payload: Vec<u8>) -> Result<()> {
        self.write_cmd(&AppCmd::StreamChunk {
            stream_id,
            seq,
            payload,
        })
        .await
    }

    pub async fn stream_window(&mut self, stream_id: u64, credits: u32) -> Result<()> {
        self.write_cmd(&AppCmd::StreamWindow {
            stream_id,
            credits,
        })
        .await
    }

    pub async fn stream_cancel(&mut self, stream_id: u64) -> Result<()> {
        self.write_cmd(&AppCmd::StreamCancel { stream_id }).await?;
        match self.read_event().await? {
            AppEvent::StreamClosed {
                stream_id: id,
                error: Some(AppErrorCode::Canceled),
            } if id == stream_id => Ok(()),
            AppEvent::StreamClosed {
                stream_id: id,
                error,
            } if id == stream_id => Err(AppSdkError::BadResponse(format!(
                "closed with {error:?}"
            ))),
            AppEvent::Error { code, message } => Err(AppSdkError::BadResponse(
                message.unwrap_or_else(|| code.to_string()),
            )),
            other => Err(AppSdkError::UnexpectedEvent(format!("{other:?}"))),
        }
    }

    /// Read the next event (Incoming, Stream*, Error, …).
    pub async fn next_event(&mut self) -> Result<AppEvent> {
        self.read_event().await
    }

    /// Reconnect with exponential backoff, then re-Hello with the same caps/token.
    pub async fn reconnect(
        &mut self,
        opts: ConnectOpts,
        capabilities: &[AppCapability],
        token: Option<&str>,
        attempts: u32,
    ) -> Result<&[AppCapability]> {
        let mut delay = Duration::from_millis(50);
        let mut last = AppSdkError::Closed;
        for _ in 0..attempts.max(1) {
            match connect::connect(&opts).await {
                Ok(conn) => {
                    self.conn = conn;
                    self.handshaken = false;
                    self.granted.clear();
                    return self.hello(capabilities, token).await;
                }
                Err(e) => {
                    last = e;
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(2));
                }
            }
        }
        Err(last)
    }

    async fn write_cmd(&mut self, cmd: &AppCmd) -> Result<()> {
        let frame = encode_cmd(cmd);
        self.conn.write_all(&frame).await?;
        Ok(())
    }

    async fn read_event(&mut self) -> Result<AppEvent> {
        let fut = async {
            let mut len_buf = [0u8; 4];
            self.conn.read_exact(&mut len_buf).await?;
            let n = u32::from_le_bytes(len_buf) as usize;
            let mut body = vec![0u8; n];
            self.conn.read_exact(&mut body).await?;
            decode_event(&body).map_err(|_| {
                AppSdkError::Protocol(AppErrorCode::BadFrame)
            })
        };
        match tokio::time::timeout(self.read_timeout, fut).await {
            Ok(Ok(ev)) => Ok(ev),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(AppSdkError::Timeout),
        }
    }

    async fn expect_ack(&mut self) -> Result<()> {
        match self.read_event().await? {
            AppEvent::Ack { ok: true, .. } => Ok(()),
            AppEvent::Ack {
                ok: false,
                error: Some(msg),
            } => Err(AppSdkError::AckFailed(msg)),
            AppEvent::Ack { ok: false, .. } => Err(AppSdkError::AckFailed("ack failed".into())),
            AppEvent::Error { code, message } => Err(AppSdkError::Handshake(
                message.unwrap_or_else(|| code.to_string()),
            )),
            other => Err(AppSdkError::UnexpectedEvent(format!("{other:?}"))),
        }
    }
}
