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

    // ── P7 block / DHT commands ──────────────────────────────────────────────

    /// Announce content blocks to the DHT (P7). Requires capability Send.
    pub async fn dht_announce(&mut self, content_ids: Vec<Vec<u8>>) -> Result<()> {
        self.write_cmd(&AppCmd::DhtAnnounce { content_ids }).await?;
        self.expect_ack().await
    }

    /// Find DHT providers for a content block (P7). Requires capability QueryStatus.
    /// Waits until the node returns a DhtProviders event for this content_id.
    pub async fn dht_find_providers(&mut self, content_id: Vec<u8>) -> Result<Vec<String>> {
        self.write_cmd(&AppCmd::DhtFindProviders { content_id: content_id.clone() }).await?;
        loop {
            match self.read_event().await? {
                AppEvent::DhtProviders { content_id: cid, providers } if cid == content_id => {
                    return Ok(providers);
                }
                AppEvent::Ack { ok: false, error } => {
                    return Err(AppSdkError::AckFailed(
                        error.unwrap_or_else(|| "DhtFindProviders failed".into()),
                    ));
                }
                _ => {}
            }
        }
    }

    /// Ask the node to fetch a content block from specific peers (P7). Requires capability Send.
    /// Waits until the node returns a BlockData event for this content_id.
    pub async fn block_fetch(&mut self, content_id: Vec<u8>, peer_ids: Vec<String>) -> Result<Vec<u8>> {
        self.write_cmd(&AppCmd::BlockFetch { content_id: content_id.clone(), peer_ids }).await?;
        loop {
            match self.read_event().await? {
                AppEvent::BlockData { content_id: cid, data } if cid == content_id => {
                    return Ok(data);
                }
                AppEvent::Ack { ok: false, error } => {
                    return Err(AppSdkError::AckFailed(
                        error.unwrap_or_else(|| "BlockFetch failed".into()),
                    ));
                }
                _ => {}
            }
        }
    }

    /// Store a block on the node and replicate to up to `min_replicas` peers (P7).
    /// Returns the peer_ids that durably acked the block. Requires capability Send.
    pub async fn block_push(
        &mut self,
        content_id: Vec<u8>,
        data: Vec<u8>,
        min_replicas: u32,
    ) -> Result<Vec<String>> {
        self.write_cmd(&AppCmd::BlockPush { content_id: content_id.clone(), data, min_replicas })
            .await?;
        loop {
            match self.read_event().await? {
                AppEvent::BlockPushed { content_id: cid, stored_by } if cid == content_id => {
                    return Ok(stored_by);
                }
                AppEvent::Ack { ok: false, error } => {
                    return Err(AppSdkError::AckFailed(
                        error.unwrap_or_else(|| "BlockPush failed".into()),
                    ));
                }
                _ => {}
            }
        }
    }

    /// Publish a mutable value under `key` (P7 namespace heads). Requires capability Send.
    pub async fn dht_put_value(&mut self, key: Vec<u8>, value: Vec<u8>, seq: u64) -> Result<()> {
        self.write_cmd(&AppCmd::DhtPutValue { key, value, seq }).await?;
        self.expect_ack().await
    }

    /// Fetch the freshest known value for `key` (P7). Requires capability QueryStatus.
    pub async fn dht_get_value(&mut self, key: Vec<u8>) -> Result<(Option<Vec<u8>>, u64)> {
        self.write_cmd(&AppCmd::DhtGetValue { key: key.clone() }).await?;
        loop {
            match self.read_event().await? {
                AppEvent::DhtValue { key: k, value, seq } if k == key => {
                    return Ok((value, seq));
                }
                AppEvent::Ack { ok: false, error } => {
                    return Err(AppSdkError::AckFailed(
                        error.unwrap_or_else(|| "DhtGetValue failed".into()),
                    ));
                }
                _ => {}
            }
        }
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
