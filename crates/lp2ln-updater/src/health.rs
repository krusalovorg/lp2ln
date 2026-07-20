//! Updater <-> child health IPC over a local TCP socket.
//!
//! The updater binds `127.0.0.1:0`, stores the address, and passes it to the
//! child via the `LP2LN_UPDATER_IPC` environment variable.
//!
//! Protocol: newline-delimited JSON.
//!   child → updater:  {"type":"ready","build_id":"..."}
//!   child → updater:  {"type":"candidate_staged","build_id":"...","staging_path":"..."}
//!   updater → child:  {"type":"shutdown"}

use std::net::SocketAddr;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};

pub const ENV_IPC_ADDR: &str = "LP2LN_UPDATER_IPC";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChildMessage {
    Ready { build_id: String },
    CandidateStaged { build_id: String, staging_path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UpdaterMessage {
    Shutdown,
}

pub struct HealthServer {
    listener: TcpListener,
    pub addr: SocketAddr,
}

impl HealthServer {
    pub async fn bind() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        Ok(Self { listener, addr })
    }

    /// Accept one child connection and return a `HealthConn`.
    pub async fn accept_with_timeout(&self, secs: u64) -> Result<HealthConn> {
        let (stream, _) = timeout(Duration::from_secs(secs), self.listener.accept())
            .await
            .map_err(|_| anyhow::anyhow!("timed out waiting for child IPC connection"))??;
        Ok(HealthConn::new(stream))
    }
}

pub struct HealthConn {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl HealthConn {
    fn new(stream: TcpStream) -> Self {
        let (r, w) = stream.into_split();
        Self { reader: BufReader::new(r), writer: w }
    }

    /// Read the next message from the child with a deadline.
    pub async fn recv(&mut self, timeout_secs: u64) -> Result<Option<ChildMessage>> {
        let mut line = String::new();
        let n = timeout(
            Duration::from_secs(timeout_secs),
            self.reader.read_line(&mut line),
        )
        .await
        .map_err(|_| anyhow::anyhow!("timeout reading child message"))??;
        if n == 0 {
            return Ok(None); // EOF
        }
        let msg = serde_json::from_str(line.trim())
            .map_err(|e| anyhow::anyhow!("child sent bad JSON: {e}: {line}"))?;
        Ok(Some(msg))
    }

    pub async fn send(&mut self, msg: &UpdaterMessage) -> Result<()> {
        let mut line = serde_json::to_string(msg)?;
        line.push('\n');
        self.writer.write_all(line.as_bytes()).await?;
        Ok(())
    }
}
