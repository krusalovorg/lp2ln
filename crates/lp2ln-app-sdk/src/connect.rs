//! Connect helpers for App Plane IPC endpoints.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::error::{AppSdkError, Result};

/// Where to connect.
#[derive(Debug, Clone)]
pub enum Endpoint {
    /// Loopback TCP (dev / tests only).
    Tcp(String),
    /// Unix domain socket path.
    #[cfg(unix)]
    Unix(String),
    /// Windows named pipe (`\\.\pipe\…` or bare name).
    #[cfg(windows)]
    NamedPipe(String),
}

#[derive(Debug, Clone)]
pub struct ConnectOpts {
    pub endpoint: Endpoint,
    pub connect_timeout: Duration,
}

impl ConnectOpts {
    pub fn tcp(addr: impl Into<String>) -> Self {
        Self {
            endpoint: Endpoint::Tcp(addr.into()),
            connect_timeout: Duration::from_secs(5),
        }
    }

    #[cfg(unix)]
    pub fn unix(path: impl Into<String>) -> Self {
        Self {
            endpoint: Endpoint::Unix(path.into()),
            connect_timeout: Duration::from_secs(5),
        }
    }

    #[cfg(windows)]
    pub fn named_pipe(path: impl Into<String>) -> Self {
        Self {
            endpoint: Endpoint::NamedPipe(normalize_windows_pipe_name(&path.into())),
            connect_timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = d;
        self
    }
}

#[cfg(windows)]
fn normalize_windows_pipe_name(path: &str) -> String {
    if path.starts_with(r"\\.\pipe\") || path.starts_with(r"//./pipe/") {
        path.to_string()
    } else if path.contains('\\') || path.contains('/') {
        path.to_string()
    } else {
        format!(r"\\.\pipe\{path}")
    }
}

pub(crate) type BoxConn = Box<dyn Conn + Send + Unpin>;

pub(crate) trait Conn: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> Conn for T {}

pub(crate) async fn connect(opts: &ConnectOpts) -> Result<BoxConn> {
    let fut = async {
        match &opts.endpoint {
            Endpoint::Tcp(addr) => {
                let s = TcpStream::connect(addr).await?;
                Ok(Box::new(s) as BoxConn)
            }
            #[cfg(unix)]
            Endpoint::Unix(path) => {
                let s = tokio::net::UnixStream::connect(path).await?;
                Ok(Box::new(s) as BoxConn)
            }
            #[cfg(windows)]
            Endpoint::NamedPipe(path) => {
                let client = tokio::net::windows::named_pipe::ClientOptions::new().open(path)?;
                Ok(Box::new(client) as BoxConn)
            }
        }
    };
    match tokio::time::timeout(opts.connect_timeout, fut).await {
        Ok(r) => r,
        Err(_) => Err(AppSdkError::Timeout),
    }
}
