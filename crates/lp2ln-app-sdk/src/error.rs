//! SDK error types.

use std::fmt;

use lp2ln_app_protocol::AppErrorCode;

pub type Result<T> = std::result::Result<T, AppSdkError>;

#[derive(Debug)]
pub enum AppSdkError {
    Io(std::io::Error),
    Protocol(AppErrorCode),
    Handshake(String),
    AckFailed(String),
    UnexpectedEvent(String),
    Closed,
    Timeout,
    BadResponse(String),
}

impl fmt::Display for AppSdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Protocol(c) => write!(f, "protocol: {c}"),
            Self::Handshake(m) => write!(f, "handshake: {m}"),
            Self::AckFailed(m) => write!(f, "ack failed: {m}"),
            Self::UnexpectedEvent(m) => write!(f, "unexpected event: {m}"),
            Self::Closed => write!(f, "connection closed"),
            Self::Timeout => write!(f, "timeout"),
            Self::BadResponse(m) => write!(f, "bad response: {m}"),
        }
    }
}

impl std::error::Error for AppSdkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for AppSdkError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
