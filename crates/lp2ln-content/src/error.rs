use std::io;

/// Errors from content primitives (store, encrypt, manifests, leases).
#[derive(Debug, thiserror::Error)]
pub enum ContentError {
    #[error("redb: {0}")]
    Redb(String),

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("serialization: {0}")]
    Serialize(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("crypto: {0}")]
    Crypto(String),

    #[error("{0}")]
    Other(String),
}

impl From<postcard::Error> for ContentError {
    fn from(e: postcard::Error) -> Self {
        Self::Serialize(e.to_string())
    }
}

impl From<redb::Error> for ContentError {
    fn from(e: redb::Error) -> Self {
        Self::Redb(e.to_string())
    }
}

impl From<redb::DatabaseError> for ContentError {
    fn from(e: redb::DatabaseError) -> Self {
        Self::Redb(e.to_string())
    }
}

impl From<redb::TransactionError> for ContentError {
    fn from(e: redb::TransactionError) -> Self {
        Self::Redb(e.to_string())
    }
}

impl From<redb::TableError> for ContentError {
    fn from(e: redb::TableError) -> Self {
        Self::Redb(e.to_string())
    }
}

impl From<redb::StorageError> for ContentError {
    fn from(e: redb::StorageError) -> Self {
        Self::Redb(e.to_string())
    }
}

impl From<redb::CommitError> for ContentError {
    fn from(e: redb::CommitError) -> Self {
        Self::Redb(e.to_string())
    }
}
