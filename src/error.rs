//! ZFA error type.

use std::fmt;

/// A worker error: either a configuration/setup problem or a runtime failure
/// in the mempool watcher, sync engine, or wallet.
#[derive(Debug)]
pub struct ZfaError {
    pub message: String,
}

impl ZfaError {
    pub fn new(message: impl Into<String>) -> Self {
        ZfaError { message: message.into() }
    }
}

impl fmt::Display for ZfaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ZfaError {}

impl From<anyhow::Error> for ZfaError {
    fn from(e: anyhow::Error) -> Self {
        ZfaError::new(format!("{e:#}"))
    }
}

impl From<rusqlite::Error> for ZfaError {
    fn from(e: rusqlite::Error) -> Self {
        ZfaError::new(format!("database error: {e}"))
    }
}