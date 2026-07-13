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

/// The concrete error type returned by `propose_transfer` / `create_proposed_transactions`
/// for our `WalletDb`. Naming it pins the otherwise-unconstrained commitment-tree error
/// parameter so type inference can resolve it (mirrors zecd's `ProposalError`).
pub type ProposalError = zcash_client_backend::data_api::error::Error<
    zcash_client_sqlite::error::SqliteClientError,
    zcash_client_sqlite::wallet::commitment_tree::Error,
    zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelectorError,
    zcash_primitives::transaction::fees::zip317::FeeError,
    zcash_primitives::transaction::fees::zip317::FeeError,
    zcash_client_sqlite::ReceivedNoteId,
>;