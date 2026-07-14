//! The mempool authentication watcher — the primary ZFA authentication path.
//!
//! The watcher maintains a persistent gRPC connection to lightwalletd and
//! processes every mempool transaction:
//!
//! 1. Parse the raw transaction bytes (`Transaction::read`).
//! 2. Trial-decrypt with the service wallet's viewing keys using
//!    `zcash_client_backend::decrypt_transaction`.
//! 3. If the wallet received a shielded output, extract the memo.
//! 4. Parse the memo through the strict ZFA authentication memo parser.
//! 5. If the memo carries a return address, create at most one OTP response in
//!    `responses.sqlite` (claim incoming txid, persist response txid, broadcast).
//!
//! The mempool stream **closes when a new block is mined**. The watcher
//! reconnects immediately with bounded backoff. On reconnect, the current
//! mempool is re-served — the response ledger ensures we never construct a
//! second response transaction for the same incoming txid.
//!
//! TODO: full implementation.
