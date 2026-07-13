//! The mempool authentication watcher — the primary ZFA authentication path.
//!
//! The watcher maintains a persistent gRPC connection to lightwalletd and
//! processes every mempool transaction:
//!
//! 1. Parse the raw transaction bytes (`Transaction::read`).
//! 2. Trial-decrypt with the service wallet's viewing key
//!    (`decrypt_and_store_transaction`).
//! 3. If the wallet received a shielded output, extract the memo.
//! 4. Parse the memo through the strict ZFA session memo parser.
//! 5. If the memo matches a pending session, atomically authenticate it in
//!    zfa.db (claim txid + transition pending → authenticated).
//!
//! The mempool stream **closes when a new block is mined**. The watcher
//! reconnects immediately with bounded backoff. On reconnect, the current
//! mempool is re-served — txid dedup in `processed_txids` ensures we never
//! double-process a transaction.
//!
//! TODO: full implementation.