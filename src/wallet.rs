//! Wallet: key custody, DB init, and the single-writer actor.
//!
//! The wallet module owns:
//!
//! - The service wallet's encrypted seed (keys.toml), decrypted in memory
//!   only for sending OTP response transactions.
//! - The zcash_client_sqlite wallet database (data.sqlite), exclusively owned
//!   and migrated by librustzcash.
//! - The single-writer actor that serializes all wallet writes: sync batches,
//!   mempool decryption, and OTP response sends.
//!
//! Ported from zecd's wallet module, stripped of: multi-wallet, transparent
//! receiving, watch-only, passphrase encryption, pipelined proving, and the
//! Bitcoin-Core RPC send paths. Added: ZFA session authentication on the
//! mempool path, and fixed OTP response transaction construction.

pub mod actor;
pub mod keys;
pub mod open;
pub mod store;