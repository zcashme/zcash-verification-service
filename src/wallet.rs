//! Wallet: key custody, DB init, and the single-writer actor.
//!
//! The wallet module owns:
//!
//! - The service wallet's encrypted seed (`zfa.toml` `[seed]` table),
//!   decrypted in memory only for sending OTP response transactions.
//! - The zcash_client_sqlite wallet database (data.sqlite), exclusively owned
//!   and migrated by librustzcash.
//! - The single-writer actor that serializes all wallet writes: sync batches,
//!   mempool decryption, and OTP response sends.
//! - A seed→database UFVK cross-check that catches a swapped `data.sqlite`.
//!
//! Ported from zecd's wallet module, stripped of: multi-wallet, transparent
//! receiving, watch-only, passphrase encryption, UFVK pin, pipelined proving,
//! and the Bitcoin-Core RPC send paths. Added: the minimal ZFA OTP response
//! flow with OTP key derived from the seed.

pub mod actor;
pub mod binding;
pub mod keys;
pub mod open;
pub mod store;