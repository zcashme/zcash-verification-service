//! Block sync + reorg recovery.
//!
//! Ported from zecd's `sync/engine.rs`, simplified for ZFA's needs (no
//! transparent, single account, no enhancement). The sync engine downloads
//! compact blocks from lightwalletd and scans them through librustzcash's
//! `scan_cached_blocks` to recover the wallet's note state — the source of
//! truth for confirmed transactions that the mempool watcher might miss.
//!
//! This module is a placeholder — the full implementation will be ported from
//! zecd's sync engine when we wire up the wallet actor.

// TODO: port sync_one_batch, reorg handling, cache management from zecd