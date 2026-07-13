//! The single-writer actor: serializes all wallet + session writes.
//!
//! Ported from zecd's `wallet/actor.rs`, stripped to ZFA's needs. The actor
//! runs the main loop: connect to lightwalletd → sync confirmed blocks → open
//! mempool stream → decrypt each tx → match session memo → authenticate
//! session in zfa.db. On mempool stream close (new block) → sync → reopen.
//!
//! TODO: full implementation porting from zecd.

// Placeholder — the full actor will be ported from zecd.