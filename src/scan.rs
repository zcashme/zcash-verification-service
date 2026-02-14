//! Memo decryption utilities for ZVS.
//!
//! This module handles decrypting memos from full Zcash transactions using
//! the unified `decrypt_transaction` API from zcash_client_backend.

use std::collections::HashMap;

use anyhow::Result;
use tracing::debug;

use zcash_client_backend::{decrypt_transaction, TransferType};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    consensus::{BlockHeight, MainNetwork},
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};

/// A decrypted memo with its associated value.
#[derive(Debug, Clone)]
pub struct DecryptedMemo {
    /// The memo text (empty string if no text memo).
    pub memo_text: String,
    /// The value of the note in zatoshis.
    pub value: Zatoshis,
    /// Whether this is an incoming payment (vs change or outgoing).
    pub is_incoming: bool,
}

/// Decrypt all memos from a transaction using the unified API.
///
/// This function handles both Sapling and Orchard outputs in a single call.
/// It only returns incoming transfers (not change or outgoing).
///
/// # Parameters
/// - `tx`: The transaction to decrypt
/// - `ufvk`: The unified full viewing key to use for decryption
/// - `block_height`: The height at which the transaction was mined
///
/// # Returns
/// A vector of decrypted memos with their values, filtered to only incoming transfers.
pub fn decrypt_memos(
    tx: &Transaction,
    ufvk: &UnifiedFullViewingKey,
    block_height: BlockHeight,
) -> Result<Vec<DecryptedMemo>> {
    // Build the UFVK map (we only have one account)
    let mut ufvks = HashMap::new();
    ufvks.insert(0u32, ufvk.clone());

    // Use the unified decrypt_transaction API
    let decrypted = decrypt_transaction(
        &MainNetwork,
        Some(block_height),
        None, // chain_tip not needed for mined transactions
        tx,
        &ufvks,
    );

    let mut results = Vec::new();

    // Process Sapling outputs
    for output in decrypted.sapling_outputs() {
        // Only process incoming transfers (not change or outgoing)
        if !matches!(output.transfer_type(), TransferType::Incoming) {
            continue;
        }

        let memo_text = extract_memo_text(output.memo());
        let value = output.note_value();

        if !memo_text.is_empty() {
            debug!("Decrypted Sapling memo: {}", memo_text);
        }

        results.push(DecryptedMemo {
            memo_text,
            value,
            is_incoming: true,
        });
    }

    // Process Orchard outputs
    for output in decrypted.orchard_outputs() {
        // Only process incoming transfers (not change or outgoing)
        if !matches!(output.transfer_type(), TransferType::Incoming) {
            continue;
        }

        let memo_text = extract_memo_text(output.memo());
        let value = output.note_value();

        if !memo_text.is_empty() {
            debug!("Decrypted Orchard memo: {}", memo_text);
        }

        results.push(DecryptedMemo {
            memo_text,
            value,
            is_incoming: true,
        });
    }

    Ok(results)
}

/// Extract UTF-8 text from MemoBytes.
///
/// Per ZIP-302:
/// - Empty memos return empty string
/// - Text memos are extracted as UTF-8
pub fn extract_memo_text(memo_bytes: &MemoBytes) -> String {
    match Memo::try_from(memo_bytes.clone()) {
        Ok(Memo::Text(text)) => text.to_string(),
        Ok(Memo::Empty) => String::new(),
        Ok(Memo::Future(_)) => String::new(),
        Ok(Memo::Arbitrary(_)) => String::new(),
        Err(_) => String::new(),
    }
}

/// Convenience function to get the first non-empty memo from a transaction.
///
/// This is useful when you expect a single memo per transaction (like ZVS verification).
pub fn decrypt_first_memo(
    tx: &Transaction,
    ufvk: &UnifiedFullViewingKey,
    block_height: BlockHeight,
) -> Result<Option<DecryptedMemo>> {
    let memos = decrypt_memos(tx, ufvk, block_height)?;

    // Return the first memo with non-empty text
    Ok(memos.into_iter().find(|m| !m.memo_text.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_memo_text_empty() {
        let memo = MemoBytes::empty();
        assert_eq!(extract_memo_text(&memo), "");
    }

    #[test]
    fn test_extract_memo_text_with_content() {
        let memo = MemoBytes::from_bytes(b"pineapple").unwrap();
        // Note: MemoBytes::from_bytes pads to 512 bytes, so this tests the parsing
        assert!(extract_memo_text(&memo).starts_with("pineapple"));
    }
}
