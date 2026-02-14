//! Memo decryption utilities for ZVS.
//!
//! This module handles decrypting memos from full Zcash transactions.
//! Compact blocks (used for efficient sync) don't include memos - we must
//! fetch the full transaction to read memo fields.

use anyhow::{anyhow, Result};
use tonic::transport::Channel;
use tracing::debug;

use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, TxFilter,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, MainNetwork};

/// Fetch a transaction from lightwalletd and decrypt its memo.
///
/// Returns the decrypted memo text if found, or None if no memo/empty memo.
pub async fn fetch_and_decrypt_memo(
    client: &mut CompactTxStreamerClient<Channel>,
    ufvk: &UnifiedFullViewingKey,
    txid: &[u8],
    height: u32,
) -> Result<Option<String>> {
    // Fetch full transaction from lightwalletd
    let tx_filter = TxFilter {
        block: None,
        index: 0,
        hash: txid.to_vec(),
    };

    let raw_tx = client
        .get_transaction(tx_filter)
        .await
        .map_err(|e| anyhow!("Failed to fetch transaction: {e}"))?
        .into_inner();

    if raw_tx.data.is_empty() {
        return Err(anyhow!("Empty transaction data"));
    }

    // Parse transaction
    let block_height = BlockHeight::from_u32(height);
    let branch_id = zcash_primitives::consensus::BranchId::for_height(&MainNetwork, block_height);

    let tx = Transaction::read(&raw_tx.data[..], branch_id)
        .map_err(|e| anyhow!("Failed to parse transaction: {e}"))?;

    // Try Sapling first, then Orchard
    if let Some(memo) = decrypt_sapling_memo(&tx, ufvk, block_height)? {
        return Ok(Some(memo));
    }

    if let Some(memo) = decrypt_orchard_memo(&tx, ufvk)? {
        return Ok(Some(memo));
    }

    Ok(None)
}

/// Decrypt memo from Sapling outputs in a transaction.
pub fn decrypt_sapling_memo(
    tx: &Transaction,
    ufvk: &UnifiedFullViewingKey,
    block_height: BlockHeight,
) -> Result<Option<String>> {
    let sapling_dfvk = match ufvk.sapling() {
        Some(k) => k,
        None => return Ok(None),
    };

    let bundle = match tx.sapling_bundle() {
        Some(b) => b,
        None => return Ok(None),
    };

    let ivk = sapling_dfvk.to_ivk(zip32::Scope::External);
    let prepared_ivk = sapling_crypto::keys::PreparedIncomingViewingKey::new(&ivk);

    // ZIP-212 activated at Canopy (mainnet height 1046400)
    let zip212 = if u32::from(block_height) >= 1_046_400 {
        sapling_crypto::note_encryption::Zip212Enforcement::On
    } else {
        sapling_crypto::note_encryption::Zip212Enforcement::Off
    };

    for output in bundle.shielded_outputs() {
        let domain = sapling_crypto::note_encryption::SaplingDomain::new(zip212);

        if let Some((_note, _address, memo_bytes)) =
            zcash_note_encryption::try_note_decryption(&domain, &prepared_ivk, output)
        {
            let memo_text = extract_memo_text(&memo_bytes);
            if !memo_text.is_empty() {
                debug!("Decrypted Sapling memo: {}", memo_text);
                return Ok(Some(memo_text));
            }
        }
    }

    Ok(None)
}

/// Decrypt memo from Orchard actions in a transaction.
pub fn decrypt_orchard_memo(
    tx: &Transaction,
    ufvk: &UnifiedFullViewingKey,
) -> Result<Option<String>> {
    let orchard_fvk = match ufvk.orchard() {
        Some(k) => k,
        None => return Ok(None),
    };

    let bundle = match tx.orchard_bundle() {
        Some(b) => b,
        None => return Ok(None),
    };

    let ivk = orchard_fvk.to_ivk(zip32::Scope::External);
    let prepared_ivk = orchard::keys::PreparedIncomingViewingKey::new(&ivk);

    for action in bundle.actions() {
        let domain = orchard::note_encryption::OrchardDomain::for_action(action);

        if let Some((_note, _address, memo_bytes)) =
            zcash_note_encryption::try_note_decryption(&domain, &prepared_ivk, action)
        {
            let memo_text = extract_memo_text(&memo_bytes);
            if !memo_text.is_empty() {
                debug!("Decrypted Orchard memo: {}", memo_text);
                return Ok(Some(memo_text));
            }
        }
    }

    Ok(None)
}

/// Extract UTF-8 text from 512-byte memo array.
///
/// Per ZIP-302:
/// - 0xF6 prefix indicates empty memo
/// - Text memos are null-terminated UTF-8
pub fn extract_memo_text(memo_bytes: &[u8; 512]) -> String {
    // 0xF6 = empty memo per ZIP-302
    if memo_bytes[0] == 0xF6 {
        return String::new();
    }

    let end = memo_bytes.iter().position(|&b| b == 0).unwrap_or(512);
    String::from_utf8_lossy(&memo_bytes[..end]).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_memo_text_empty() {
        let mut memo = [0u8; 512];
        memo[0] = 0xF6;
        assert_eq!(extract_memo_text(&memo), "");
    }

    #[test]
    fn test_extract_memo_text_with_content() {
        let mut memo = [0u8; 512];
        memo[..9].copy_from_slice(b"pineapple");
        assert_eq!(extract_memo_text(&memo), "pineapple");
    }

    #[test]
    fn test_extract_memo_text_with_whitespace() {
        let mut memo = [0u8; 512];
        memo[..12].copy_from_slice(b"  pineapple ");
        assert_eq!(extract_memo_text(&memo), "pineapple");
    }
}
