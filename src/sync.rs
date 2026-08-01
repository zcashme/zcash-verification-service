//! Block sync + reorg recovery.
//!
//! Ported from zecd's `sync/engine.rs`, simplified for ZFA (no transparent,
//! no enhancement). Downloads compact blocks from lightwalletd
//! and scans them through librustzcash's `scan_cached_blocks` to recover the
//! wallet's note state — the source of truth for confirmed transactions that
//! the mempool watcher might miss.

use std::path::Path;

use anyhow::anyhow;
use prost::Message;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use zcash_client_backend::data_api::{
    chain::{error::Error as ChainError, scan_cached_blocks},
    scanning::{ScanPriority, ScanRange},
    WalletRead, WalletWrite,
};
use zcash_client_sqlite::chain::BlockMeta;
use zcash_client_sqlite::{error::SqliteClientError, FsBlockDb};
use zcash_protocol::consensus::BlockHeight;

use crate::lwd::LwdClient;
use crate::network::ZNetwork;
use crate::wallet::open::{block_path, WriteDb};

const BATCH_SIZE: u32 = 10_000;

/// Process at most one batch of confirmed-block sync work.
///
/// Returns `true` if blocks were scanned (caller should call again),
/// `false` if the wallet is caught up (no pending scan ranges).
pub async fn sync_one_batch(
    name: &str,
    client: &mut LwdClient,
    params: ZNetwork,
    wallet_dir: &Path,
    db_cache: &mut FsBlockDb,
    db_data: &mut WriteDb,
) -> anyhow::Result<bool> {
    let scan_ranges = db_data.suggest_scan_ranges()?;
    let Some(first) = scan_ranges.first() else {
        return Ok(false);
    };

    // A Verify range is small; scan it whole. Otherwise scan the first BATCH_SIZE chunk.
    let scan_range = if first.priority() == ScanPriority::Verify {
        first.clone()
    } else {
        match first.split_at(first.block_range().start + BATCH_SIZE) {
            Some((cur, _)) => cur,
            None => first.clone(),
        }
    };

    info!("[{name}] syncing {scan_range}");

    // Download compact blocks for this range.
    let block_meta = download_blocks(client, wallet_dir, db_cache, &scan_range).await?;

    // Fetch the prior block's chain state and scan.
    let result: anyhow::Result<()> = async {
        let start = u32::from(scan_range.block_range().start);
        // `scan_cached_blocks` asserts `from_height == from_state.block_height + 1`.
        // We must fetch the tree state at `start - 1` so that the chain state's
        // block height is exactly `start - 1`. The previous `.max(1)` clamping
        // broke this invariant when `start <= 1`, causing a panic.
        //
        // `start == 0` (scanning from genesis) has no prior block to anchor
        // against, so it is rejected explicitly. `start == 1` correctly
        // requests tree state at height 0 (the genesis block, whose commitment
        // trees are empty).
        if start == 0 {
            anyhow::bail!("cannot scan from genesis (height 0): no prior chain state exists");
        }
        let prior_height = BlockHeight::from(start - 1);

        let tree_state = client
            .get_tree_state(u32::from(prior_height) as u64)
            .await?;
        let chain_state = tree_state.to_chain_state()?;

        // We run on a LocalSet (WalletDb is !Send), so block_in_place is
        // unavailable. Call the CPU-bound scan directly.
        scan_or_rewind(
            name,
            params,
            db_cache,
            db_data,
            scan_range.block_range().start,
            &chain_state,
            scan_range.len(),
        )?;
        Ok(())
    }
    .await;

    // Clean up the cache regardless of success or failure.
    delete_cached_blocks(name, wallet_dir, db_cache, &block_meta);
    result?;

    Ok(true)
}

/// Scan cached blocks, recovering in place when librustzcash reports that the
/// compact-block `prev_hash` disagrees with wallet history. Detection belongs
/// to `scan_cached_blocks`; choosing a rewind depth and clearing the cache is
/// application policy, copied from zecd's bounded one-batch sync engine.
fn scan_or_rewind(
    name: &str,
    params: ZNetwork,
    db_cache: &mut FsBlockDb,
    db_data: &mut WriteDb,
    start: BlockHeight,
    chain_state: &zcash_client_backend::data_api::chain::ChainState,
    limit: usize,
) -> anyhow::Result<()> {
    match scan_cached_blocks(&params, db_cache, db_data, start, chain_state, limit) {
        Ok(_) => Ok(()),
        Err(ChainError::Scan(error)) if error.is_continuity_error() => {
            let requested = error.at_height().saturating_sub(10);
            let rewind_height = rewind_wallet(db_data, error.at_height(), requested)?;
            info!(
                "[{name}] chain reorg detected at {}; rewound wallet to {rewind_height}",
                error.at_height()
            );
            db_cache
                .truncate_to_height(rewind_height)
                .map_err(|e| anyhow!("truncating compact-block cache after reorg: {e:?}"))?;
            Ok(())
        }
        Err(error) => Err(anyhow!("scan error: {error:?}")),
    }
}

/// Rewind to the requested depth, falling back to just below the conflicting
/// block when the first requested point lacks a valid commitment-tree
/// checkpoint. The second failure is an explicit unrecoverable-reorg error
/// instead of an infinite retry loop.
fn rewind_wallet(
    db_data: &mut WriteDb,
    at_height: BlockHeight,
    requested: BlockHeight,
) -> anyhow::Result<BlockHeight> {
    match db_data.truncate_to_height(requested) {
        Ok(height) => Ok(height),
        Err(SqliteClientError::RequestedRewindInvalid { .. }) => {
            let shallow = at_height.saturating_sub(2);
            match db_data.truncate_to_height(shallow) {
                Ok(height) => Ok(height),
                Err(SqliteClientError::RequestedRewindInvalid { .. }) => anyhow::bail!(
                    "unrecoverable reorg at {at_height}: no valid wallet checkpoint exists below the conflict"
                ),
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error.into()),
    }
}

/// Download compact blocks for a scan range and write them to the block cache.
async fn download_blocks(
    client: &mut LwdClient,
    wallet_dir: &Path,
    db_cache: &mut FsBlockDb,
    scan_range: &ScanRange,
) -> anyhow::Result<Vec<BlockMeta>> {
    // Guard against an empty scan range: `end - 1` would underflow when
    // `end == 0`, and there are no blocks to download anyway.
    if scan_range.is_empty() {
        return Ok(vec![]);
    }
    let start = u32::from(scan_range.block_range().start);
    // Safe: `is_empty()` is false, so `end > start >= 0`, meaning `end >= 1`.
    let end = u32::from(scan_range.block_range().end) - 1; // inclusive

    let mut stream = client.get_block_range(start as u64, end as u64).await?;
    let mut block_meta = vec![];

    while let Some(block) = stream.message().await? {
        let (sapling_outputs_count, orchard_actions_count) = block
            .vtx
            .iter()
            .map(|tx| (tx.outputs.len() as u32, tx.actions.len() as u32))
            .fold((0, 0), |(acc_s, acc_o), (s, o)| (acc_s + s, acc_o + o));

        let meta = BlockMeta {
            height: block.height(),
            block_hash: block.hash(),
            block_time: block.time,
            sapling_outputs_count,
            orchard_actions_count,
        };

        let encoded = block.encode_to_vec();
        let mut block_file = File::create(block_path(wallet_dir, &meta)).await?;
        block_file.write_all(&encoded).await?;
        block_meta.push(meta);
    }

    db_cache
        .write_block_metadata(&block_meta)
        .map_err(|e| anyhow!("{e:?}"))?;
    Ok(block_meta)
}

/// Remove a just-scanned batch's cached compact-block files and metadata rows.
fn delete_cached_blocks(
    name: &str,
    wallet_dir: &Path,
    db_cache: &mut FsBlockDb,
    block_meta: &[BlockMeta],
) {
    let lowest = block_meta.iter().map(|m| m.height).min();
    for meta in block_meta {
        if let Err(e) = std::fs::remove_file(block_path(wallet_dir, meta)) {
            warn!("[{name}] failed to remove cached block {:?}: {e}", meta);
        }
    }
    if let Some(lowest) = lowest {
        let truncate_to = BlockHeight::from(u32::from(lowest).saturating_sub(1));
        if let Err(e) = db_cache.truncate_to_height(truncate_to) {
            warn!("[{name}] failed to truncate block cache to {truncate_to}: {e:?}");
        }
    }
}
