//! Block sync + reorg recovery.
//!
//! Ported from zecd's `sync/engine.rs`, simplified for ZFA (no transparent,
//! no reorg retry, no enhancement). Downloads compact blocks from lightwalletd
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
    chain::scan_cached_blocks,
    scanning::{ScanPriority, ScanRange},
    WalletRead, WalletWrite,
};
use zcash_client_sqlite::chain::BlockMeta;
use zcash_client_sqlite::{FsBlockDb, FsBlockDbError};
use zcash_protocol::consensus::BlockHeight;

use crate::lwd::LwdClient;
use crate::network::ZNetwork;
use crate::wallet::open::{block_path, WriteDb};

const BATCH_SIZE: u32 = 10_000;

/// Outcome of one sync batch.
pub struct BatchOutcome {
    /// Whether a batch was scanned (caller should call again).
    pub worked: bool,
}

/// Process at most one batch of confirmed-block sync work.
///
/// Returns `worked = true` if blocks were scanned (caller should call again),
/// `false` if the wallet is caught up (no pending scan ranges).
pub async fn sync_one_batch(
    name: &str,
    client: &mut LwdClient,
    params: &ZNetwork,
    wallet_dir: &Path,
    db_cache: &mut FsBlockDb,
    db_data: &mut WriteDb,
) -> anyhow::Result<BatchOutcome> {
    let scan_ranges = db_data.suggest_scan_ranges()?;
    let Some(first) = scan_ranges.first() else {
        return Ok(BatchOutcome { worked: false });
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
    let block_meta = download_blocks(name, client, wallet_dir, db_cache, &scan_range).await?;

    // Fetch the prior block's chain state and scan.
    let result: anyhow::Result<()> = async {
        let start = u32::from(scan_range.block_range().start);
        let prior_height = BlockHeight::from(start.saturating_sub(1).max(1));

        let tree_state = client.get_tree_state(u32::from(prior_height) as u64).await?;
        let chain_state = tree_state.to_chain_state()?;

        tokio::task::block_in_place(|| {
            scan_cached_blocks(
                params,
                db_cache,
                db_data,
                scan_range.block_range().start,
                &chain_state,
                scan_range.len(),
            )
        }).map_err(|e| anyhow::anyhow!("scan error: {e:?}"))?;
        Ok(())
    }
    .await;

    // Clean up the cache regardless of success or failure.
    delete_cached_blocks(name, wallet_dir, db_cache, &block_meta);
    result?;

    Ok(BatchOutcome { worked: true })
}

/// Download compact blocks for a scan range and write them to the block cache.
async fn download_blocks(
    name: &str,
    client: &mut LwdClient,
    wallet_dir: &Path,
    db_cache: &mut FsBlockDb,
    scan_range: &ScanRange,
) -> anyhow::Result<Vec<BlockMeta>> {
    let start = u32::from(scan_range.block_range().start);
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
fn delete_cached_blocks(name: &str, wallet_dir: &Path, db_cache: &mut FsBlockDb, block_meta: &[BlockMeta]) {
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