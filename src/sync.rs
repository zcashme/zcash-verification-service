//! Wallet synchronization with lightwalletd.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tonic::transport::Channel;
use tracing::{debug, error, info};

use zcash_client_backend::{
    data_api::{
        chain::{BlockCache, BlockSource},
        scanning::ScanRange,
        wallet::decrypt_and_store_transaction,
        AccountBirthday, TransactionDataRequest, WalletRead,
    },
    proto::{
        compact_formats::CompactBlock,
        service::{compact_tx_streamer_client::CompactTxStreamerClient, BlockId, ChainSpec, TxFilter},
    },
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, MainNetwork};

use crate::wallet::Wallet;

// =============================================================================
// MemBlockCache - In-memory block cache for sync
// =============================================================================

/// In-memory block cache. Stores compact blocks in RAM during sync.
#[derive(Default)]
pub struct MemBlockCache(RwLock<BTreeMap<BlockHeight, CompactBlock>>);

impl MemBlockCache {
    pub fn new() -> Self {
        Default::default()
    }
}

impl BlockSource for MemBlockCache {
    type Error = Infallible;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), zcash_client_backend::data_api::chain::error::Error<WalletErrT, Self::Error>>
    where
        F: FnMut(
            CompactBlock,
        ) -> Result<
            (),
            zcash_client_backend::data_api::chain::error::Error<WalletErrT, Self::Error>,
        >,
    {
        let inner = self.0.read().unwrap();
        let block_iter = inner
            .iter()
            .filter(|(_, cb)| {
                if let Some(h) = from_height {
                    cb.height() >= h
                } else {
                    true
                }
            })
            .take(limit.unwrap_or(usize::MAX));

        for (_, cb) in block_iter {
            with_block(cb.clone())?;
        }
        Ok(())
    }
}

#[async_trait]
impl BlockCache for MemBlockCache {
    fn get_tip_height(
        &self,
        range: Option<&ScanRange>,
    ) -> Result<Option<BlockHeight>, Self::Error> {
        let inner = self.0.read().unwrap();
        if let Some(range) = range {
            let r = range.block_range();
            for h in (u32::from(r.start)..u32::from(r.end)).rev() {
                if inner.contains_key(&h.into()) {
                    return Ok(Some(h.into()));
                }
            }
            Ok(None)
        } else {
            Ok(inner.last_key_value().map(|(h, _)| *h))
        }
    }

    async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, Self::Error> {
        let inner = self.0.read().unwrap();
        let r = range.block_range();
        let mut blocks = Vec::with_capacity(range.len());
        for height in u32::from(r.start)..u32::from(r.end) {
            if let Some(cb) = inner.get(&height.into()) {
                blocks.push(cb.clone());
            }
        }
        Ok(blocks)
    }

    async fn insert(&self, compact_blocks: Vec<CompactBlock>) -> Result<(), Self::Error> {
        let mut inner = self.0.write().unwrap();
        for block in compact_blocks {
            inner.insert(block.height(), block);
        }
        Ok(())
    }

    async fn delete(&self, range: ScanRange) -> Result<(), Self::Error> {
        let mut inner = self.0.write().unwrap();
        let r = range.block_range();
        for height in u32::from(r.start)..u32::from(r.end) {
            inner.remove(&height.into());
        }
        Ok(())
    }

    async fn truncate(&self, height: BlockHeight) -> Result<(), Self::Error> {
        let mut inner = self.0.write().unwrap();
        inner.retain(|h, _| *h <= height);
        Ok(())
    }
}

// =============================================================================
// Birthday fetching
// =============================================================================

/// Fetch the account birthday from lightwalletd.
pub async fn fetch_birthday(
    client: &mut CompactTxStreamerClient<Channel>,
    birthday_height: u32,
) -> Result<AccountBirthday> {
    let request = BlockId {
        height: (birthday_height as u64).saturating_sub(1),
        ..Default::default()
    };

    let treestate = client
        .get_tree_state(request)
        .await
        .map_err(|e| anyhow!("Failed to fetch tree state: {}", e))?
        .into_inner();

    let birthday = AccountBirthday::from_treestate(treestate, None)
        .map_err(|_| anyhow!("Failed to parse tree state into AccountBirthday"))?;

    Ok(birthday)
}

// =============================================================================
// Wallet Sync
// =============================================================================

/// Sync the wallet with the blockchain.
///
/// Downloads compact blocks, scans for relevant transactions, and enhances
/// discovered transactions by fetching full tx data and decrypting memos.
///
/// Extracted from the former `Wallet::sync()` method so that all network I/O
/// lives outside `wallet.rs`.
pub async fn sync_wallet(
    client: &mut CompactTxStreamerClient<Channel>,
    wallet: &mut Wallet,
) -> Result<()> {
    let db_cache = MemBlockCache::new();

    info!("Starting wallet sync...");

    zcash_client_backend::sync::run(
        client,
        &MainNetwork,
        &db_cache,
        wallet.db_mut(),
        10_000, // batch size
    )
    .await
    .map_err(|e| anyhow!("Sync failed: {:?}", e))?;

    info!("Wallet sync complete, processing enhancement requests...");

    // Process transaction enhancement requests to fetch full transactions and decrypt memos
    let requests = wallet
        .db()
        .transaction_data_requests()
        .map_err(|e| anyhow!("Failed to get transaction data requests: {:?}", e))?;

    let mut enhanced_count = 0;
    for request in requests {
        if let TransactionDataRequest::Enhancement(txid) = request {
            debug!("Enhancing transaction: {}", hex::encode(txid.as_ref()));

            // Fetch full transaction from lightwalletd
            let response = client
                .get_transaction(TxFilter {
                    block: None,
                    index: 0,
                    hash: txid.as_ref().to_vec(),
                })
                .await
                .map_err(|e| {
                    anyhow!(
                        "Failed to fetch transaction {}: {:?}",
                        hex::encode(txid.as_ref()),
                        e
                    )
                })?;

            let raw_tx = response.into_inner();

            // Get the mined height for this transaction
            let mined_height = wallet
                .db()
                .get_tx_height(txid)
                .map_err(|e| anyhow!("Failed to get tx height: {:?}", e))?;

            // Determine the branch ID for parsing
            let branch_id = mined_height
                .map(|h| BranchId::for_height(&MainNetwork, h))
                .unwrap_or(BranchId::Nu5);

            // Parse the transaction
            let tx = Transaction::read(&raw_tx.data[..], branch_id)
                .map_err(|e| anyhow!("Failed to parse transaction: {:?}", e))?;

            // Decrypt and store the transaction (this updates memos in the DB)
            decrypt_and_store_transaction(&MainNetwork, wallet.db_mut(), &tx, mined_height)
                .map_err(|e| anyhow!("Failed to decrypt and store transaction: {:?}", e))?;

            enhanced_count += 1;
        }
    }

    if enhanced_count > 0 {
        info!(
            "Enhanced {} transactions with full memo data",
            enhanced_count
        );
    }

    Ok(())
}

/// Background sync loop. Runs forever, syncing the wallet periodically.
///
/// Checks chain height, and syncs when new blocks are available.
/// Logs errors and continues — never returns under normal operation.
pub async fn run_sync_loop(
    mut client: CompactTxStreamerClient<Channel>,
    wallet: Arc<tokio::sync::Mutex<Wallet>>,
    sync_interval_secs: u64,
) -> ! {
    let mut last_synced_height: u32 = {
        let w = wallet.lock().await;
        w.get_synced_height().unwrap_or(0)
    };

    let mut interval = tokio::time::interval(Duration::from_secs(sync_interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        // Check chain height
        let chain_height = match client.get_latest_block(ChainSpec {}).await {
            Ok(resp) => resp.into_inner().height as u32,
            Err(e) => {
                error!("Failed to get chain height: {}", e);
                continue;
            }
        };

        if chain_height <= last_synced_height {
            continue;
        }

        info!(
            "Chain at {}, last sync at {} (+{} blocks). Syncing...",
            chain_height,
            last_synced_height,
            chain_height - last_synced_height
        );

        let mut w = wallet.lock().await;
        match sync_wallet(&mut client, &mut w).await {
            Ok(()) => {
                last_synced_height = chain_height;
                match w.get_balance() {
                    Ok(b) => info!(
                        "Sync complete @ {}. Balance: {} spendable (S={}, O={})",
                        chain_height,
                        u64::from(b.spendable),
                        u64::from(b.sapling_spendable),
                        u64::from(b.orchard_spendable)
                    ),
                    Err(_) => info!("Sync complete @ {}", chain_height),
                }
            }
            Err(e) => {
                error!("Background sync failed: {}", e);
            }
        }
    }
}
