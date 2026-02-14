//! Wallet synchronization with lightwalletd.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::RwLock;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tonic::transport::Channel;

use zcash_client_backend::{
    data_api::{
        chain::{BlockCache, BlockSource},
        scanning::ScanRange,
        AccountBirthday,
    },
    proto::{
        compact_formats::CompactBlock,
        service::{compact_tx_streamer_client::CompactTxStreamerClient, BlockId},
    },
};
use zcash_protocol::consensus::BlockHeight;

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
    fn get_tip_height(&self, range: Option<&ScanRange>) -> Result<Option<BlockHeight>, Self::Error> {
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
