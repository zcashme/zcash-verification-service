//! Chain source adapter.
use zcash_client_backend::proto::service::{BlockId, RawTransaction, TreeState};
use zcash_client_backend::proto::compact_formats::CompactBlock;

/// Concrete chain client.
pub struct ChainClient;

#[cfg(feature = "lwd")]
impl ChainClient {
    pub async fn connect(url: &str) -> anyhow::Result<Self> { Ok(ChainClient) }
    pub async fn get_latest_block(&self) -> anyhow::Result<BlockId> { anyhow::bail!("not restored") }
    pub async fn get_tree_state(&self, _h: u64) -> anyhow::Result<TreeState> { anyhow::bail!("not restored") }
    pub async fn get_block_range(&self, _s: u64, _e: u64) -> anyhow::Result<tonic::codec::Streaming<CompactBlock>> { anyhow::bail!("not restored") }
    pub async fn get_mempool_stream(&self) -> anyhow::Result<tonic::codec::Streaming<RawTransaction>> { anyhow::bail!("not restored") }
    pub async fn send_transaction(&self, _d: Vec<u8>) -> anyhow::Result<(i32, String)> { anyhow::bail!("not restored") }
}

