//! Chain source adapter — trait implementations for `lwd` and `zebra-indexer`.

use async_trait::async_trait;
use anyhow::Context;
use zcash_client_backend::proto::service::{
    BlockId, RawTransaction, TreeState,
};
use zcash_client_backend::proto::compact_formats::CompactBlock;

/// Shared chain-source adapter (LWD / zebra-indexer).
#[async_trait]
pub trait ChainClient: Send + Sync {
    async fn get_latest_block(&mut self) -> anyhow::Result<BlockId>;
    async fn get_tree_state(&mut self, height: u64) -> anyhow::Result<TreeState>;
    async fn get_block_range(&mut self, start: u64, end: u64) -> anyhow::Result<tonic::codec::Streaming<CompactBlock>>;
    async fn get_mempool_stream(&mut self) -> anyhow::Result<tonic::codec::Streaming<RawTransaction>>;
    async fn send_transaction(&mut self, data: Vec<u8>) -> anyhow::Result<(i32, String)>;
}

#[cfg(feature = "lwd")]
mod lwd_adapter {
    use super::*;
    use std::time::Duration;
    use tracing::info;
    use zcash_client_backend::proto::service::{
        BlockRange, ChainSpec, Empty,
    };
    use tonic::transport::{Channel, ClientTlsConfig};

    pub struct LwdAdapter {
        inner: zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient<tonic::transport::Channel>,
    }

    #[async_trait]
    impl ChainClient for LwdAdapter {
        async fn connect(url: &str) -> anyhow::Result<Self> {
            let endpoint = tonic::transport::Channel::from_shared(url.to_string()).context("invalid gRPC URL")?;
            let endpoint = if url.starts_with("https://") {
                endpoint.tls_config(ClientTlsConfig::new().with_native_roots()).context("TLS config")?
            } else { endpoint };
            let endpoint = endpoint.http2_keep_alive_interval(Duration::from_secs(30)).keep_alive_timeout(Duration::from_secs(20)).keep_alive_while_idle(true);
            let channel = endpoint.connect().await.context("failed to connect")?;
            Ok(LwdAdapter { inner: zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::new(channel) })
        }
        async fn get_latest_block(&mut self) -> anyhow::Result<BlockId> {
            let resp = self.inner.get_latest_block(ChainSpec {}).await.context("GetLatestBlock failed")?;
            Ok(resp.into_inner())
        }
        async fn get_tree_state(&mut self, height: u64) -> anyhow::Result<TreeState> {
            let resp = self.inner.get_tree_state(BlockId { height, hash: vec![] }).await.context("GetTreeState failed")?;
            Ok(resp.into_inner())
        }
        async fn get_block_range(&mut self, start: u64, end: u64) -> anyhow::Result<tonic::codec::Streaming<CompactBlock>> {
            let resp = self.inner.get_block_range(BlockRange { start: Some(BlockId { height: start, hash: vec![] }), end: Some(BlockId { height: end, hash: vec![] }), pool_types: vec![] }).await.context("GetBlockRange failed")?;
            Ok(resp.into_inner())
        }
        async fn get_mempool_stream(&mut self) -> anyhow::Result<tonic::codec::Streaming<RawTransaction>> {
            let resp = self.inner.get_mempool_stream(Empty {}).await.context("GetMempoolStream failed")?;
            Ok(resp.into_inner())
        }
        async fn send_transaction(&mut self, data: Vec<u8>) -> anyhow::Result<(i32, String)> {
            let resp = self.inner.send_transaction(zcash_client_backend::proto::service::RawTransaction { data, height: 0 }).await.context("SendTransaction failed")?;
            let inner = resp.into_inner();
            Ok((inner.error_code, inner.error_message))
        }
    }
}

/// Factory: connect to chain source (LWD or zebra-indexer) and return adapter.
#[cfg(feature = "lwd")]
pub async fn connect_lwd(url: &str) -> anyhow::Result<Box<dyn ChainClient>> {
    use crate::chain::lwd_adapter::LwdAdapter;
    let adapter = LwdAdapter::connect(url).await?;
    Ok(Box::new(adapter))
}
