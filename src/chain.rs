//! Compile-time selected chain source adapter.

use std::time::Duration;

use anyhow::Context;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::{BlockId, RawTransaction, TreeState};

/// The single chain client used by wallet initialization, sync, and the actor.
/// Its transport is selected at compile time by the `lwd` or `zebra-indexer`
/// Cargo feature.
pub struct ChainClient {
    #[cfg(feature = "lwd")]
    inner: zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient<
        tonic::transport::Channel,
    >,

    // The selected backend's client is stored directly here, keeping one public
    // ChainClient API while avoiding runtime backend selection.
    #[cfg(feature = "zebra-indexer")]
    inner: zebra_indexer_proto::ZebraClient,
}

#[cfg(feature = "lwd")]
impl ChainClient {
    /// Connect to the configured lightwalletd gRPC endpoint.
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
        use tonic::transport::{Channel, ClientTlsConfig};

        let endpoint = Channel::from_shared(url.to_string()).context("invalid lightwalletd URL")?;
        let endpoint = if url.starts_with("https://") {
            endpoint
                .tls_config(ClientTlsConfig::new().with_native_roots())
                .context("configuring lightwalletd TLS")?
        } else {
            endpoint
        };

        let channel = endpoint
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(20))
            .keep_alive_while_idle(true)
            .connect()
            .await
            .context("connecting to lightwalletd")?;

        Ok(Self {
            inner: CompactTxStreamerClient::new(channel),
        })
    }

    pub async fn get_latest_block(&mut self) -> anyhow::Result<BlockId> {
        use zcash_client_backend::proto::service::ChainSpec;

        self.inner
            .get_latest_block(ChainSpec {})
            .await
            .context("GetLatestBlock failed")
            .map(tonic::Response::into_inner)
    }

    pub async fn get_tree_state(&mut self, height: u64) -> anyhow::Result<TreeState> {
        self.inner
            .get_tree_state(BlockId {
                height,
                hash: vec![],
            })
            .await
            .context("GetTreeState failed")
            .map(tonic::Response::into_inner)
    }

    pub async fn get_block_range(
        &mut self,
        start: u64,
        end: u64,
    ) -> anyhow::Result<tonic::codec::Streaming<CompactBlock>> {
        use zcash_client_backend::proto::service::BlockRange;

        let response = self
            .inner
            .get_block_range(BlockRange {
                start: Some(BlockId {
                    height: start,
                    hash: vec![],
                }),
                end: Some(BlockId {
                    height: end,
                    hash: vec![],
                }),
                pool_types: vec![],
            })
            .await
            .context("GetBlockRange failed")?;
        Ok(response.into_inner())
    }

    pub async fn get_mempool_stream(
        &mut self,
    ) -> anyhow::Result<tonic::codec::Streaming<RawTransaction>> {
        self.inner
            .get_mempool_stream(zcash_client_backend::proto::service::Empty {})
            .await
            .context("GetMempoolStream failed")
            .map(tonic::Response::into_inner)
    }

    pub async fn send_transaction(&mut self, data: Vec<u8>) -> anyhow::Result<(i32, String)> {
        let response = self
            .inner
            .send_transaction(RawTransaction { data, height: 0 })
            .await
            .context("SendTransaction failed")?
            .into_inner();
        Ok((response.error_code, response.error_message))
    }
}
