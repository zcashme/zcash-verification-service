//! The lightwalletd gRPC client.
//!
//! A thin wrapper around `zcash_client_backend::proto::service::CompactTxStreamerClient`
//! that connects to a lightwalletd (or Zaino) gRPC endpoint. Both servers
//! serve the same `CompactTxStreamer` proto, so the backend is selected by the
//! configured URL — no code change is needed to switch between them.
//!
//! The five RPCs ZFA uses:
//!
//! | RPC | ZFA role |
//! |-----|----------|
//! | `GetMempoolStream` | **Primary auth path** — watch for auth payments |
//! | `GetLatestBlock` | Chain tip for consensus branch ID |
//! | `GetBlockRange` | Sync confirmed blocks (recovery) |
//! | `GetTreeState` | Birthday anchor / chain state |
//! | `SendTransaction` | Broadcast OTP response transaction |

use anyhow::Context;
use tracing::info;

use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{
    BlockId, BlockRange, ChainSpec, Empty, RawTransaction, TreeState,
};

/// A connected lightwalletd gRPC client.
///
/// Both lightwalletd and Zaino serve the same `CompactTxStreamer` gRPC API, so
/// this client works against either — the choice is made by the URL in config.
pub struct LwdClient {
    inner: CompactTxStreamerClient<tonic::transport::Channel>,
}

impl LwdClient {
    /// Connect to the lightwalletd/Zaino gRPC endpoint.
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let channel = tonic::transport::Channel::from_shared(url.to_string())
            .context("invalid gRPC URL")?
            .connect()
            .await
            .context("failed to connect to lightwalletd gRPC endpoint")?;
        info!("connected to lightwalletd gRPC: {url}");
        Ok(LwdClient {
            inner: CompactTxStreamerClient::new(channel),
        })
    }

    /// `GetLatestBlock` — returns the chain tip height and hash.
    pub async fn get_latest_block(&mut self) -> anyhow::Result<BlockId> {
        let resp = self
            .inner
            .get_latest_block(ChainSpec {})
            .await
            .context("GetLatestBlock failed")?;
        Ok(resp.into_inner())
    }

    /// `GetTreeState` — returns the note commitment tree state at a given height.
    pub async fn get_tree_state(&mut self, height: u64) -> anyhow::Result<TreeState> {
        let resp = self
            .inner
            .get_tree_state(BlockId {
                height,
                hash: vec![],
            })
            .await
            .context("GetTreeState failed")?;
        Ok(resp.into_inner())
    }

    /// `SendTransaction` — broadcasts a raw transaction. Returns the error
    /// code (0 = success) and message.
    pub async fn send_transaction(&mut self, data: Vec<u8>) -> anyhow::Result<(i32, String)> {
        let resp = self
            .inner
            .send_transaction(RawTransaction { data, height: 0 })
            .await
            .context("SendTransaction failed")?;
        let inner = resp.into_inner();
        Ok((inner.error_code, inner.error_message))
    }

    /// `GetMempoolStream` — opens the mempool stream. Returns a `Streaming<RawTransaction>`
    /// that yields current and new mempool transactions, and **closes when a new
    /// block is mined** (lightwalletd/Zaino contract). The caller must reconnect
    /// after the stream ends.
    pub async fn get_mempool_stream(
        &mut self,
    ) -> anyhow::Result<tonic::codec::Streaming<RawTransaction>> {
        let resp = self
            .inner
            .get_mempool_stream(Empty {})
            .await
            .context("GetMempoolStream failed")?;
        Ok(resp.into_inner())
    }

    /// `GetBlockRange` — streams compact blocks for a height range (inclusive
    /// of `end`). Used for confirmed-block sync / recovery.
    pub async fn get_block_range(
        &mut self,
        start: u64,
        end: u64,
    ) -> anyhow::Result<tonic::codec::Streaming<CompactBlock>> {
        let resp = self
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
        Ok(resp.into_inner())
    }
}
