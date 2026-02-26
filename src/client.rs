//! gRPC client connection to lightwalletd.

use anyhow::Result;
use tonic::transport::Channel;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;

/// Connect to a lightwalletd instance.
///
/// The returned client wraps a tonic `Channel` which is cheap to clone.
/// Both the sync and mempool tasks should use their own clone.
pub async fn connect(url: &str) -> Result<CompactTxStreamerClient<Channel>> {
    let client = CompactTxStreamerClient::connect(url.to_string()).await?;
    Ok(client)
}
