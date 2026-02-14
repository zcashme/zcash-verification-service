//! Mempool streaming client for ZVS.
//!
//! This module connects to lightwalletd's GetMempoolStream and yields
//! parsed transactions. It does NOT handle decryption - that's wallet's job.

use anyhow::{anyhow, Result};
use tonic::transport::Channel;
use tracing::{debug, info, warn};

use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, Empty,
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, MainNetwork};

/// Stream mempool transactions from lightwalletd.
///
/// Connects to GetMempoolStream and calls the handler for each parsed transaction.
/// Returns Ok(()) when the stream closes normally (new block mined).
/// Returns Err on connection or parsing errors.
///
/// # Parameters
/// - `client`: The gRPC client connected to lightwalletd
/// - `handler`: Called for each successfully parsed transaction
pub async fn stream_mempool<F, Fut>(
    client: &mut CompactTxStreamerClient<Channel>,
    mut handler: F,
) -> Result<()>
where
    F: FnMut(Transaction, BlockHeight) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    info!("Connecting to mempool stream...");

    let response = client
        .get_mempool_stream(Empty {})
        .await
        .map_err(|e| anyhow!("Failed to connect to mempool stream: {}", e))?;

    let mut stream = response.into_inner();

    info!("Connected to mempool stream");

    loop {
        match stream.message().await {
            Ok(Some(raw_tx)) => {
                // Parse the raw transaction
                let height = if raw_tx.height == 0 {
                    // Mempool transactions have height 0, use a recent height for branch ID
                    // This is safe because we only need it for transaction parsing
                    BlockHeight::from_u32(2_600_000)
                } else {
                    BlockHeight::from_u32(raw_tx.height as u32)
                };

                let branch_id = BranchId::for_height(&MainNetwork, height);

                match Transaction::read(&raw_tx.data[..], branch_id) {
                    Ok(tx) => {
                        let txid = tx.txid();
                        debug!("Received mempool tx: {}", hex::encode(txid.as_ref()));

                        if let Err(e) = handler(tx, height).await {
                            warn!("Handler error for tx {}: {}", hex::encode(txid.as_ref()), e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse mempool transaction: {}", e);
                    }
                }
            }
            Ok(None) => {
                // Stream closed normally (new block mined)
                info!("Mempool stream closed (new block)");
                return Ok(());
            }
            Err(e) => {
                return Err(anyhow!("Mempool stream error: {}", e));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests would require a mock gRPC server
}
