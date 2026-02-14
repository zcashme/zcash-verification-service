//! Wallet synchronization with lightwalletd.

use anyhow::{anyhow, Result};
use tonic::transport::Channel;

use zcash_client_backend::{
    data_api::AccountBirthday,
    proto::service::{compact_tx_streamer_client::CompactTxStreamerClient, BlockId},
};

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
