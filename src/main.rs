//! ZVS - Zcash Verification Service
//!
//! Streams mempool transactions and logs verification requests in real-time.

use std::env;
use std::path::PathBuf;

use anyhow::Result;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;

mod memo_rules;
mod scan;
mod sync;
mod wallet;

use wallet::Wallet;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    dotenvy::dotenv().ok();

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let url = env::var("LIGHTWALLETD_URL").expect("LIGHTWALLETD_URL required");
    let seed_hex = env::var("SEED_HEX").expect("SEED_HEX required");
    let birthday_height: u32 = env::var("BIRTHDAY_HEIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let data_dir = env::var("ZVS_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./zvs_data"));

    let seed = hex::decode(&seed_hex)?;

    println!("ZVS - Zcash Verification Service");
    println!("=================================");
    println!("Lightwalletd: {}", url);
    println!("Birthday height: {}", birthday_height);
    println!("Mode: Mempool streaming (real-time)");
    println!();

    // Connect to lightwalletd
    info!("Connecting to lightwalletd at {}", url);
    let mut client = CompactTxStreamerClient::connect(url.clone()).await?;

    // Fetch birthday for wallet initialization (only needed if wallet.db doesn't exist)
    let birthday = sync::fetch_birthday(&mut client, birthday_height).await?;

    // Create wallet
    let wallet = Wallet::new(&seed, Some(&birthday), &data_dir)?;

    match wallet.get_address() {
        Ok(address) => println!("Wallet address: {}", address),
        Err(e) => println!("Could not get address: {}", e),
    }

    match wallet.get_balance() {
        Ok(balance) => {
            let total_zats = u64::from(balance.total);
            let total_zec = total_zats as f64 / 100_000_000.0;
            println!("Balance: {:.8} ZEC ({} zats)", total_zec, total_zats);
        }
        Err(_) => println!("Balance: (wallet not synced yet)"),
    }
    println!();

    println!("Starting ZVS mempool service...");
    println!("Press Ctrl+C to stop");
    println!();

    tokio::select! {
        result = run_mempool_service(&mut client, &wallet) => {
            if let Err(e) = result {
                eprintln!("Service error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutting down...");
        }
    }

    Ok(())
}

/// Run the mempool streaming service.
async fn run_mempool_service(
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    wallet: &Wallet,
) -> Result<()> {
    info!("Starting mempool streaming service");

    loop {
        info!("Connecting to mempool stream...");

        let result = scan::stream_mempool(client, |tx, height| {
            // Decrypt memo using wallet
            if let Some(memo) = wallet.decrypt_memo(&tx, height) {
                info!(
                    "Verification request: {} (value={} zats, tx={})",
                    memo.memo_text,
                    u64::from(memo.value),
                    hex::encode(memo.txid.as_ref())
                );
            }
            async { Ok(()) }
        })
        .await;

        match result {
            Ok(()) => {
                info!("Mempool stream closed, reconnecting in 500ms...");
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
            Err(e) => {
                error!("Mempool stream error: {}", e);
                warn!("Reconnecting in 30s...");
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            }
        }
    }
}
