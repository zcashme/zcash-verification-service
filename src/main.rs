//! ZVS - Zcash Verification Service
//!
//! Streams mempool transactions and responds to verification requests in real-time.

use std::env;
use std::path::PathBuf;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BlockHeight;

mod memo_rules;
mod otp_rules;
mod scan;
mod verification;
mod wallet;

use wallet::Wallet;

/// A transaction received from the mempool stream.
struct MempoolTx {
    tx: Transaction,
    height: BlockHeight,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    dotenvy::dotenv().ok();

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    let url = env::var("LIGHTWALLETD_URL").expect("LIGHTWALLETD_URL required");
    let seed_hex = env::var("SEED_HEX").expect("SEED_HEX required");
    let otp_secret_hex = env::var("OTP_SECRET").expect("OTP_SECRET required (hex-encoded)");
    let birthday_height: u32 = env::var("BIRTHDAY_HEIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let data_dir = env::var("ZVS_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./zvs_data"));

    let seed = hex::decode(&seed_hex)?;
    let otp_secret = hex::decode(&otp_secret_hex)?;

    println!("ZVS - Zcash Verification Service");
    println!("=================================");
    println!("Lightwalletd: {}", url);
    println!("Birthday height: {}", birthday_height);
    println!("Mode: Mempool streaming (real-time)");
    println!();

    let mut wallet = Wallet::new(&url, &seed, birthday_height, &data_dir).await?;

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
        result = run_mempool_service(&mut wallet, &otp_secret) => {
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
///
/// Uses a channel to decouple streaming from processing, avoiding borrow conflicts.
async fn run_mempool_service(
    wallet: &mut Wallet,
    otp_secret: &[u8],
) -> Result<()> {
    info!("Starting mempool streaming service");

    loop {
        info!("Connecting to mempool stream...");

        // Clone the client for the streaming task
        let mut stream_client = wallet.clone_client();

        // Channel for passing transactions from stream to processor
        let (tx_sender, mut tx_receiver) = mpsc::channel::<MempoolTx>(100);

        // Spawn the stream task
        let stream_handle = tokio::spawn(async move {
            scan::stream_mempool(&mut stream_client, |tx, height| {
                let sender = tx_sender.clone();
                async move {
                    if sender.send(MempoolTx { tx, height }).await.is_err() {
                        return Err(anyhow::anyhow!("Processor stopped"));
                    }
                    Ok(())
                }
            }).await
        });

        // Process transactions as they arrive
        while let Some(mempool_tx) = tx_receiver.recv().await {
            // Decrypt memo using wallet
            if let Some(memo) = wallet.decrypt_memo(&mempool_tx.tx, mempool_tx.height) {
                // Handle the verification request
                if let Err(e) = verification::handle_memo(wallet, &memo, otp_secret).await {
                    error!("Failed to handle memo: {}", e);
                }
            }
        }

        // Wait for stream task to finish
        let stream_result = stream_handle.await;

        match stream_result {
            Ok(Ok(())) => {
                info!("Mempool stream closed, reconnecting in 500ms...");
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
            Ok(Err(e)) => {
                error!("Mempool stream error: {}", e);
                warn!("Reconnecting in 30s...");
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            }
            Err(e) => {
                error!("Stream task panicked: {}", e);
                warn!("Reconnecting in 30s...");
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            }
        }
    }
}
