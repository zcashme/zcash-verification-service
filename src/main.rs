//! ZVS - Zcash Verification Service
//!
//! Streams mempool transactions and responds to verification requests in real-time.

use std::env;
use std::path::PathBuf;

use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

mod memo_rules;
mod otp_rules;
mod scan;
mod verification;
mod wallet;

use verification::handle_memo;
use wallet::Wallet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // ZVS owns the wallet directly
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
/// Connects to GetMempoolStream and processes transactions in real-time.
/// Reconnects automatically when the stream closes (on new block).
async fn run_mempool_service(
    wallet: &mut Wallet,
    otp_secret: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting mempool streaming service");

    loop {
        info!("Connecting to mempool stream...");

        match wallet.stream_mempool(otp_secret, |wallet, memo| {
            Box::pin(handle_memo(wallet, memo, otp_secret))
        }).await {
            Ok(()) => {
                // Stream closed normally (new block mined)
                info!("Mempool stream closed, reconnecting in 500ms...");
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
            Err(e) => {
                // Stream error - use longer backoff
                error!("Mempool stream error: {}", e);
                warn!("Reconnecting in 30s...");
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            }
        }
    }
}
