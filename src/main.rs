//! ZVS - Zcash Verification Service

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

mod memo_rules;
mod otp_rules;
mod scan;
mod verification;
mod wallet;

use verification::{get_pending_requests, handle_memo};
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
    let poll_interval: u64 = env::var("POLL_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    let seed = hex::decode(&seed_hex)?;
    let otp_secret = hex::decode(&otp_secret_hex)?;

    println!("ZVS - Zcash Verification Service");
    println!("=================================");
    println!("Lightwalletd: {}", url);
    println!("Birthday height: {}", birthday_height);
    println!("Poll interval: {}s", poll_interval);
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

    // Show pending requests
    match wallet.get_all_memos().await {
        Ok(memos) => {
            let requests = get_pending_requests(&memos, &otp_secret);
            println!("Pending verification requests: {}", requests.len());
            for req in requests.iter().take(10) {
                println!("  - session: {}, OTP: {}, tx: {}", req.session_id, req.otp, req.txid_hex);
            }
            if requests.len() > 10 {
                println!("  ... and {} more", requests.len() - 10);
            }
        }
        Err(e) => println!("Could not fetch pending requests: {}", e),
    }
    println!();

    println!("Starting ZVS service...");
    println!("Press Ctrl+C to stop");
    println!();

    let poll_duration = Duration::from_secs(poll_interval);
    tokio::select! {
        result = run_service(&mut wallet, &otp_secret, poll_duration) => {
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

/// Run the verification service loop.
async fn run_service(
    wallet: &mut Wallet,
    otp_secret: &[u8],
    poll_interval: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting verification service with {:?} poll interval", poll_interval);

    // Initial sync
    let result = wallet.sync().await?;
    for memo in result.new_memos.iter() {
        handle_memo(wallet, memo, otp_secret).await;
    }

    let mut last_height = wallet.get_chain_height().await?;
    info!("Initial sync complete. Chain tip: {}", last_height);

    loop {
        tokio::time::sleep(poll_interval).await;

        match wallet.get_chain_height().await {
            Ok(current_height) => {
                if current_height > last_height {
                    info!("New blocks detected: {} -> {}", last_height, current_height);

                    match wallet.sync().await {
                        Ok(result) => {
                            if result.blocks_scanned > 0 {
                                info!(
                                    "Scanned {} blocks, {} new notes",
                                    result.blocks_scanned,
                                    result.sapling_notes_received + result.orchard_notes_received
                                );
                            }

                            for memo in result.new_memos.iter() {
                                handle_memo(wallet, memo, otp_secret).await;
                            }

                            last_height = current_height;
                        }
                        Err(e) => error!("Sync error: {}", e),
                    }
                } else {
                    debug!("No new blocks (height: {})", current_height);
                }
            }
            Err(e) => error!("Failed to get chain height: {}", e),
        }
    }
}
