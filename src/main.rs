//! ZVS - Zcash Verification Service

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use tracing_subscriber::EnvFilter;

mod memo_rules;
mod otp_rules;
mod scan;
mod verification;
mod wallet;

use otp_rules::generate_otp;
use verification::VerificationService;

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

    let mut service = VerificationService::connect(
        &url,
        &seed,
        birthday_height,
        &data_dir,
        otp_secret.clone(),
    ).await?;

    match service.get_address() {
        Ok(address) => println!("Wallet address: {}", address),
        Err(e) => println!("Could not get address: {}", e),
    }

    match service.get_balance() {
        Ok(balance) => {
            let total_zec = balance.total as f64 / 100_000_000.0;
            println!("Balance: {:.8} ZEC ({} zats)", total_zec, balance.total);
        }
        Err(_) => println!("Balance: (wallet not synced yet)"),
    }
    println!();

    match service.get_received_memos().await {
        Ok(memos) => {
            let valid_requests: Vec<_> = memos.iter()
                .filter(|m| m.verification.is_some())
                .collect();

            println!("Received transactions: {} total, {} valid verification requests",
                     memos.len(), valid_requests.len());

            if !valid_requests.is_empty() {
                println!("\nPending verification requests:");
                for memo in valid_requests.iter().take(10) {
                    if let Some(ref v) = memo.verification {
                        let otp = generate_otp(&otp_secret, &v.session_id);
                        println!("  - session: {}, OTP: {}, tx: {}",
                                 v.session_id, otp, memo.txid_hex);
                    }
                }
                if valid_requests.len() > 10 {
                    println!("  ... and {} more", valid_requests.len() - 10);
                }
            }
        }
        Err(e) => println!("Could not fetch memos: {}", e),
    }
    println!();

    println!("Starting ZVS service...");
    println!("Press Ctrl+C to stop");
    println!();

    let poll_duration = Duration::from_secs(poll_interval);
    tokio::select! {
        result = service.run(poll_duration) => {
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
