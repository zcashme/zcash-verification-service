use anyhow::{anyhow, Result};
use serde::Serialize;
use tracing::{debug, error, info};

// =============================================================================
// Types
// =============================================================================

/// A wallet transaction row for Supabase.
#[derive(Debug, Clone, Serialize)]
pub struct WalletRow {
    pub txid: String,
    pub amount_zats: i64,
    pub memo: Option<String>,
    pub pool: String,
    pub block_height: Option<u32>,
    pub block_time: Option<i64>,
    pub status: String,
    pub detected_at: String,
}

// =============================================================================
// Client
// =============================================================================

/// Supabase REST client for the `wallet` table.
///
/// Uses PostgREST's upsert via `Prefer: resolution=merge-duplicates`.
/// The `wallet` table must have a UNIQUE constraint on `txid`.
pub struct SupabaseClient {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
    service_key: String,
}

impl SupabaseClient {
    pub fn new(project_url: &str, api_key: &str, service_key: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: format!("{}/rest/v1/wallet?on_conflict=txid", project_url.trim_end_matches('/')),
            api_key: api_key.to_string(),
            service_key: service_key.to_string(),
        }
    }

    /// Upsert a single transaction row.
    pub async fn upsert(&self, row: &WalletRow) -> Result<()> {
        let response = self
            .client
            .post(&self.base_url)
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", &self.service_key))
            .header("Content-Type", "application/json")
            .header("Prefer", "resolution=merge-duplicates")
            .json(row)
            .send()
            .await
            .map_err(|e| anyhow!("Supabase request failed: {}", e))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            error!("Supabase upsert failed ({}): {}", status, body);
            return Err(anyhow!("Supabase upsert failed: {} {}", status, body));
        }

        debug!("Upserted tx {}", row.txid);
        Ok(())
    }

    /// Upsert a batch of transaction rows.
    pub async fn upsert_batch(&self, rows: &[WalletRow]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }

        let response = self
            .client
            .post(&self.base_url)
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", &self.service_key))
            .header("Content-Type", "application/json")
            .header("Prefer", "resolution=merge-duplicates")
            .json(rows)
            .send()
            .await
            .map_err(|e| anyhow!("Supabase batch request failed: {}", e))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            error!("Supabase batch upsert failed ({}): {}", status, body);
            return Err(anyhow!("Supabase batch upsert failed: {} {}", status, body));
        }

        info!("Upserted {} transactions to Supabase", rows.len());
        Ok(())
    }
}
