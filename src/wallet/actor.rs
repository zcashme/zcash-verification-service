//! The single-writer actor: the sole owner/writer of the wallet DB, running
//! the sync loop and the mempool watcher.
//!
//! Ported from zecd's `wallet/actor.rs`, stripped to ZFA's needs and extended
//! with session authentication. The actor's main loop:
//!
//! 1. Connect to lightwalletd gRPC.
//! 2. Sync confirmed blocks (recover wallet state — the source of truth).
//! 3. Open `GetMempoolStream`.
//! 4. For each raw transaction: parse → decrypt → extract memo → authenticate
//!    session in zfa.db.
//! 5. When the stream closes (new block mined) → sync → reopen stream.
//! 6. On network failure → reconnect with bounded backoff.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use tokio::sync::watch;
use tracing::{error, info, warn};

use zcash_client_backend::data_api::wallet::decrypt_and_store_transaction;
use zcash_client_backend::data_api::{Account, WalletRead, WalletWrite};
use zcash_client_sqlite::FsBlockDb;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::TxId;

use crate::backoff::Backoff;
use crate::config::AppConfig;
use crate::lwd::LwdClient;
use crate::memo;
use crate::network::ZNetwork;
use crate::session;
use crate::wallet::keys::{self, SeedKeeper};
use crate::wallet::open::{self, WriteDb};
use crate::wallet::store::WalletStore;

/// Parameters needed to launch the wallet actor.
pub struct ActorConfig {
    pub network: ZNetwork,
    pub wallet_dir: PathBuf,
    pub keys_path: PathBuf,
    pub lwd_url: String,
    pub session_ttl_secs: u64,
    pub sync_interval: Duration,
    pub connect_timeout: Duration,
    pub reconnect_base: Duration,
    pub reconnect_max: Duration,
    pub age_identity: Option<PathBuf>,
    pub zfa_db_path: PathBuf,
    pub shutdown: watch::Receiver<bool>,
}

/// Spawn the wallet actor task. Returns a join handle awaited at shutdown.
pub async fn spawn(cfg: ActorConfig) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let mut db_data = open::init_dbs(cfg.network, &cfg.wallet_dir)?;
    let db_cache = open::open_fsblockdb(&cfg.wallet_dir)?;

    let store = WalletStore::read(&cfg.keys_path)?;

    // Load the seed (auto-unlock with age identity).
    let mut seed = SeedKeeper::locked();
    if store.has_seed() && !store.is_encrypted() {
        if let Some(identity_path) = &cfg.age_identity {
            match keys::decrypt_seed_with_identity(&store, identity_path) {
                Ok(Some(s)) => {
                    seed.set(s);
                    info!("auto-unlocked wallet seed at startup");
                }
                Ok(None) => warn!("keys.toml has no mnemonic"),
                Err(e) => warn!("could not decrypt seed at startup: {e}"),
            }
        } else {
            warn!("no age identity configured; OTP sending will fail");
        }
    } else if store.is_encrypted() {
        warn!("wallet is passphrase-encrypted; manual unlock not yet implemented");
    }

    // Resolve the account (create if needed — bootstrap from seed).
    let account_id = match ensure_account(&mut db_data, &cfg, &seed, &store) {
        Ok(id) => Some(id),
        Err(e) => {
            warn!("could not resolve wallet account: {e}");
            None
        }
    };

    let ufvk = account_id
        .and_then(|id| db_data.get_account(id).ok().flatten().and_then(|a| a.ufvk().cloned()));

    let actor = WalletActor {
        network: cfg.network,
        wallet_dir: cfg.wallet_dir,
        db_data,
        db_cache,
        seed,
        ufvk,
        lwd_url: cfg.lwd_url,
        client: None,
        tip_height: None,
        backoff: Backoff::new(cfg.reconnect_base, cfg.reconnect_max),
        sync_interval: cfg.sync_interval,
        connect_timeout: cfg.connect_timeout,
        zfa_db_path: cfg.zfa_db_path,
        shutdown: cfg.shutdown,
    };

    Ok(tokio::spawn(actor.run()))
}

/// Try to select the wallet's account, or bootstrap one from the seed.
fn ensure_account(
    db: &mut WriteDb,
    cfg: &ActorConfig,
    seed: &SeedKeeper,
    store: &WalletStore,
) -> anyhow::Result<zcash_client_sqlite::AccountUuid> {
    let ids = db.get_account_ids()?;
    if let Some(id) = ids.first().copied() {
        return Ok(id);
    }

    let Some(seed_bytes) = seed.clone_seed() else {
        return Err(anyhow::anyhow!(
            "wallet has no account and seed is not loaded; \
             provide an age identity or unlock"
        ));
    };

    let birthday_height = store.birthday;
    let prior = u32::from(birthday_height).saturating_sub(1).max(1);

    let birthday = {
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| anyhow::anyhow!("no tokio runtime for bootstrap"))?;

        let mut client = tokio::task::block_in_place(|| {
            handle.block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(30),
                    LwdClient::connect(&cfg.lwd_url),
                )
                .await
            })
        })
        .map_err(|_| anyhow::anyhow!("timed out connecting to lightwalletd for bootstrap"))??;

        let tree_state = tokio::task::block_in_place(|| {
            handle.block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(30),
                    client.get_tree_state(u64::from(prior)),
                )
                .await
            })
        })
        .map_err(|_| anyhow::anyhow!("timed out fetching tree state for bootstrap"))??;

        zcash_client_backend::data_api::AccountBirthday::from_treestate(tree_state, None)
            .map_err(|_| anyhow::anyhow!("failed to derive account birthday from tree state"))?
    };

    let (id, _usk) = db
        .create_account("primary", &seed_bytes, &birthday, None)
        .context("creating wallet account from seed")?;
    info!(
        "bootstrapped wallet account from seed at birthday {}",
        u32::from(birthday_height)
    );
    Ok(id)
}

struct WalletActor {
    network: ZNetwork,
    wallet_dir: PathBuf,
    db_data: WriteDb,
    db_cache: FsBlockDb,
    seed: SeedKeeper,
    ufvk: Option<zcash_keys::keys::UnifiedFullViewingKey>,
    lwd_url: String,
    client: Option<LwdClient>,
    tip_height: Option<u32>,
    backoff: Backoff,
    sync_interval: Duration,
    connect_timeout: Duration,
    zfa_db_path: PathBuf,
    shutdown: watch::Receiver<bool>,
}

impl WalletActor {
    async fn run(mut self) {
        info!("[zfa] wallet actor starting");

        if let Err(e) = self.connect().await {
            warn!("[zfa] initial connect failed: {e}");
        }
        if self.client.is_some() {
            if let Err(e) = self.refresh_tip().await {
                warn!("[zfa] initial tip refresh failed: {e}");
                self.client = None;
            }
        }

        loop {
            if *self.shutdown.borrow() {
                info!("[zfa] wallet actor shutting down");
                return;
            }

            if self.client.is_none() {
                match self.connect().await {
                    Ok(()) => {}
                    Err(e) => {
                        let delay = self.backoff.next_delay();
                        warn!("[zfa] reconnect failed: {e}; retrying in {delay:?}");
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                }
            }

            // Open zfa.db for session writes.
            let mut zfa_db = match session::init_db(&self.zfa_db_path) {
                Ok(db) => db,
                Err(e) => {
                    error!("[zfa] failed to open zfa.db: {e}");
                    tokio::time::sleep(self.sync_interval).await;
                    continue;
                }
            };

            // Open the mempool stream.
            let stream = match self.client.as_mut().unwrap().get_mempool_stream().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("[zfa] failed to open mempool stream: {e}");
                    self.client = None;
                    tokio::time::sleep(self.sync_interval).await;
                    continue;
                }
            };
            info!("[zfa] mempool stream opened");

            let mut stream = stream;
            loop {
                tokio::select! {
                    biased;
                    _ = self.shutdown.changed() => {
                        info!("[zfa] shutdown during mempool watch");
                        return;
                    }
                    msg = stream.message() => {
                        match msg {
                            Ok(Some(raw_tx)) => {
                                self.process_mempool_tx(&mut zfa_db, raw_tx);
                            }
                            Ok(None) => {
                                info!("[zfa] mempool stream closed (new block)");
                                break;
                            }
                            Err(e) => {
                                warn!("[zfa] mempool stream error: {e}");
                                self.client = None;
                                break;
                            }
                        }
                    }
                }
            }

            // Stream closed → refresh tip and loop.
            if self.client.is_some() {
                if let Err(e) = self.refresh_tip().await {
                    warn!("[zfa] tip refresh after stream close failed: {e}");
                    self.client = None;
                }
            }
        }
    }

    async fn connect(&mut self) -> anyhow::Result<()> {
        info!("[zfa] connecting to lightwalletd: {}", self.lwd_url);
        let client = tokio::time::timeout(
            self.connect_timeout,
            LwdClient::connect(&self.lwd_url),
        )
        .await
        .map_err(|_| anyhow::anyhow!("connect timed out after {:?}", self.connect_timeout))??;
        self.client = Some(client);
        self.backoff.reset();
        Ok(())
    }

    async fn refresh_tip(&mut self) -> anyhow::Result<()> {
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("not connected"))?;
        let tip = client.get_latest_block().await?;
        let height = tip.height as u32;
        if self.tip_height != Some(height) {
            self.tip_height = Some(height);
            self.db_data
                .update_chain_tip(BlockHeight::from_u32(height))?;
            info!("[zfa] chain tip: {height}");
        }
        Ok(())
    }

    /// Process one mempool transaction: parse → decrypt → extract memo → authenticate.
    fn process_mempool_tx(
        &mut self,
        zfa_db: &mut rusqlite::Connection,
        raw_tx: zcash_client_backend::proto::service::RawTransaction,
    ) {
        let tip = self.tip_height.unwrap_or(0);

        // lightwalletd sends height=0 for mempool; Zaino sends the tip height.
        let branch_height = if raw_tx.height == 0 || raw_tx.height > tip as u64 {
            BlockHeight::from_u32(tip + 1)
        } else {
            BlockHeight::from_u32(raw_tx.height as u32)
        };

        let branch_id = BranchId::for_height(&self.network, branch_height);

        let tx = match Transaction::read(&raw_tx.data[..], branch_id) {
            Ok(tx) => tx,
            Err(e) => {
                tracing::debug!("[zfa] skipping unparseable mempool tx: {e}");
                return;
            }
        };

        let txid = tx.txid();
        let txid_hex = txid.to_string();

        let mined_height = if raw_tx.height == 0 || raw_tx.height > tip as u64 {
            None
        } else {
            Some(BlockHeight::from_u32(raw_tx.height as u32))
        };

        // Trial-decrypt and store. No-ops for unrelated transactions.
        if let Err(e) = decrypt_and_store_transaction(
            &self.network,
            &mut self.db_data,
            &tx,
            mined_height,
        ) {
            tracing::debug!("[zfa] decrypt_and_store failed for tx {txid_hex}: {e}");
            return;
        }

        // Check if the wallet received any shielded output with a ZFA session memo.
        if let Some(session_id) = self.extract_session_id(&txid) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            match session::authenticate_session(zfa_db, &session_id, &txid_hex, "", now) {
                Ok(true) => info!("[zfa] session {session_id} authenticated (txid {txid_hex})"),
                Ok(false) => tracing::debug!(
                    "[zfa] session {session_id} not authenticated (duplicate/expired/wrong status)"
                ),
                Err(e) => warn!("[zfa] failed to authenticate session {session_id}: {e}"),
            }
        }
    }

    /// Query the wallet DB for a memo matching this txid, and try to parse it
    /// as a ZFA session memo.
    fn extract_session_id(&self, txid: &TxId) -> Option<String> {
        let conn = rusqlite::Connection::open(open::data_db_path(&self.wallet_dir)).ok()?;

        // Convert txid to internal byte order for the DB (txid in DB is
        // stored in internal/protocol byte order, not display order).
        let mut internal = txid.as_ref().to_vec();
        // TxId::as_ref() returns the bytes in the same order as TxId::to_string
        // (which is display/reversed order). The DB stores internal order.
        internal.reverse();

        let mut stmt = conn
            .prepare(
                "SELECT memo FROM orchard_received_notes orn
                 JOIN transactions t ON t.id_tx = orn.transaction_id
                 WHERE t.txid = ?1 AND orn.memo IS NOT NULL",
            )
            .ok()?;

        let rows = stmt
            .query_map(rusqlite::params![internal], |row| {
                let memo: Vec<u8> = row.get(0)?;
                Ok(memo)
            })
            .ok()?;

        for row in rows {
            if let Ok(memo_bytes) = row {
                // The memo in the DB is the raw 512-byte memo field.
                if memo_bytes.len() == 512 {
                    let memo_array: [u8; 512] = memo_bytes[..512].try_into().ok()?;
                    if let Some(parsed) = memo::parse_memo(&memo_array) {
                        return Some(parsed.session_id);
                    }
                }
            }
        }
        None
    }
}