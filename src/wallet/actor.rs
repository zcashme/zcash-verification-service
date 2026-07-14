//! The single-writer actor: the sole owner/writer of the wallet DB, running
//! the sync loop and the mempool watcher.
//!
//! Ported from zecd's `wallet/actor.rs`, stripped to ZFA's needs and extended
//! with session authentication and automatic OTP response sending.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use tokio::sync::watch;
use tracing::{error, info, warn};

use zcash_client_backend::data_api::wallet::{
    create_proposed_transactions, decrypt_and_store_transaction,
    input_selection::{GreedyInputSelector, SpendPolicy},
    propose_transfer, ConfirmationsPolicy, SpendingKeys,
};
use zcash_client_backend::data_api::{Account as _, WalletRead as _, WalletWrite as _};
use zcash_client_backend::fees::{
    standard::MultiOutputChangeStrategy, DustOutputPolicy, SplitPolicy, StandardFeeRule,
};
use zcash_client_backend::wallet::OvkPolicy;
use zcash_client_sqlite::FsBlockDb;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::TxId;
use zcash_proofs::prover::LocalTxProver;

use crate::backoff::Backoff;
use crate::lwd::LwdClient;
use crate::memo;
use crate::network::ZNetwork;
use crate::otp;
use crate::session;
use crate::sync as sync_engine;
use crate::wallet::keys::{self, SeedKeeper};
use crate::wallet::open::{self, WriteDb};
use crate::wallet::store::WalletStore;

/// Note-management defaults (from zecd).
const TARGET_NOTE_COUNT: usize = 4;
const MIN_SPLIT_OUTPUT_VALUE: u64 = 10_000_000; // 0.1 ZEC
/// Fixed OTP response amount (1000 zats = 0.00001 ZEC).
const OTP_RESPONSE_AMOUNT: u64 = 1_000;

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

/// Build the wallet actor (does not spawn — caller runs it directly).
pub async fn build(cfg: ActorConfig) -> anyhow::Result<WalletActor> {
    let mut db_data = open::init_dbs(cfg.network, &cfg.wallet_dir)?;
    let db_cache = open::open_fsblockdb(&cfg.wallet_dir)?;

    let store = WalletStore::read(&cfg.keys_path)?;

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

    let account_id = match ensure_account(&mut db_data, &cfg, &seed, &store).await {
        Ok(id) => Some(id),
        Err(e) => {
            warn!("could not resolve wallet account: {e}");
            None
        }
    };

    let ufvk = account_id
        .and_then(|id| db_data.get_account(id).ok().flatten().and_then(|a| a.ufvk().cloned()));

    let prover = tokio::task::spawn_blocking(LocalTxProver::bundled)
        .await
        .map_err(|e| anyhow::anyhow!("failed to build prover: {e}"))?;

    Ok(WalletActor {
        network: cfg.network,
        wallet_dir: cfg.wallet_dir,
        db_data,
        db_cache,
        seed,
        account_id,
        ufvk,
        prover,
        lwd_url: cfg.lwd_url,
        client: None,
        tip_height: None,
        backoff: Backoff::new(cfg.reconnect_base, cfg.reconnect_max),
        sync_interval: cfg.sync_interval,
        connect_timeout: cfg.connect_timeout,
        zfa_db_path: cfg.zfa_db_path,
        shutdown: cfg.shutdown,
    })
}

async fn ensure_account(
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
            "wallet has no account and seed is not loaded; provide an age identity or unlock"
        ));
    };

    let birthday_height = store.birthday;
    let prior = u32::from(birthday_height).saturating_sub(1).max(1);

    let mut client = tokio::time::timeout(
        Duration::from_secs(30),
        LwdClient::connect(&cfg.lwd_url),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out connecting for bootstrap"))??;

    let tree_state = tokio::time::timeout(
        Duration::from_secs(30),
        client.get_tree_state(u64::from(prior)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out fetching tree state"))??;

    let birthday = zcash_client_backend::data_api::AccountBirthday::from_treestate(tree_state, None)
        .map_err(|_| anyhow::anyhow!("failed to derive birthday from tree state"))?;

    let (id, _usk) = db
        .create_account("primary", &seed_bytes, &birthday, None)
        .map_err(|e| anyhow::anyhow!("creating wallet account from seed: {e}"))?;
    info!(
        "bootstrapped wallet account from seed at birthday {}",
        u32::from(birthday_height)
    );
    Ok(id)
}

pub struct WalletActor {
    network: ZNetwork,
    wallet_dir: PathBuf,
    db_data: WriteDb,
    db_cache: FsBlockDb,
    seed: SeedKeeper,
    account_id: Option<zcash_client_sqlite::AccountUuid>,
    ufvk: Option<zcash_keys::keys::UnifiedFullViewingKey>,
    prover: LocalTxProver,
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
    pub async fn run(mut self) {
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

            // Sync confirmed blocks before watching the mempool.
            loop {
                if *self.shutdown.borrow() {
                    return;
                }
                match sync_engine::sync_one_batch(
                    "zfa",
                    self.client.as_mut().unwrap(),
                    &self.network,
                    &self.wallet_dir,
                    &mut self.db_cache,
                    &mut self.db_data,
                )
                .await
                {
                    Ok(outcome) => {
                        if !outcome.worked {
                            break; // caught up
                        }
                    }
                    Err(e) => {
                        warn!("[zfa] sync batch failed: {e}");
                        self.client = None;
                        break;
                    }
                }
            }

            if self.client.is_none() {
                continue; // reconnect
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
                                self.process_mempool_tx(&mut zfa_db, raw_tx).await;
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

            // Stream closed → refresh tip and loop (sync + reopen).
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

    /// Process one mempool transaction: parse → decrypt → extract memo → authenticate → OTP.
    async fn process_mempool_tx(
        &mut self,
        zfa_db: &mut rusqlite::Connection,
        raw_tx: zcash_client_backend::proto::service::RawTransaction,
    ) {
        let tip = self.tip_height.unwrap_or(0);

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

        // Trial-decrypt and store.
        if let Err(e) = decrypt_and_store_transaction(
            &self.network,
            &mut self.db_data,
            &tx,
            mined_height,
        ) {
            tracing::debug!("[zfa] decrypt_and_store failed for tx {txid_hex}: {e}");
            return;
        }

        // Check if we received a shielded output with a ZFA session memo.
        if let Some(session_id) = self.extract_session_id(&txid) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            match session::authenticate_session(zfa_db, &session_id, &txid_hex, "", now) {
                Ok(true) => {
                    info!("[zfa] session {session_id} authenticated (txid {txid_hex})");

                    // Check if we need to send an OTP response.
                    if let Ok(Some(status)) = session::session_status(zfa_db, &session_id) {
                        if status.otp_status.as_deref() != Some("sent") {
                            if let Some(user_addr) = status.user_address {
                                // Generate OTP and send response transaction.
                                let otp_secret = session_id.as_bytes();
                                let nonce = &txid.as_ref()[..8];
                                let otp_code = otp::generate_otp(otp_secret, &session_id, nonce);

                                match self.send_otp_response(&user_addr, &otp_code).await {
                                    Ok(resp_txid) => {
                                        info!(
                                            "[zfa] OTP response sent to {user_addr} \
                                             (otp={otp_code}, txid={resp_txid})"
                                        );
                                        let _ = session::set_otp_sent(
                                            zfa_db,
                                            &session_id,
                                            &otp_code,
                                        );
                                    }
                                    Err(e) => {
                                        warn!("[zfa] OTP response send failed: {e}");
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(false) => tracing::debug!(
                    "[zfa] session {session_id} not authenticated (duplicate/expired/wrong status)"
                ),
                Err(e) => warn!("[zfa] failed to authenticate session {session_id}: {e}"),
            }
        }
    }

    /// Send an OTP response transaction to the user's address with the OTP code in the memo.
    async fn send_otp_response(
        &mut self,
        recipient_address: &str,
        otp_code: &str,
    ) -> anyhow::Result<String> {
        info!("[zfa] building OTP response tx to {} with OTP {}", recipient_address, otp_code);
        let account_id = self.account_id.ok_or_else(|| anyhow::anyhow!("no account"))?;
        
        let zaddr = zcash_address::ZcashAddress::try_from_encoded(recipient_address)
            .map_err(|e| anyhow::anyhow!("invalid recipient address: {e}"))?;
            
        let memo_str = format!("(ZFA OTP){otp_code}");
        let mut memo_bytes = [0u8; 512];
        let bytes = memo_str.as_bytes();
        let len = bytes.len().min(512);
        memo_bytes[..len].copy_from_slice(&bytes[..len]);
        let memo = zcash_protocol::memo::MemoBytes::from_bytes(&memo_bytes)
            .map_err(|e| anyhow::anyhow!("invalid memo: {e}"))?;

        let payment = zip321::Payment::new(
            zaddr,
            Some(
                zcash_protocol::value::Zatoshis::from_u64(1_000)
                    .map_err(|e| anyhow::anyhow!("invalid amount: {e}"))?,
            ),
            Some(memo),
            None,
            None,
            vec![],
        )
        .map_err(|e| anyhow::anyhow!("invalid payment: {e}"))?;
        
        let request = zip321::TransactionRequest::new(vec![payment])
            .map_err(|e| anyhow::anyhow!("invalid transaction request: {e}"))?;

        let usk = self.seed.derive_usk(self.network, zip32::AccountId::try_from(0u32).unwrap())?;
        
        let txids = do_send_otp_response(
            &mut self.db_data,
            &self.network,
            account_id,
            request,
            &usk,
            &self.prover,
        )?;
        
        if txids.is_empty() {
            return Err(anyhow::anyhow!("no txids created"));
        }
        let txid = txids[0];
        
        // Broadcast
        use zcash_client_backend::data_api::WalletRead;
        let tx_data = self.db_data
            .get_transaction(txid)
            .map_err(|e| anyhow::anyhow!("getting transaction: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("transaction not found after creation"))?;
            
        let mut buf = Vec::new();
        use zcash_primitives::transaction::Transaction as TxTrait;
        TxTrait::write(&tx_data, &mut buf)
            .map_err(|e| anyhow::anyhow!("serializing transaction: {e}"))?;
            
        let txid_hex = txid.to_string();
        info!("[zfa] broadcasting OTP response tx {}", txid_hex);
        
        let (error_code, error_message) = self
            .client
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("not connected"))?
            .send_transaction(buf)
            .await?;

        if error_code != 0 {
            return Err(anyhow::anyhow!(
                "lightwalletd rejected transaction: code {error_code}, message: {error_message}"
            ));
        }

        Ok(txid_hex)
    }


    /// Query the wallet DB for a memo matching this txid, and try to parse it
    /// as a ZFA session memo.
    fn extract_session_id(&self, txid: &TxId) -> Option<String> {
        let conn = rusqlite::Connection::open(open::data_db_path(&self.wallet_dir)).ok()?;

        // txid in the DB is stored in internal/protocol byte order.
        let mut internal = txid.as_ref().to_vec();
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
fn do_send_otp_response(
    db: &mut WriteDb,
    net: &ZNetwork,
    account_id: zcash_client_sqlite::AccountUuid,
    request: zip321::TransactionRequest,
    usk: &zcash_keys::keys::UnifiedSpendingKey,
    prover: &zcash_proofs::prover::LocalTxProver,
) -> anyhow::Result<Vec<TxId>> {
    let change_strategy = zcash_client_backend::fees::standard::MultiOutputChangeStrategy::new(
        zcash_client_backend::fees::StandardFeeRule::Zip317,
        None,
        zcash_protocol::ShieldedPool::Orchard,
        zcash_client_backend::fees::DustOutputPolicy::default(),
        zcash_client_backend::fees::SplitPolicy::with_min_output_value(
            std::num::NonZeroUsize::new(4).unwrap(),
            zcash_protocol::value::Zatoshis::from_u64(10_000_000).unwrap(),
        ),
    );
    let input_selector = zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelector::new();
    let policy = zcash_client_backend::data_api::wallet::ConfirmationsPolicy::default();

    let proposal = zcash_client_backend::data_api::wallet::propose_transfer(
        db,
        net,
        account_id,
        &input_selector,
        &change_strategy,
        request,
        policy,
        &zcash_client_backend::data_api::wallet::input_selection::SpendPolicy::default(),
        None,
    ).map_err(|e: zcash_client_backend::data_api::error::Error<_, zcash_client_sqlite::wallet::commitment_tree::Error, _, _, _, _>| anyhow::anyhow!("propose error: {:?}", e))?;

    let txids = zcash_client_backend::data_api::wallet::create_proposed_transactions(
        db,
        net,
        prover,
        prover,
        &zcash_client_backend::data_api::wallet::SpendingKeys::from_unified_spending_key(usk.clone()),
        zcash_client_backend::wallet::OvkPolicy::Sender,
        &proposal,
    ).map_err(|e: zcash_client_backend::data_api::error::Error<_, _, zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelectorError, _, zcash_primitives::transaction::fees::zip317::FeeError, _>| anyhow::anyhow!("create error: {:?}", e))?;

    Ok(txids.into())
}
