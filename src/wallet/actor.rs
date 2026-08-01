//! The single-writer actor: the sole owner/writer of the wallet DB, running
//! the sync loop and the mempool watcher.
//!
//! Ported from zecd's `wallet/actor.rs`, stripped to ZFA's needs and extended
//! with automatic OTP response sending.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{error, info, warn};

use zcash_client_backend::data_api::wallet::{
    input_selection::{GreedyInputSelector, SpendPolicy},
    ConfirmationsPolicy, SpendingKeys,
};
use zcash_client_backend::data_api::{WalletRead as _, WalletWrite as _};
use zcash_client_backend::fees::{
    standard::MultiOutputChangeStrategy, DustOutputPolicy, SplitPolicy, StandardFeeRule,
};
use zcash_client_backend::wallet::OvkPolicy;
use zcash_client_backend::{decrypt_transaction, DecryptedOutput, TransferType};
use zcash_client_sqlite::FsBlockDb;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::transaction::Transaction;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::TxId;

use crate::backoff::Backoff;
use crate::lwd::LwdClient;
use crate::memo;
use crate::network::ZNetwork;
use crate::otp;
use crate::response_ledger::{self, Claim, ResponseState};
use crate::sync as sync_engine;
use crate::wallet::binding;
use crate::wallet::keys::{self, OtpSecret, SeedKeeper};
use crate::wallet::open::{self, WriteDb};
use crate::wallet::store::WalletStore;

/// Note-management defaults (from zecd).
const TARGET_NOTE_COUNT: usize = 3;
const MIN_SPLIT_OUTPUT_VALUE: u64 = 500_000; // 0.005 ZEC — covers ~8 OTP responses per note
/// An incoming note must pay at least 0.002 ZEC to request an OTP response.
const MIN_AUTH_PAYMENT: u64 = 200_000;
/// Fixed OTP response amount, retained from the original worker.
const OTP_RESPONSE_AMOUNT: u64 = 50_000;

/// Parameters needed to launch the wallet actor.
pub struct ActorConfig {
    pub network: ZNetwork,
    pub wallet_dir: PathBuf,
    /// Path to the file containing the `[seed]` table (zfa.toml or --keys-file).
    pub seed_path: PathBuf,
    /// Path to the age identity file that decrypts the mnemonic.
    pub identity_path: PathBuf,
    pub lwd_url: String,
    pub sync_interval: Duration,
    pub connect_timeout: Duration,
    pub reconnect_base: Duration,
    pub reconnect_max: Duration,
    pub response_ledger_path: PathBuf,
    pub shutdown: watch::Receiver<bool>,
}

/// Build the wallet actor (does not spawn — caller runs it directly).
pub async fn build(cfg: ActorConfig) -> anyhow::Result<WalletActor> {
    let mut db_data = open::init_dbs(cfg.network, &cfg.wallet_dir)?;
    let db_cache = open::open_fsblockdb(&cfg.wallet_dir)?;

    let store = WalletStore::read(&cfg.seed_path)?;

    let seed_bytes = keys::decrypt_seed_with_identity(&store, &cfg.identity_path)?;
    let mut seed = SeedKeeper::locked();
    seed.set(seed_bytes);

    let account_id = ensure_account(&mut db_data, &cfg, &seed, &store).await?;
    let account_ufvk = binding::account_ufvk_encoded(cfg.network, &db_data, account_id)?;
    let seed_for_check = seed
        .clone_seed()
        .ok_or_else(|| anyhow::anyhow!("service seed disappeared during startup"))?;
    let seed_ufvk = binding::seed_ufvk_encoded(cfg.network, &seed_for_check)?;
    if seed_ufvk != account_ufvk {
        anyhow::bail!(
            "zfa.toml mnemonic does not derive the UFVK in the wallet database; \
             refusing to operate with mismatched wallet state"
        );
    }

    // Derive the OTP HMAC key from the seed.
    let otp_key = seed
        .derive_otp_key()
        .ok_or_else(|| anyhow::anyhow!("service seed disappeared during OTP key derivation"))?;

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
        prover,
        lwd_url: cfg.lwd_url,
        client: None,
        tip_height: None,
        backoff: Backoff::new(cfg.reconnect_base, cfg.reconnect_max),
        sync_interval: cfg.sync_interval,
        connect_timeout: cfg.connect_timeout,
        otp_secret: OtpSecret::new(otp_key),
        response_ledger_path: cfg.response_ledger_path,
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
    if ids.len() > 1 {
        anyhow::bail!("the ZFA worker requires exactly one wallet account");
    }
    if let Some(id) = ids.first().copied() {
        return Ok(id);
    }

    let Some(seed_bytes) = seed.clone_seed() else {
        return Err(anyhow::anyhow!(
            "wallet has no account and seed is not loaded; provide an age identity or unlock"
        ));
    };

    // `store.birthday` is the tree-state height (the block before the actual
    // birthday), as written by `init_wallet` which fetches tree state at this
    // height. We must do the same — not subtract 1.
    let prior = u32::from(store.birthday);

    let mut client =
        tokio::time::timeout(Duration::from_secs(30), LwdClient::connect(&cfg.lwd_url))
            .await
            .map_err(|_| anyhow::anyhow!("timed out connecting for bootstrap"))??;

    let tree_state = tokio::time::timeout(
        Duration::from_secs(30),
        client.get_tree_state(u64::from(prior)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out fetching tree state"))??;

    let birthday =
        zcash_client_backend::data_api::AccountBirthday::from_treestate(tree_state, None)
            .map_err(|_| anyhow::anyhow!("failed to derive birthday from tree state"))?;

    let (id, _usk) = db
        .create_account(crate::config::ACCOUNT_NAME, &seed_bytes, &birthday, None)
        .map_err(|e| anyhow::anyhow!("creating wallet account from seed: {e}"))?;
    info!(
        "bootstrapped wallet account from seed at birthday {}",
        u32::from(store.birthday)
    );
    Ok(id)
}

pub struct WalletActor {
    network: ZNetwork,
    wallet_dir: PathBuf,
    db_data: WriteDb,
    db_cache: FsBlockDb,
    seed: SeedKeeper,
    account_id: zcash_client_sqlite::AccountUuid,
    prover: LocalTxProver,
    lwd_url: String,
    client: Option<LwdClient>,
    tip_height: Option<u32>,
    backoff: Backoff,
    sync_interval: Duration,
    connect_timeout: Duration,
    otp_secret: OtpSecret,
    response_ledger_path: PathBuf,
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
                    Ok(()) => {
                        if let Err(e) = self.refresh_tip().await {
                            let delay = self.backoff.next_delay();
                            warn!("[zfa] tip refresh after reconnect failed: {e}");
                            self.client = None;
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                    }
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
                let Some(client) = self.client.as_mut() else {
                    break;
                };
                match sync_engine::sync_one_batch(
                    "zfa",
                    client,
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

            // The response ledger is worker-local idempotence state, not a
            // consumer application's session store.
            let mut response_ledger = match response_ledger::init_db(&self.response_ledger_path) {
                Ok(db) => db,
                Err(e) => {
                    error!("[zfa] failed to open response ledger: {e}");
                    tokio::time::sleep(self.sync_interval).await;
                    continue;
                }
            };
            self.rebroadcast_pending_responses(&mut response_ledger)
                .await;

            // Open the mempool stream.
            let Some(client) = self.client.as_mut() else {
                continue;
            };
            let stream = match client.get_mempool_stream().await {
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
                                self.process_mempool_tx(&mut response_ledger, raw_tx).await;
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
        let client = tokio::time::timeout(self.connect_timeout, LwdClient::connect(&self.lwd_url))
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
        let height = u32::try_from(tip.height)
            .map_err(|_| anyhow::anyhow!("lightwalletd returned an out-of-range chain height"))?;
        if self.tip_height != Some(height) {
            self.tip_height = Some(height);
            self.db_data
                .update_chain_tip(BlockHeight::from_u32(height))?;
            info!("[zfa] chain tip: {height}");
        }
        Ok(())
    }

    /// Process one unmined transaction from `GetMempoolStream`.
    ///
    /// The stream's `RawTransaction.height` is intentionally ignored. The
    /// lightwalletd proto convention is zero while Zaino currently reports the
    /// best-tip height, but both values describe a mempool event. The pinned
    /// `zcash_client_backend::decrypt_transaction` API expects `None` plus the
    /// current tip for this case and handles Sapling, Orchard, and Ironwood.
    async fn process_mempool_tx(
        &mut self,
        response_ledger: &mut rusqlite::Connection,
        raw_tx: zcash_client_backend::proto::service::RawTransaction,
    ) {
        let Some(tip) = self.tip_height else {
            warn!("[zfa] cannot decrypt mempool transaction before learning the chain tip");
            return;
        };
        let Some(mempool_height) = tip.checked_add(1) else {
            error!("[zfa] chain tip cannot be incremented for mempool decryption");
            return;
        };
        let branch_id = BranchId::for_height(&self.network, BlockHeight::from_u32(mempool_height));

        let tx = match Transaction::read(&raw_tx.data[..], branch_id) {
            Ok(tx) => tx,
            Err(e) => {
                tracing::debug!("[zfa] skipping unparseable mempool tx: {e}");
                return;
            }
        };

        let payments = match self.decrypt_and_store_mempool_tx(&tx, BlockHeight::from_u32(tip)) {
            Ok(payments) => payments,
            Err(e) => {
                tracing::debug!("[zfa] trial decryption/store failed: {e}");
                return;
            }
        };

        for payment in payments {
            if payment.amount_zats < MIN_AUTH_PAYMENT {
                tracing::debug!(
                    txid = %payment.incoming_txid,
                    amount_zats = payment.amount_zats,
                    "[zfa] ignored auth request below the minimum payment"
                );
                continue;
            }

            if let Err(e) = self.parse_return_address(&payment.return_address) {
                tracing::debug!(txid = %payment.incoming_txid, "[zfa] ignored invalid return address: {e}");
                continue;
            }

            let incoming_txid = payment.incoming_txid.to_string();
            match response_ledger::claim(response_ledger, &incoming_txid) {
                Ok(Claim::Acquired) => {
                    let otp_code = otp::generate_otp(
                        self.otp_secret.expose(),
                        &payment.session_id,
                        &payment.return_address,
                    );
                    let response_txid = match self
                        .create_otp_response(&payment.return_address, &otp_code)
                    {
                        Ok(txid) => txid,
                        Err(e) => {
                            warn!(
                                txid = %incoming_txid,
                                "[zfa] response claimed but wallet transaction creation failed: {e}"
                            );
                            continue;
                        }
                    };

                    if let Err(e) = response_ledger::record_created(
                        response_ledger,
                        &incoming_txid,
                        &response_txid,
                    ) {
                        error!(
                            txid = %incoming_txid,
                            response_txid = %response_txid,
                            "[zfa] wallet created a response but the ledger was not updated: {e}"
                        );
                        continue;
                    }

                    self.broadcast_and_record(response_ledger, &incoming_txid, response_txid)
                        .await;
                }
                Ok(Claim::AlreadyHandled(
                    ResponseState::Created { response_txid }
                    | ResponseState::Broadcasting { response_txid },
                )) => {
                    self.broadcast_and_record(response_ledger, &incoming_txid, response_txid)
                        .await;
                }
                Ok(Claim::AlreadyHandled(ResponseState::Broadcast { .. })) => {
                    tracing::debug!(txid = %incoming_txid, "[zfa] duplicate auth transaction ignored");
                }
                Ok(Claim::AlreadyHandled(ResponseState::Claimed)) => {
                    error!(
                        txid = %incoming_txid,
                        "[zfa] response is claimed without a recorded transaction; refusing a second spend"
                    );
                }
                Err(e) => {
                    warn!(txid = %incoming_txid, "[zfa] failed to claim response: {e}");
                }
            }
        }
    }

    /// Trial-decrypt and persist one mempool transaction using the public
    /// librustzcash API, then retain only authentic incoming payment events.
    fn decrypt_and_store_mempool_tx(
        &mut self,
        tx: &Transaction,
        chain_tip: BlockHeight,
    ) -> anyhow::Result<Vec<IncomingAuthPayment>> {
        let ufvks = self.db_data.get_unified_full_viewing_keys()?;
        let decrypted = decrypt_transaction(&self.network, None, Some(chain_tip), tx, &ufvks);
        let mut payments = Vec::new();

        collect_incoming_from_pool(
            decrypted.sapling_outputs(),
            |note| note.value().inner(),
            tx.txid(),
            &mut payments,
        );
        collect_incoming_from_pool(
            decrypted.orchard_outputs(),
            |note_and_pool| note_and_pool.0.value().inner(),
            tx.txid(),
            &mut payments,
        );
        collect_incoming_from_pool(
            decrypted.ironwood_outputs(),
            |note_and_pool| note_and_pool.0.value().inner(),
            tx.txid(),
            &mut payments,
        );

        self.db_data.store_decrypted_tx(decrypted)?;
        Ok(payments)
    }

    /// Construct and persist, but do not yet broadcast, one OTP response.
    fn create_otp_response(
        &mut self,
        recipient_address: &str,
        otp_code: &str,
    ) -> anyhow::Result<TxId> {
        let account_id = self.account_id;
        let zaddr = self.parse_return_address(recipient_address)?;

        let memo_str = format!("(ZFA OTP){otp_code}");
        let mut memo_bytes = [0u8; 512];
        memo_bytes[..memo_str.len()].copy_from_slice(memo_str.as_bytes());
        let memo = zcash_protocol::memo::MemoBytes::from_bytes(&memo_bytes)
            .map_err(|e| anyhow::anyhow!("invalid memo: {e}"))?;

        let payment = zip321::Payment::new(
            zaddr,
            Some(
                zcash_protocol::value::Zatoshis::from_u64(OTP_RESPONSE_AMOUNT)
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

        let account_index =
            zip32::AccountId::try_from(crate::config::ACCOUNT_INDEX).map_err(|_| {
                anyhow::anyhow!(
                    "account {} is not a valid ZIP-32 account",
                    crate::config::ACCOUNT_INDEX
                )
            })?;
        let usk = self.seed.derive_usk(self.network, account_index)?;

        let txids = do_send_otp_response(
            &mut self.db_data,
            &self.network,
            account_id,
            request,
            &usk,
            &self.prover,
        )?;

        if txids.len() != 1 {
            return Err(anyhow::anyhow!(
                "expected one OTP response transaction, created {}",
                txids.len()
            ));
        }
        Ok(txids[0])
    }

    async fn broadcast_and_record(
        &mut self,
        response_ledger: &mut rusqlite::Connection,
        incoming_txid: &str,
        response_txid: TxId,
    ) {
        if let Err(e) =
            response_ledger::record_broadcasting(response_ledger, incoming_txid, &response_txid)
        {
            error!(
                txid = %incoming_txid,
                response_txid = %response_txid,
                "[zfa] response could not be marked as broadcasting: {e}"
            );
            return;
        }

        match self.broadcast_response(response_txid).await {
            Ok(()) => {
                if let Err(e) = response_ledger::record_broadcast(
                    response_ledger,
                    incoming_txid,
                    &response_txid,
                ) {
                    error!(
                        txid = %incoming_txid,
                        response_txid = %response_txid,
                        "[zfa] response was broadcast but ledger update failed: {e}"
                    );
                }
            }
            Err(e) => warn!(
                txid = %incoming_txid,
                response_txid = %response_txid,
                "[zfa] response broadcast failed; the recorded transaction may be retried: {e}"
            ),
        }
    }

    /// Retry every persisted-but-unacknowledged response before opening the
    /// next mempool stream. This is safe because these are the exact wallet
    /// transactions recorded before their original broadcast attempt.
    async fn rebroadcast_pending_responses(&mut self, response_ledger: &mut rusqlite::Connection) {
        let pending = match response_ledger::pending_broadcasts(response_ledger) {
            Ok(pending) => pending,
            Err(e) => {
                error!("[zfa] could not read pending OTP responses from the ledger: {e}");
                return;
            }
        };
        for pending in pending {
            self.broadcast_and_record(
                response_ledger,
                &pending.incoming_txid,
                pending.response_txid,
            )
            .await;
        }
    }

    /// Broadcast a wallet transaction that was already durably created.
    async fn broadcast_response(&mut self, txid: TxId) -> anyhow::Result<()> {
        let tx_data = self
            .db_data
            .get_transaction(txid)
            .map_err(|e| anyhow::anyhow!("getting transaction: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("transaction not found after creation"))?;

        let mut buf = Vec::new();
        use zcash_primitives::transaction::Transaction as TxTrait;
        TxTrait::write(&tx_data, &mut buf)
            .map_err(|e| anyhow::anyhow!("serializing transaction: {e}"))?;

        let (error_code, error_message) = self
            .client
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("not connected"))?
            .send_transaction(buf)
            .await?;

        if error_code != 0 {
            // "transaction already exists in mempool" means the tx was
            // successfully broadcast before (e.g. by a previous worker run
            // that crashed before recording the broadcast). Treat it as
            // success — the tx is in the mempool, which is the goal.
            if error_message.contains("already exists") {
                info!("[zfa] response tx already in mempool — treating as broadcast");
                return Ok(());
            }
            return Err(anyhow::anyhow!(
                "lightwalletd rejected transaction: code {error_code}, message: {error_message}"
            ));
        }

        Ok(())
    }

    /// Parse an exact return-address string and require a shielded receiver on
    /// this worker's network. `ZcashAddress::convert_if_network` is the
    /// upstream network validation boundary; `Payment::new` then enforces that
    /// the selected recipient can carry a memo.
    fn parse_return_address(&self, encoded: &str) -> anyhow::Result<zcash_address::ZcashAddress> {
        let address = zcash_address::ZcashAddress::try_from_encoded(encoded)
            .map_err(|e| anyhow::anyhow!("invalid return address: {e}"))?;
        if !address.can_receive_memo() {
            anyhow::bail!("return address has no shielded receiver for the OTP memo");
        }
        address
            .clone()
            .convert_if_network::<zcash_keys::address::Address>(self.network.network_type())
            .map_err(|e| anyhow::anyhow!("return address is for another network: {e}"))?;
        Ok(address)
    }
}

/// Typed data retained from one incoming decrypted shielded note.
struct IncomingAuthPayment {
    incoming_txid: TxId,
    session_id: String,
    return_address: String,
    amount_zats: u64,
}

fn collect_incoming_from_pool<Note>(
    outputs: &[DecryptedOutput<Note, zcash_client_sqlite::AccountUuid>],
    note_value: impl Fn(&Note) -> u64,
    incoming_txid: TxId,
    payments: &mut Vec<IncomingAuthPayment>,
) {
    for output in outputs {
        if output.transfer_type() != TransferType::Incoming {
            continue;
        }
        let Some(parsed) = memo::parse_memo(output.memo().as_array()) else {
            continue;
        };
        let Some(return_address) = parsed.return_address else {
            continue;
        };
        payments.push(IncomingAuthPayment {
            incoming_txid,
            session_id: parsed.session_id,
            return_address,
            amount_zats: note_value(output.note()),
        });
    }
}
fn do_send_otp_response(
    db: &mut WriteDb,
    net: &ZNetwork,
    account_id: zcash_client_sqlite::AccountUuid,
    request: zip321::TransactionRequest,
    usk: &UnifiedSpendingKey,
    prover: &zcash_proofs::prover::LocalTxProver,
) -> anyhow::Result<Vec<TxId>> {
    let target_note_count = NonZeroUsize::new(TARGET_NOTE_COUNT)
        .ok_or_else(|| anyhow::anyhow!("target note count must be nonzero"))?;
    let min_split_output = Zatoshis::from_u64(MIN_SPLIT_OUTPUT_VALUE)
        .map_err(|e| anyhow::anyhow!("invalid minimum split-output value: {e}"))?;
    let change_strategy = MultiOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        zcash_protocol::ShieldedPool::Ironwood,
        DustOutputPolicy::default(),
        SplitPolicy::with_min_output_value(target_note_count, min_split_output),
    );
    let input_selector = GreedyInputSelector::new();
    let policy = ConfirmationsPolicy::default();

    let proposal = zcash_client_backend::data_api::wallet::propose_transfer(
        db,
        net,
        account_id,
        &input_selector,
        &change_strategy,
        request,
        policy,
        &SpendPolicy::default(),
        None, // lock_inputs
        None, // proposed_version
    )
    .map_err(
        |e: zcash_client_backend::data_api::error::Error<
            _,
            zcash_client_sqlite::wallet::commitment_tree::Error,
            _,
            _,
            _,
            _,
        >| anyhow::anyhow!("propose error: {:?}", e),
    )?;

    let txids = zcash_client_backend::data_api::wallet::create_proposed_transactions(
        db,
        net,
        prover,
        prover,
        &SpendingKeys::from_unified_spending_key(usk.clone()),
        OvkPolicy::Sender,
        &proposal,
        None, // expiry_height
    )
    .map_err(
        |e: zcash_client_backend::data_api::error::Error<
            _,
            _,
            zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelectorError,
            _,
            zcash_primitives::transaction::fees::zip317::FeeError,
            _,
        >| anyhow::anyhow!("create error: {:?}", e),
    )?;

    Ok(txids.into())
}
