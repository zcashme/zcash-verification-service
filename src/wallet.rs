//! ZVS Wallet - Core wallet implementation for Zcash operations.
//!
//! This module provides a complete wallet abstraction over zcash_client_sqlite,
//! handling account management, synchronization, transaction building, and
//! memo decryption.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::Path;

use anyhow::{anyhow, Result};
use secrecy::Secret;
use tonic::transport::Channel;
use tracing::{debug, info, warn};

use zcash_client_backend::{
    data_api::{
        chain::{scan_cached_blocks, BlockSource, ChainState},
        wallet::{
            create_proposed_transactions, input_selection::GreedyInputSelector, propose_transfer,
            ConfirmationsPolicy, SpendingKeys,
        },
        AccountBirthday, WalletRead, WalletWrite,
    },
    proto::{
        compact_formats::CompactBlock,
        service::{
            compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec,
            RawTransaction, TxFilter,
        },
    },
    wallet::OvkPolicy,
    zip321::TransactionRequest,
};
use zcash_client_sqlite::{util::SystemClock, wallet::init::init_wallet_db, AccountUuid, WalletDb};
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::consensus::{BlockHeight, MainNetwork};

use crate::memo_rules::{validate_memo, VerificationData};
use crate::otp_rules::create_change_strategy;
use crate::scan::{decrypt_orchard_memo, decrypt_sapling_memo};

/// Sync batch size for block downloads.
const BATCH_SIZE: u32 = 1000;

/// In-memory cache for compact blocks during sync.
pub struct MemoryBlockSource {
    blocks: BTreeMap<u32, CompactBlock>,
}

impl MemoryBlockSource {
    pub fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, height: u32, block: CompactBlock) {
        self.blocks.insert(height, block);
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
    }
}

impl Default for MemoryBlockSource {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockSource for MemoryBlockSource {
    type Error = anyhow::Error;

    fn with_blocks<F, DbErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_row: F,
    ) -> std::result::Result<
        (),
        zcash_client_backend::data_api::chain::error::Error<DbErrT, Self::Error>,
    >
    where
        F: FnMut(
            CompactBlock,
        ) -> std::result::Result<
            (),
            zcash_client_backend::data_api::chain::error::Error<DbErrT, Self::Error>,
        >,
    {
        let start = from_height.map(u32::from).unwrap_or(0);
        let mut count = 0;

        for (_, block) in self.blocks.range(start..) {
            if let Some(l) = limit {
                if count >= l {
                    break;
                }
            }
            with_row(block.clone())?;
            count += 1;
        }

        Ok(())
    }
}

/// Account balance breakdown.
#[derive(Debug, Clone, Default)]
pub struct AccountBalance {
    pub total: u64,
    pub sapling_spendable: u64,
    pub orchard_spendable: u64,
    pub pending_change: u64,
}

/// A received memo with metadata.
#[derive(Debug, Clone)]
pub struct ReceivedMemo {
    pub txid: TxId,
    pub txid_hex: String,
    pub height: u32,
    pub memo: String,
    pub value_zats: u64,
    pub verification: Option<VerificationData>,
}

/// Result of a sync operation.
#[derive(Debug, Clone, Default)]
pub struct SyncResult {
    pub blocks_scanned: u32,
    pub start_height: u32,
    pub end_height: u32,
    pub sapling_notes_received: usize,
    pub orchard_notes_received: usize,
    pub new_memos: Vec<ReceivedMemo>,
}

/// Transaction send result.
#[derive(Debug, Clone)]
pub struct SendResult {
    pub txid: TxId,
    pub raw_tx: Vec<u8>,
}

/// The wallet database type used throughout ZVS.
pub type WalletDbType = WalletDb<rusqlite::Connection, MainNetwork, SystemClock, rand::rngs::OsRng>;

/// ZVS Wallet - handles all Zcash wallet operations.
pub struct Wallet {
    db: WalletDbType,
    client: CompactTxStreamerClient<Channel>,
    account_id: AccountUuid,
    usk: UnifiedSpendingKey,
    birthday_height: u32,
}

impl Wallet {
    /// Create a new wallet, connecting to lightwalletd and initializing the database.
    pub async fn new(
        lightwalletd_url: &str,
        seed: &[u8],
        birthday_height: u32,
        data_dir: &Path,
    ) -> Result<Self> {
        info!("Connecting to lightwalletd at {}", lightwalletd_url);

        let client = CompactTxStreamerClient::connect(lightwalletd_url.to_owned())
            .await
            .map_err(|e| anyhow!("Failed to connect to lightwalletd: {e}"))?;

        std::fs::create_dir_all(data_dir)?;
        let db_path = data_dir.join("wallet.db");

        info!("Initializing wallet database at {}", db_path.display());

        let mut db = WalletDb::for_path(&db_path, MainNetwork, SystemClock, rand::rngs::OsRng)
            .map_err(|e| anyhow!("Failed to open wallet db: {e}"))?;

        init_wallet_db(&mut db, None).map_err(|e| anyhow!("Failed to init wallet db: {e:?}"))?;

        // Get or create account
        let accounts = db
            .get_account_ids()
            .map_err(|e| anyhow!("Failed to get accounts: {e}"))?;

        let (account_id, usk) = if let Some(existing_id) = accounts.first() {
            info!("Using existing account");
            let usk =
                UnifiedSpendingKey::from_seed(&MainNetwork, seed, zip32::AccountId::ZERO)
                    .map_err(|e| anyhow!("Failed to derive spending key: {e:?}"))?;
            (*existing_id, usk)
        } else {
            info!("Creating new account from seed");
            let mut temp_client = client.clone();
            let birthday = Self::fetch_birthday_static(&mut temp_client, birthday_height).await?;
            let seed_secret: Secret<Vec<u8>> = Secret::new(seed.to_vec());
            let (account_id, usk) = db
                .create_account("ZVS Wallet", &seed_secret, &birthday, None)
                .map_err(|e| anyhow!("Failed to create account: {e}"))?;
            info!("Created account: {:?}", account_id);
            (account_id, usk)
        };

        Ok(Self {
            db,
            client,
            account_id,
            usk,
            birthday_height,
        })
    }

    /// Get the account UUID.
    pub fn account_id(&self) -> AccountUuid {
        self.account_id
    }

    /// Get the unified spending key.
    pub fn spending_key(&self) -> &UnifiedSpendingKey {
        &self.usk
    }

    /// Get the unified full viewing key.
    pub fn viewing_key(&self) -> zcash_keys::keys::UnifiedFullViewingKey {
        self.usk.to_unified_full_viewing_key()
    }

    /// Get the birthday height.
    pub fn birthday_height(&self) -> u32 {
        self.birthday_height
    }

    // =========================================================================
    // Address Methods
    // =========================================================================

    /// Get the default unified address (Orchard + Sapling receivers).
    pub fn get_unified_address(&self) -> Result<String> {
        let ufvk = self.usk.to_unified_full_viewing_key();
        let (ua, _) = ufvk.default_address(UnifiedAddressRequest::AllAvailableKeys)?;
        Ok(ua.encode(&MainNetwork))
    }

    /// Get the default Sapling address.
    pub fn get_sapling_address(&self) -> Result<String> {
        let ufvk = self.usk.to_unified_full_viewing_key();
        let sapling_dfvk = ufvk.sapling().ok_or_else(|| anyhow!("No Sapling key"))?;
        let (_, address) = sapling_dfvk.default_address();
        Ok(zcash_client_backend::encoding::encode_payment_address(
            zcash_protocol::constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &address,
        ))
    }

    /// Get the default address (unified).
    pub fn get_address(&self) -> Result<String> {
        self.get_unified_address()
    }

    // =========================================================================
    // Balance Methods
    // =========================================================================

    /// Get the account balance.
    pub fn get_balance(&self) -> Result<AccountBalance> {
        let summary = self
            .db
            .get_wallet_summary(ConfirmationsPolicy::default())
            .map_err(|e| anyhow!("Failed to get wallet summary: {e}"))?
            .ok_or_else(|| anyhow!("Wallet not synced"))?;

        let balance = summary
            .account_balances()
            .get(&self.account_id)
            .ok_or_else(|| anyhow!("Account not found"))?;

        Ok(AccountBalance {
            total: u64::from(balance.total()),
            sapling_spendable: u64::from(balance.sapling_balance().spendable_value()),
            orchard_spendable: u64::from(balance.orchard_balance().spendable_value()),
            pending_change: u64::from(balance.sapling_balance().change_pending_confirmation())
                + u64::from(balance.orchard_balance().change_pending_confirmation()),
        })
    }

    /// Get the spendable balance (sum of sapling + orchard spendable).
    pub fn get_spendable_balance(&self) -> Result<u64> {
        let balance = self.get_balance()?;
        Ok(balance.sapling_spendable + balance.orchard_spendable)
    }

    // =========================================================================
    // Chain State Methods
    // =========================================================================

    /// Get the latest block height from the chain.
    pub async fn get_chain_height(&mut self) -> Result<u32> {
        let response = self
            .client
            .get_latest_block(ChainSpec {})
            .await
            .map_err(|e| anyhow!("Failed to get latest block: {e}"))?;
        Ok(response.into_inner().height as u32)
    }

    /// Get the last scanned block height from the wallet.
    pub fn get_scanned_height(&self) -> Result<Option<u32>> {
        let meta = self
            .db
            .block_fully_scanned()
            .map_err(|e| anyhow!("Failed to get scan progress: {e}"))?;
        Ok(meta.map(|m| u32::from(m.block_height())))
    }

    /// Fetch the chain state at a specific height.
    async fn get_chain_state_at(&mut self, height: u32) -> Result<ChainState> {
        let tree_state = self
            .client
            .get_tree_state(BlockId {
                height: height as u64,
                hash: vec![],
            })
            .await
            .map_err(|e| anyhow!("Failed to get tree state: {e}"))?
            .into_inner();

        let birthday = AccountBirthday::from_treestate(tree_state, None)
            .map_err(|_| anyhow!("Failed to parse tree state"))?;

        Ok(birthday.prior_chain_state().clone())
    }

    /// Fetch birthday tree state (static method for initialization).
    async fn fetch_birthday_static(
        client: &mut CompactTxStreamerClient<Channel>,
        height: u32,
    ) -> Result<AccountBirthday> {
        let prior_height = height.saturating_sub(1);
        info!("Fetching tree state at height {}", prior_height);

        let tree_state = client
            .get_tree_state(BlockId {
                height: prior_height as u64,
                hash: vec![],
            })
            .await
            .map_err(|e| anyhow!("Failed to get tree state: {e}"))?
            .into_inner();

        AccountBirthday::from_treestate(tree_state, None)
            .map_err(|_| anyhow!("Failed to create birthday from tree state"))
    }

    // =========================================================================
    // Synchronization Methods
    // =========================================================================

    /// Full sync from birthday to chain tip.
    pub async fn sync(&mut self) -> Result<SyncResult> {
        let chain_tip = self.get_chain_height().await?;

        let scan_from = self
            .get_scanned_height()?
            .map(|h| h + 1)
            .unwrap_or(self.birthday_height);

        if scan_from > chain_tip {
            info!("Wallet is up to date (tip: {})", chain_tip);
            return Ok(SyncResult::default());
        }

        info!("Syncing from block {} to {}", scan_from, chain_tip);

        let mut result = SyncResult {
            start_height: scan_from,
            end_height: chain_tip,
            ..Default::default()
        };

        let mut current = scan_from;
        let mut block_source = MemoryBlockSource::new();

        while current <= chain_tip {
            let batch_end = std::cmp::min(current + BATCH_SIZE - 1, chain_tip);
            info!("Downloading blocks {} to {}", current, batch_end);

            // Download blocks
            self.download_blocks(&mut block_source, current, batch_end)
                .await?;

            info!("Downloaded {} blocks, scanning...", block_source.len());

            // Scan blocks
            let from_height = BlockHeight::from_u32(current);
            let chain_state = self.get_chain_state_at(current.saturating_sub(1)).await?;

            let scan_result = scan_cached_blocks(
                &MainNetwork,
                &block_source,
                &mut self.db,
                from_height,
                &chain_state,
                block_source.len(),
            )
            .map_err(|e| anyhow!("Scan error: {e}"))?;

            result.sapling_notes_received += scan_result.received_sapling_note_count();
            result.orchard_notes_received += scan_result.received_orchard_note_count();
            result.blocks_scanned += batch_end - current + 1;

            info!(
                "Scanned batch: {} sapling, {} orchard notes",
                scan_result.received_sapling_note_count(),
                scan_result.received_orchard_note_count()
            );

            block_source.clear();
            current = batch_end + 1;
        }

        // Fetch memos for any new notes
        result.new_memos = self.fetch_pending_memos().await?;

        info!(
            "Sync complete: {} blocks, {} sapling, {} orchard, {} memos",
            result.blocks_scanned,
            result.sapling_notes_received,
            result.orchard_notes_received,
            result.new_memos.len()
        );

        Ok(result)
    }

    /// Incremental sync - sync only new blocks since last scan.
    pub async fn sync_incremental(&mut self) -> Result<SyncResult> {
        // Same as sync() - it already handles incremental
        self.sync().await
    }

    /// Download blocks into the block source.
    async fn download_blocks(
        &mut self,
        block_source: &mut MemoryBlockSource,
        start: u32,
        end: u32,
    ) -> Result<()> {
        let block_range = BlockRange {
            start: Some(BlockId {
                height: start as u64,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: end as u64,
                hash: vec![],
            }),
        };

        let mut stream = self
            .client
            .get_block_range(block_range)
            .await
            .map_err(|e| anyhow!("Failed to get block range: {e}"))?
            .into_inner();

        use tokio_stream::StreamExt;
        while let Some(block) = stream.next().await {
            let block = block.map_err(|e| anyhow!("Stream error: {e}"))?;
            block_source.insert(block.height as u32, block);
        }

        Ok(())
    }

    // =========================================================================
    // Memo Methods
    // =========================================================================

    /// Fetch memos for notes that need memo enhancement.
    ///
    /// After scanning, notes are stored without memos (compact blocks don't include them).
    /// This method fetches full transactions and decrypts memos for recent notes.
    pub async fn fetch_pending_memos(&mut self) -> Result<Vec<ReceivedMemo>> {
        // Get notes that need memo enhancement using transaction_data_requests
        let requests = self
            .db
            .transaction_data_requests()
            .map_err(|e| anyhow!("Failed to get data requests: {e}"))?;

        let mut memos = Vec::new();

        for request in requests {
            match request {
                zcash_client_backend::data_api::TransactionDataRequest::GetStatus(_) => {
                    // Status requests are for pending transactions, skip for now
                    continue;
                }
                zcash_client_backend::data_api::TransactionDataRequest::Enhancement(txid) => {
                    // Fetch and process this transaction
                    match self.fetch_and_process_transaction(&txid).await {
                        Ok(Some(memo)) => memos.push(memo),
                        Ok(None) => {}
                        Err(e) => {
                            warn!("Failed to process transaction {}: {}", hex::encode(txid.as_ref()), e);
                        }
                    }
                }
            }
        }

        Ok(memos)
    }

    /// Fetch a transaction from lightwalletd, decrypt memo, and store enhanced data.
    async fn fetch_and_process_transaction(&mut self, txid: &TxId) -> Result<Option<ReceivedMemo>> {
        let txid_bytes = txid.as_ref().to_vec();
        let txid_hex = hex::encode(&txid_bytes);

        debug!("Fetching transaction {} for memo", txid_hex);

        // Fetch raw transaction
        let tx_filter = TxFilter {
            block: None,
            index: 0,
            hash: txid_bytes.clone(),
        };

        let raw_tx = self
            .client
            .get_transaction(tx_filter)
            .await
            .map_err(|e| anyhow!("Failed to fetch transaction: {e}"))?
            .into_inner();

        if raw_tx.data.is_empty() {
            return Err(anyhow!("Empty transaction data"));
        }

        // Get height for this transaction (use current tip as approximation)
        let height = raw_tx.height as u32;
        let block_height = BlockHeight::from_u32(height);
        let branch_id =
            zcash_primitives::consensus::BranchId::for_height(&MainNetwork, block_height);

        // Parse transaction
        let tx = Transaction::read(&raw_tx.data[..], branch_id)
            .map_err(|e| anyhow!("Failed to parse transaction: {e}"))?;

        // Store enhanced transaction data in wallet
        self.db
            .set_transaction_status(*txid, zcash_client_backend::data_api::TransactionStatus::Mined(block_height))
            .map_err(|e| anyhow!("Failed to store transaction: {e}"))?;

        // Try to decrypt memo
        let ufvk = self.usk.to_unified_full_viewing_key();

        // Try Sapling first
        if let Some(memo_text) = decrypt_sapling_memo(&tx, &ufvk, block_height)? {
            if !memo_text.is_empty() {
                let verification = validate_memo(&memo_text);
                let value_zats = self.get_transaction_value(txid)?;

                return Ok(Some(ReceivedMemo {
                    txid: *txid,
                    txid_hex,
                    height,
                    memo: memo_text,
                    value_zats,
                    verification,
                }));
            }
        }

        // Try Orchard
        if let Some(memo_text) = decrypt_orchard_memo(&tx, &ufvk)? {
            if !memo_text.is_empty() {
                let verification = validate_memo(&memo_text);
                let value_zats = self.get_transaction_value(txid)?;

                return Ok(Some(ReceivedMemo {
                    txid: *txid,
                    txid_hex,
                    height,
                    memo: memo_text,
                    value_zats,
                    verification,
                }));
            }
        }

        Ok(None)
    }

    /// Get total received value for a transaction.
    fn get_transaction_value(&self, _txid: &TxId) -> Result<u64> {
        // TODO: Query received notes for this txid and sum values
        // For now return 0, the actual value should come from the note decryption
        Ok(0)
    }

    /// Fetch all memos (for display purposes).
    pub async fn get_all_memos(&mut self) -> Result<Vec<ReceivedMemo>> {
        // First ensure we have latest memos
        self.fetch_pending_memos().await
    }

    // =========================================================================
    // Transaction Methods
    // =========================================================================

    /// Fetch raw transaction bytes from the wallet or lightwalletd.
    pub async fn fetch_raw_transaction(&mut self, txid: &TxId) -> Result<Vec<u8>> {
        // First try to get from wallet database
        // The transaction should be stored after create_proposed_transactions()

        // If not in wallet, fetch from lightwalletd
        let tx_filter = TxFilter {
            block: None,
            index: 0,
            hash: txid.as_ref().to_vec(),
        };

        let raw_tx = self
            .client
            .get_transaction(tx_filter)
            .await
            .map_err(|e| anyhow!("Failed to fetch transaction: {e}"))?
            .into_inner();

        if raw_tx.data.is_empty() {
            return Err(anyhow!("Transaction not found: {}", hex::encode(txid.as_ref())));
        }

        Ok(raw_tx.data)
    }

    /// Create and sign a transaction from a ZIP-321 request.
    pub async fn create_transaction(&mut self, request: TransactionRequest) -> Result<SendResult> {
        let change_strategy = create_change_strategy::<WalletDbType>();
        let input_selector = GreedyInputSelector::new();

        info!("Proposing transfer...");

        let proposal = match propose_transfer::<_, _, _, _, Infallible>(
            &mut self.db,
            &MainNetwork,
            self.account_id,
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::default(),
        ) {
            Ok(p) => p,
            Err(e) => return Err(anyhow!("Failed to propose transfer: {:?}", e)),
        };

        info!("Proposal created, building transaction...");

        // Load prover
        let prover = LocalTxProver::with_default_location()
            .ok_or_else(|| anyhow!("Sapling params not found. Run: ./fetch-params.sh"))?;

        // Create transaction
        let spending_keys = SpendingKeys::from_unified_spending_key(self.usk.clone());
        let txids = match create_proposed_transactions::<_, _, Infallible, _, Infallible, _>(
            &mut self.db,
            &MainNetwork,
            &prover,
            &prover,
            &spending_keys,
            OvkPolicy::Sender,
            &proposal,
        ) {
            Ok(t) => t,
            Err(e) => return Err(anyhow!("Failed to create transaction: {:?}", e)),
        };

        let txid = *txids.first();
        info!("Transaction created: {}", hex::encode(txid.as_ref()));

        // Fetch raw transaction bytes
        let raw_tx = self.fetch_raw_transaction(&txid).await?;

        Ok(SendResult { txid, raw_tx })
    }

    /// Broadcast a raw transaction to the network.
    pub async fn broadcast_transaction(&mut self, raw_tx: Vec<u8>) -> Result<()> {
        let height = self.get_chain_height().await?;

        info!("Broadcasting transaction ({} bytes)...", raw_tx.len());

        let response = self
            .client
            .send_transaction(RawTransaction {
                data: raw_tx,
                height: height as u64,
            })
            .await
            .map_err(|e| anyhow!("Failed to broadcast transaction: {e}"))?;

        let send_response = response.into_inner();
        if send_response.error_code != 0 {
            return Err(anyhow!("Broadcast failed: {}", send_response.error_message));
        }

        info!("Transaction broadcast successfully!");
        Ok(())
    }

    /// Create, sign, and broadcast a transaction.
    pub async fn send_transaction(&mut self, request: TransactionRequest) -> Result<TxId> {
        let result = self.create_transaction(request).await?;
        self.broadcast_transaction(result.raw_tx).await?;
        Ok(result.txid)
    }

    // =========================================================================
    // Low-Level Access
    // =========================================================================

    /// Get mutable access to the wallet database.
    pub fn db_mut(&mut self) -> &mut WalletDbType {
        &mut self.db
    }

    /// Get immutable access to the wallet database.
    pub fn db(&self) -> &WalletDbType {
        &self.db
    }

    /// Get mutable access to the lightwalletd client.
    pub fn client_mut(&mut self) -> &mut CompactTxStreamerClient<Channel> {
        &mut self.client
    }
}
