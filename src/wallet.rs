//! ZVS Wallet - Wallet operations for Zcash Verification Service
//!
//! This module provides wallet functionality over zcash_client_sqlite:
//! - Account management
//! - Address generation
//! - Memo decryption
//!
//! Network operations (streaming, broadcasting) are handled separately.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::Path;

use anyhow::{anyhow, Result};
use secrecy::Secret;
use tracing::{debug, info};

use tonic::transport::Channel;
use zcash_client_backend::{
    data_api::{
        wallet::{
            create_proposed_transactions, decrypt_and_store_transaction,
            input_selection::GreedyInputSelector, propose_transfer, ConfirmationsPolicy,
            SpendingKeys,
        },
        AccountBirthday, TransactionDataRequest, WalletRead, WalletWrite,
    },
    decrypt_transaction,
    fees::{zip317::MultiOutputChangeStrategy, DustOutputPolicy, SplitPolicy, StandardFeeRule},
    proto::service::{
        compact_tx_streamer_client::CompactTxStreamerClient, RawTransaction, TxFilter,
    },
    wallet::OvkPolicy,
    zip321::TransactionRequest,
    TransferType,
};
use zcash_proofs::prover::LocalTxProver;
use zcash_client_sqlite::{
    util::SystemClock, wallet::commitment_tree, wallet::init::init_wallet_db, AccountUuid,
    ReceivedNoteId, WalletDb,
};
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, MainNetwork},
    memo::MemoBytes,
    value::Zatoshis,
    ShieldedProtocol,
};

// =============================================================================
// Types
// =============================================================================

/// Account balance breakdown.
#[derive(Debug, Clone)]
pub struct AccountBalance {
    pub total: Zatoshis,
}

impl Default for AccountBalance {
    fn default() -> Self {
        Self {
            total: Zatoshis::ZERO,
        }
    }
}

/// A decrypted memo with its associated value.
#[derive(Debug, Clone)]
pub struct DecryptedMemo {
    pub txid: TxId,
    pub memo: MemoBytes,
    pub value: Zatoshis,
}

/// The wallet database type used throughout ZVS.
pub type WalletDbType = WalletDb<rusqlite::Connection, MainNetwork, SystemClock, rand::rngs::OsRng>;

/// Error type alias for propose/create functions.
type WalletError = zcash_client_backend::data_api::error::Error<
    zcash_client_sqlite::error::SqliteClientError,
    commitment_tree::Error,
    zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelectorError,
    zcash_primitives::transaction::fees::zip317::FeeError,
    zcash_primitives::transaction::fees::zip317::FeeError,
    ReceivedNoteId,
>;

// =============================================================================
// Wallet
// =============================================================================

/// ZVS Wallet - handles all Zcash wallet operations.
///
/// The wallet is purely local - it handles keys, database, and crypto.
/// Network operations (streaming, broadcasting) are handled by the caller
/// who passes a client when needed.
pub struct Wallet {
    db: WalletDbType,
    account_id: AccountUuid,
    usk: UnifiedSpendingKey,
}

impl Wallet {
    /// Create a new wallet, initializing the database.
    ///
    /// If this is a new wallet (no existing account), `birthday` must be provided.
    /// For existing wallets, `birthday` is ignored.
    pub fn new(seed: &[u8], birthday: Option<&AccountBirthday>, data_dir: &Path) -> Result<Self> {
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
            let usk = UnifiedSpendingKey::from_seed(&MainNetwork, seed, zip32::AccountId::ZERO)
                .map_err(|e| anyhow!("Failed to derive spending key: {e:?}"))?;
            (*existing_id, usk)
        } else {
            info!("Creating new account from seed");
            let birthday = birthday.ok_or_else(|| anyhow!("Birthday required for new wallet"))?;
            let seed_secret: Secret<Vec<u8>> = Secret::new(seed.to_vec());
            let (account_id, usk) = db
                .create_account("ZVS Wallet", &seed_secret, birthday, None)
                .map_err(|e| anyhow!("Failed to create account: {e}"))?;
            info!("Created account: {:?}", account_id);
            (account_id, usk)
        };

        Ok(Self {
            db,
            account_id,
            usk,
        })
    }

    // =========================================================================
    // Database Access (for sync)
    // =========================================================================

    /// Get mutable access to the wallet database for sync operations.
    pub fn db_mut(&mut self) -> &mut WalletDbType {
        &mut self.db
    }

    /// Sync wallet with the blockchain.
    ///
    /// Downloads compact blocks and scans for relevant transactions.
    /// Uses in-memory block cache (re-downloads on each run).
    /// After scanning, fetches full transactions to decrypt memos.
    pub async fn sync(
        &mut self,
        client: &mut zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient<tonic::transport::Channel>,
    ) -> Result<()> {
        let db_cache = crate::sync::MemBlockCache::new();

        info!("Starting wallet sync...");

        zcash_client_backend::sync::run(
            client,
            &MainNetwork,
            &db_cache,
            &mut self.db,
            10_000, // batch size
        )
        .await
        .map_err(|e| anyhow!("Sync failed: {:?}", e))?;

        info!("Wallet sync complete, processing enhancement requests...");

        // Process transaction enhancement requests to fetch full transactions and decrypt memos
        let requests = self
            .db
            .transaction_data_requests()
            .map_err(|e| anyhow!("Failed to get transaction data requests: {:?}", e))?;

        let mut enhanced_count = 0;
        for request in requests {
            if let TransactionDataRequest::Enhancement(txid) = request {
                debug!("Enhancing transaction: {}", hex::encode(txid.as_ref()));

                // Fetch full transaction from lightwalletd
                let response = client
                    .get_transaction(TxFilter {
                        block: None,
                        index: 0,
                        hash: txid.as_ref().to_vec(),
                    })
                    .await
                    .map_err(|e| {
                        anyhow!(
                            "Failed to fetch transaction {}: {:?}",
                            hex::encode(txid.as_ref()),
                            e
                        )
                    })?;

                let raw_tx = response.into_inner();

                // Get the mined height for this transaction
                let mined_height = self
                    .db
                    .get_tx_height(txid)
                    .map_err(|e| anyhow!("Failed to get tx height: {:?}", e))?;

                // Determine the branch ID for parsing
                let branch_id = mined_height
                    .map(|h| BranchId::for_height(&MainNetwork, h))
                    .unwrap_or(BranchId::Nu5);

                // Parse the transaction
                let tx = Transaction::read(&raw_tx.data[..], branch_id)
                    .map_err(|e| anyhow!("Failed to parse transaction: {:?}", e))?;

                // Decrypt and store the transaction (this updates memos in the DB)
                decrypt_and_store_transaction(&MainNetwork, &mut self.db, &tx, mined_height)
                    .map_err(|e| anyhow!("Failed to decrypt and store transaction: {:?}", e))?;

                enhanced_count += 1;
            }
        }

        if enhanced_count > 0 {
            info!("Enhanced {} transactions with full memo data", enhanced_count);
        }

        Ok(())
    }

    // =========================================================================
    // Transaction Sending
    // =========================================================================

    /// Send a transaction.
    ///
    /// Takes a ZIP-321 transaction request, builds the transaction, and broadcasts it.
    pub async fn send_transaction(
        &mut self,
        client: &mut CompactTxStreamerClient<Channel>,
        request: TransactionRequest,
    ) -> Result<TxId> {
        let input_selector = GreedyInputSelector::new();
        let change_strategy = create_change_strategy();

        // Step 1: Propose transfer (select inputs)
        info!("Proposing transfer...");
        let result: Result<_, WalletError> = propose_transfer(
            &mut self.db,
            &MainNetwork,
            self.account_id,
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::default(),
        );
        let proposal = result.map_err(|e| anyhow!("Propose failed: {:?}", e))?;

        // Step 2: Create and sign transaction
        info!("Creating transaction...");
        let prover = LocalTxProver::bundled();
        let result: Result<_, WalletError> = create_proposed_transactions(
            &mut self.db,
            &MainNetwork,
            &prover,
            &prover,
            &SpendingKeys::from_unified_spending_key(self.usk.clone()),
            OvkPolicy::Sender,
            &proposal,
        );
        let txids = result.map_err(|e| anyhow!("Create tx failed: {:?}", e))?;

        let txid = *txids.first();

        // Step 3: Get raw transaction from DB
        let tx_data = self
            .db
            .get_transaction(txid)
            .map_err(|e| anyhow!("Failed to get tx: {:?}", e))?
            .ok_or_else(|| anyhow!("Transaction not found after creation"))?;

        let mut raw_tx_bytes = Vec::new();
        tx_data
            .write(&mut raw_tx_bytes)
            .map_err(|e| anyhow!("Failed to serialize tx: {:?}", e))?;

        // Step 4: Broadcast
        info!("Broadcasting transaction...");
        let response = client
            .send_transaction(RawTransaction {
                data: raw_tx_bytes,
                height: 0,
            })
            .await
            .map_err(|e| anyhow!("Broadcast failed: {:?}", e))?;

        let send_response = response.into_inner();
        if send_response.error_code != 0 {
            return Err(anyhow!(
                "Broadcast rejected: {}",
                send_response.error_message
            ));
        }

        info!("Transaction sent: {}", hex::encode(txid.as_ref()));
        Ok(txid)
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
            total: balance.total(),
        })
    }

    // =========================================================================
    // Memo Decryption Methods
    // =========================================================================

    /// Decrypt memos from a transaction.
    ///
    /// Uses the wallet's viewing key to decrypt any outputs addressed to us.
    /// Returns only incoming transfers (not change or outgoing).
    pub fn decrypt_memo(&self, tx: &Transaction, height: BlockHeight) -> Option<DecryptedMemo> {
        let ufvk = self.usk.to_unified_full_viewing_key();

        // Build the UFVK map (we only have one account)
        let mut ufvks = HashMap::new();
        ufvks.insert(0u32, ufvk);

        // Use the unified decrypt_transaction API from zcash_client_backend
        let decrypted = decrypt_transaction(
            &MainNetwork,
            Some(height),
            None, // chain_tip not needed for mempool
            tx,
            &ufvks,
        );

        // Process Sapling outputs first
        for output in decrypted.sapling_outputs() {
            if !matches!(output.transfer_type(), TransferType::Incoming) {
                continue;
            }

            debug!("Decrypted Sapling memo");
            return Some(DecryptedMemo {
                txid: tx.txid(),
                memo: output.memo().clone(),
                value: output.note_value(),
            });
        }

        // Process Orchard outputs
        for output in decrypted.orchard_outputs() {
            if !matches!(output.transfer_type(), TransferType::Incoming) {
                continue;
            }

            debug!("Decrypted Orchard memo");
            return Some(DecryptedMemo {
                txid: tx.txid(),
                memo: output.memo().clone(),
                value: output.note_value(),
            });
        }

        None
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Create the change strategy for transactions.
///
/// Uses Sapling for change outputs (widely compatible) with ZIP-317 fees.
fn create_change_strategy<I>() -> MultiOutputChangeStrategy<StandardFeeRule, I> {
    MultiOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None, // no memo for change
        ShieldedProtocol::Sapling,
        DustOutputPolicy::default(),
        SplitPolicy::with_min_output_value(
            NonZeroUsize::new(1).unwrap(),
            Zatoshis::const_from_u64(5_000),
        ),
    )
}
