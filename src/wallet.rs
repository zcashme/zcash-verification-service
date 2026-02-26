//! ZVS Wallet - local-only wallet operations.
//!
//! This module is purely local: keys, database, proving, and signing.
//! It performs NO network I/O. Broadcasting and block fetching are handled
//! by `mempool.rs` and `sync.rs` respectively.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::Path;

use anyhow::{anyhow, Result};
use secrecy::Secret;
use tracing::{debug, info};

use zcash_client_backend::{
    data_api::{
        wallet::{
            create_proposed_transactions, input_selection::GreedyInputSelector, propose_transfer,
            ConfirmationsPolicy, SpendingKeys,
        },
        AccountBirthday, WalletRead, WalletWrite,
    },
    decrypt_transaction,
    fees::{zip317::MultiOutputChangeStrategy, DustOutputPolicy, SplitPolicy, StandardFeeRule},
    wallet::OvkPolicy,
    zip321::TransactionRequest,
    TransferType,
};
use zcash_client_sqlite::{
    util::SystemClock, wallet::commitment_tree, wallet::init::init_wallet_db, AccountUuid,
    ReceivedNoteId, WalletDb,
};
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    consensus::{BlockHeight, MainNetwork},
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
    pub spendable: Zatoshis,
    pub sapling_spendable: Zatoshis,
    pub orchard_spendable: Zatoshis,
}

impl Default for AccountBalance {
    fn default() -> Self {
        Self {
            total: Zatoshis::ZERO,
            spendable: Zatoshis::ZERO,
            sapling_spendable: Zatoshis::ZERO,
            orchard_spendable: Zatoshis::ZERO,
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

/// ZVS Wallet - handles all local Zcash wallet operations.
///
/// Purely local: keys, database, proving, signing. No network I/O.
pub struct Wallet {
    db: WalletDbType,
    account_id: AccountUuid,
    usk: UnifiedSpendingKey,
    prover: LocalTxProver,
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

        info!("Loading proving parameters...");
        let prover = LocalTxProver::bundled();
        info!("Proving parameters loaded.");

        Ok(Self {
            db,
            account_id,
            usk,
            prover,
        })
    }

    // =========================================================================
    // Database Access (for sync task)
    // =========================================================================

    /// Mutable reference to the wallet database.
    ///
    /// Used by `sync::sync_wallet()` which needs direct DB access for
    /// `zcash_client_backend::sync::run()` and transaction enhancement.
    pub fn db_mut(&mut self) -> &mut WalletDbType {
        &mut self.db
    }

    /// Read-only reference to the wallet database.
    pub fn db(&self) -> &WalletDbType {
        &self.db
    }

    // =========================================================================
    // Transaction Creation (local only — no broadcast)
    // =========================================================================

    /// Create a signed transaction from a ZIP-321 request.
    ///
    /// Proposes inputs, creates and signs the transaction, serializes it.
    /// Returns the txid and raw bytes ready for broadcast.
    /// Does NOT broadcast — the caller is responsible for that.
    pub fn create_transaction(
        &mut self,
        request: TransactionRequest,
    ) -> Result<(TxId, Vec<u8>)> {
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
        let result: Result<_, WalletError> = create_proposed_transactions(
            &mut self.db,
            &MainNetwork,
            &self.prover,
            &self.prover,
            &SpendingKeys::from_unified_spending_key(self.usk.clone()),
            OvkPolicy::Sender,
            &proposal,
        );
        let txids = result.map_err(|e| anyhow!("Create tx failed: {:?}", e))?;

        let txid = *txids.first();

        // Step 3: Get raw transaction bytes from DB
        let tx_data = self
            .db
            .get_transaction(txid)
            .map_err(|e| anyhow!("Failed to get tx: {:?}", e))?
            .ok_or_else(|| anyhow!("Transaction not found after creation"))?;

        let mut raw_tx_bytes = Vec::new();
        tx_data
            .write(&mut raw_tx_bytes)
            .map_err(|e| anyhow!("Failed to serialize tx: {:?}", e))?;

        Ok((txid, raw_tx_bytes))
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

    /// Get the unified full viewing key for decryption.
    pub fn get_ufvk(&self) -> zcash_keys::keys::UnifiedFullViewingKey {
        self.usk.to_unified_full_viewing_key()
    }

    // =========================================================================
    // Balance Methods
    // =========================================================================

    /// Get the last synced block height.
    pub fn get_synced_height(&self) -> Option<u32> {
        self.db.chain_height().ok().flatten().map(u32::from)
    }

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
            spendable: balance.spendable_value(),
            sapling_spendable: balance.sapling_balance().spendable_value(),
            orchard_spendable: balance.orchard_balance().spendable_value(),
        })
    }
}

// =============================================================================
// Standalone Decryption
// =============================================================================

/// Decrypt memos from a transaction using a UFVK.
pub fn decrypt_memo_with_ufvk(
    ufvk: &zcash_keys::keys::UnifiedFullViewingKey,
    tx: &Transaction,
    height: BlockHeight,
) -> Option<DecryptedMemo> {
    let mut ufvks = HashMap::new();
    ufvks.insert(0u32, ufvk.clone());

    let decrypted = decrypt_transaction(&MainNetwork, Some(height), None, tx, &ufvks);

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
