//! ZVS Wallet - Core wallet implementation for Zcash operations.
//!
//! This module provides a complete wallet abstraction over zcash_client_sqlite,
//! handling account management, mempool streaming, transaction building, and
//! memo decryption.

use std::convert::Infallible;
use std::path::Path;

use anyhow::{anyhow, Result};
use secrecy::Secret;
use tonic::transport::Channel;
use tracing::{debug, info};

use zcash_client_backend::{
    data_api::{
        wallet::{
            create_proposed_transactions, input_selection::GreedyInputSelector, propose_transfer,
            ConfirmationsPolicy, SpendingKeys,
        },
        AccountBirthday, WalletRead, WalletWrite,
    },
    proto::service::{
        compact_tx_streamer_client::CompactTxStreamerClient, BlockId, ChainSpec,
        RawTransaction, TxFilter,
    },
    wallet::OvkPolicy,
    zip321::TransactionRequest,
};
use zcash_client_sqlite::{util::SystemClock, wallet::init::init_wallet_db, AccountUuid, WalletDb};
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    consensus::{BlockHeight, MainNetwork},
    value::Zatoshis,
};

use crate::memo_rules::{validate_memo, VerificationData};
use crate::otp_rules::create_change_strategy;
use crate::scan::decrypt_first_memo;

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

/// A received memo with metadata.
#[derive(Debug, Clone)]
pub struct ReceivedMemo {
    pub txid_hex: String,
    pub memo: String,
    pub value: Zatoshis,
    pub verification: Option<VerificationData>,
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
    // Memo Methods
    // =========================================================================

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

        // Decrypt memo using unified API (handles both Sapling and Orchard)
        let ufvk = self.usk.to_unified_full_viewing_key();

        if let Some(decrypted) = decrypt_first_memo(&tx, &ufvk, block_height)? {
            let verification = validate_memo(&decrypted.memo_text);

            return Ok(Some(ReceivedMemo {
                txid_hex,
                memo: decrypted.memo_text,
                value: decrypted.value, // Value now comes from decryption
                verification,
            }));
        }

        Ok(None)
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
}
