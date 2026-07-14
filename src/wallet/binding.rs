//! Cryptographically bind the service account in `data.sqlite` to the seed
//! in `zfa.toml`.
//!
//! `data.sqlite` is rebuildable chain state, but its selected account decides
//! which address the worker receives payments at. A database replacement must
//! therefore fail closed rather than silently redirect future authentication
//! payments. At startup the worker derives a UFVK from the decrypted seed and
//! compares it to the UFVK in the wallet database — a mismatch means the
//! database was swapped and the worker refuses to start.

use anyhow::anyhow;
use secrecy::{ExposeSecret as _, SecretVec};
use zcash_client_backend::data_api::{Account as _, WalletRead as _};
use zcash_client_sqlite::AccountUuid;
use zcash_keys::keys::UnifiedSpendingKey;

use crate::network::ZNetwork;
use crate::wallet::open::WriteDb;

/// Return the network-specific encoded UFVK for the selected wallet account.
pub fn account_ufvk_encoded(
    network: ZNetwork,
    db: &WriteDb,
    account_id: AccountUuid,
) -> anyhow::Result<String> {
    let account = db
        .get_account(account_id)?
        .ok_or_else(|| anyhow!("selected account was not found in the wallet database"))?;
    let ufvk = account
        .ufvk()
        .ok_or_else(|| anyhow!("selected account has no unified full viewing key"))?;
    Ok(ufvk.encode(&network))
}

/// Derive the network-specific encoded UFVK from the service seed at account
/// zero, the same ZIP-32 account index used by wallet initialization.
pub fn seed_ufvk_encoded(network: ZNetwork, seed: &SecretVec<u8>) -> anyhow::Result<String> {
    let account_index = zip32::AccountId::try_from(crate::config::ACCOUNT_INDEX)
        .map_err(|_| anyhow!("account {} is not a valid ZIP-32 account", crate::config::ACCOUNT_INDEX))?;
    let usk = UnifiedSpendingKey::from_seed(&network, seed.expose_secret(), account_index)
        .map_err(|_| anyhow!("deriving the service unified spending key failed"))?;
    Ok(usk.to_unified_full_viewing_key().encode(&network))
}