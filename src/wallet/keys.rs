//! In-memory custody of the decrypted wallet seed and on-demand spending-key
//! derivation.
//!
//! Ported from zecd's `wallet/keys.rs`, adapted for ZFA (no RpcError, simpler
//! error handling). The seed is held as a zeroizing secret in mlock'd memory
//! and never persisted in the clear. The Unified Spending Key is derived fresh
//! per operation and never cached.

use std::path::Path;

use secrecy::{ExposeSecret, SecretVec};
use zcash_keys::keys::UnifiedSpendingKey;

use crate::hardening;
use crate::network::ZNetwork;
use crate::wallet::store::WalletStore;

/// The decrypted seed held in mlock'd memory: pinned into RAM (best-effort)
/// so it is never written to swap, and zeroized + munlocked on drop.
struct MlockedSeed {
    seed: SecretVec<u8>,
    locked: bool,
}

impl MlockedSeed {
    fn new(seed: SecretVec<u8>) -> Self {
        let locked = hardening::lock_secret(seed.expose_secret());
        MlockedSeed { seed, locked }
    }

    fn expose(&self) -> &[u8] {
        self.seed.expose_secret()
    }
}

impl Drop for MlockedSeed {
    fn drop(&mut self) {
        hardening::unlock_secret(self.seed.expose_secret(), self.locked);
    }
}

/// Holds the decrypted seed (when unlocked). Sending (OTP response transactions)
/// requires this to be unlocked.
#[derive(Default)]
pub struct SeedKeeper {
    seed: Option<MlockedSeed>,
}

impl SeedKeeper {
    pub fn locked() -> Self {
        SeedKeeper { seed: None }
    }

    pub fn lock(&mut self) {
        self.seed = None;
    }

    pub fn set(&mut self, seed: SecretVec<u8>) {
        self.seed = Some(MlockedSeed::new(seed));
    }

    pub fn is_unlocked(&self) -> bool {
        self.seed.is_some()
    }

    /// A copy of the decrypted seed, if loaded — for recreating the wallet
    /// account from keys.toml on an empty datadir.
    pub fn clone_seed(&self) -> Option<SecretVec<u8>> {
        self.seed.as_ref().map(|s| SecretVec::new(s.expose().to_vec()))
    }

    /// Derive the Unified Spending Key for an account index, or an error if the
    /// seed is not loaded.
    pub fn derive_usk(
        &self,
        network: ZNetwork,
        account_index: zip32::AccountId,
    ) -> anyhow::Result<UnifiedSpendingKey> {
        let seed = self
            .seed
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("wallet is locked — seed not loaded"))?;
        UnifiedSpendingKey::from_seed(&network, seed.expose(), account_index)
            .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))
    }
}

/// Refuse to load an age identity from anything but a regular file with
/// owner-only permissions. Best-effort on non-Unix.
pub fn check_identity_file_permissions(identity_path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use anyhow::Context as _;
        use std::os::unix::fs::PermissionsExt as _;

        let meta = std::fs::metadata(identity_path).with_context(|| {
            format!("reading the age identity file {}", identity_path.display())
        })?;
        if !meta.is_file() {
            anyhow::bail!(
                "age identity path {} does not resolve to a regular file",
                identity_path.display(),
            );
        }
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "age identity file {} has insecure permissions {mode:#o}: it must be \
                 readable only by its owner (try chmod 600)",
                path = identity_path.display(),
                mode = mode & 0o7777,
            );
        }
    }
    #[cfg(not(unix))]
    let _ = identity_path;
    Ok(())
}

/// Load age identities from a file and decrypt the wallet's stored seed.
pub fn decrypt_seed_with_identity(
    store: &WalletStore,
    identity_path: &Path,
) -> anyhow::Result<Option<SecretVec<u8>>> {
    check_identity_file_permissions(identity_path)?;
    let identities = age::IdentityFile::from_file(identity_path.to_string_lossy().into_owned())?
        .into_identities()?;
    store.decrypt_seed(identities.iter().map(|i| i.as_ref() as _))
}