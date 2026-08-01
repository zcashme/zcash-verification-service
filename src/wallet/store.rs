//! Per-wallet on-disk metadata: the `[seed]` table inside `zfa.toml` (or a
//! `--keys-file` Secret mount), containing the birthday height and the
//! age-encrypted BIP-39 mnemonic.
//!
//! Simplified from zecd's `wallet/store.rs`: no UFVK pin, no passphrase
//! encryption, no network field (network is an operational constant, not a
//! per-wallet setting). The mnemonic is always wrapped to the age identity
//! file for unattended decryption.

use std::io::{Read, Write};
use std::path::Path;

use anyhow::anyhow;
use bip0039::{English, Mnemonic};
use secrecy::{ExposeSecret, SecretVec, Zeroize};
use zcash_protocol::consensus::BlockHeight;

use crate::config::ConfigFile;

/// Parsed `[seed]` table from `zfa.toml`.
pub struct WalletStore {
    pub birthday: BlockHeight,
    seed_ciphertext: String,
}

/// The on-disk `[seed]` table, read from a TOML file.
impl WalletStore {
    /// True if a `[seed]` table exists in the config file at `path`.
    pub fn exists(path: &Path) -> bool {
        match ConfigFile::read(path) {
            Ok(cfg) => cfg.seed.is_some(),
            Err(_) => false,
        }
    }

    /// Write a new `[seed]` table to `path` with the mnemonic encrypted to the
    /// age identity. The file is created `0600`.
    pub fn init_with_mnemonic<'a>(
        path: &Path,
        recipients: impl Iterator<Item = &'a dyn age::Recipient>,
        mnemonic: &Mnemonic,
        birthday: BlockHeight,
    ) -> anyhow::Result<()> {
        let ciphertext = encrypt_mnemonic(recipients, mnemonic)?;
        ConfigFile::write_seed(path, u32::from(birthday), &ciphertext)
    }

    /// Read the `[seed]` table from `path`.
    pub fn read(path: &Path) -> anyhow::Result<WalletStore> {
        let cfg = ConfigFile::read(path)?;
        let seed = cfg
            .seed
            .ok_or_else(|| anyhow!("no [seed] table in {}", path.display()))?;
        Ok(WalletStore {
            birthday: BlockHeight::from(seed.birthday),
            seed_ciphertext: seed.mnemonic,
        })
    }

    /// Decrypt the stored mnemonic and derive the BIP-39 seed.
    pub fn decrypt_seed<'a>(
        &self,
        identities: impl Iterator<Item = &'a dyn age::Identity>,
    ) -> anyhow::Result<SecretVec<u8>> {
        decrypt_seed(identities, &self.seed_ciphertext)
    }
}

// ── Encryption / decryption ──────────────────────────────────────────────────

fn encrypt_mnemonic<'a>(
    recipients: impl Iterator<Item = &'a dyn age::Recipient>,
    mnemonic: &Mnemonic,
) -> anyhow::Result<String> {
    let encryptor = age::Encryptor::with_recipients(recipients)?;
    let mut ciphertext = vec![];
    let mut writer = encryptor.wrap_output(age::armor::ArmoredWriter::wrap_output(
        &mut ciphertext,
        age::armor::Format::AsciiArmor,
    )?)?;
    writer.write_all(mnemonic.phrase().as_bytes())?;
    writer.finish().and_then(|armor| armor.finish())?;
    Ok(String::from_utf8(ciphertext).expect("armor is valid UTF-8"))
}

fn decrypt_mnemonic<'a>(
    identities: impl Iterator<Item = &'a dyn age::Identity>,
    ciphertext: &str,
) -> anyhow::Result<SecretVec<u8>> {
    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(ciphertext.as_bytes()))?;
    let mut buf = vec![];
    let ret = decryptor.decrypt(identities)?.read_to_end(&mut buf);
    let res = SecretVec::new(buf);
    ret?;
    Ok(res)
}

fn decrypt_seed<'a>(
    identities: impl Iterator<Item = &'a dyn age::Identity>,
    ciphertext: &str,
) -> anyhow::Result<SecretVec<u8>> {
    let mnemonic_bytes = decrypt_mnemonic(identities, ciphertext)?;
    let phrase = std::str::from_utf8(mnemonic_bytes.expose_secret())?;
    let mut seed = <Mnemonic<English>>::from_phrase(phrase)?.to_seed("");
    let secret = SecretVec::new(seed.to_vec());
    seed.zeroize();
    Ok(secret)
}
