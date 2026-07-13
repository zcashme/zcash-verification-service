//! Per-wallet on-disk metadata (`keys.toml`): network, birthday height, and
//! the age-encrypted BIP-39 mnemonic.
//!
//! Ported from zecd's `wallet/store.rs`, adapted for ZFA (no watch-only
//! wallet support, simpler error handling).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::anyhow;
use bip0039::{English, Mnemonic};
use secrecy::{ExposeSecret, SecretVec, Zeroize};
use serde::{Deserialize, Serialize};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use crate::network::ZNetwork;

/// A wallet passphrase, in age's own secrecy type.
pub type Passphrase = age::secrecy::SecretString;

const KEYS_FILE: &str = "keys.toml";

/// `keys.toml` `encryption` marker: `"passphrase"` means the mnemonic is
/// wrapped with a passphrase (age scrypt). Absent means the identity-file model.
const ENC_PASSPHRASE: &str = "passphrase";

pub fn keys_path(wallet_dir: &Path) -> PathBuf {
    wallet_dir.join(KEYS_FILE)
}

/// Parsed `keys.toml`.
pub struct WalletStore {
    pub network: ZNetwork,
    pub birthday: BlockHeight,
    seed_ciphertext: Option<String>,
    encrypted: bool,
    pinned_ufvk: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct StoreEncoding {
    mnemonic: Option<String>,
    network: Option<String>,
    birthday: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encryption: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ufvk: Option<String>,
}

impl WalletStore {
    /// True if a `keys.toml` exists at this path.
    pub fn exists(keys_path: &Path) -> bool {
        keys_path.exists()
    }

    /// Create a new `keys.toml` holding the mnemonic encrypted to the age identity.
    pub fn init_with_mnemonic<'a>(
        keys_path: &Path,
        recipients: impl Iterator<Item = &'a dyn age::Recipient>,
        mnemonic: &Mnemonic,
        birthday: BlockHeight,
        network: ZNetwork,
        ufvk: &str,
    ) -> anyhow::Result<()> {
        let encoding = StoreEncoding {
            mnemonic: Some(encrypt_mnemonic(recipients, mnemonic)?),
            network: Some(network.name().to_string()),
            birthday: Some(u32::from(birthday)),
            encryption: None,
            ufvk: Some(ufvk.to_string()),
        };
        write_keys_atomic(keys_path, &encoding, true)
    }

    /// Create a new `keys.toml` with the mnemonic passphrase-encrypted (age scrypt).
    pub fn init_with_passphrase(
        keys_path: &Path,
        passphrase: Passphrase,
        mnemonic: &Mnemonic,
        birthday: BlockHeight,
        network: ZNetwork,
        ufvk: &str,
    ) -> anyhow::Result<()> {
        let encoding = StoreEncoding {
            mnemonic: Some(encrypt_phrase_with_passphrase(passphrase, mnemonic.phrase())?),
            network: Some(network.name().to_string()),
            birthday: Some(u32::from(birthday)),
            encryption: Some(ENC_PASSPHRASE.to_string()),
            ufvk: Some(ufvk.to_string()),
        };
        write_keys_atomic(keys_path, &encoding, true)
    }

    /// Record the UFVK pin into keys.toml (backfill for pre-pin files).
    pub fn pin_ufvk(keys_path: &Path, ufvk: &str) -> anyhow::Result<()> {
        let mut text = String::new();
        std::fs::File::open(keys_path)
            .map_err(|e| anyhow!("opening {}: {e}", keys_path.display()))?
            .read_to_string(&mut text)?;
        let mut encoding: StoreEncoding = toml::from_str(&text)?;
        if encoding.ufvk.as_deref() == Some(ufvk) {
            return Ok(());
        }
        encoding.ufvk = Some(ufvk.to_string());
        write_keys_atomic(keys_path, &encoding, false)
    }

    pub fn read(keys_path: &Path) -> anyhow::Result<WalletStore> {
        let mut text = String::new();
        std::fs::File::open(keys_path)
            .map_err(|e| anyhow!("opening {}: {e}", keys_path.display()))?
            .read_to_string(&mut text)?;
        let encoding: StoreEncoding = toml::from_str(&text)?;

        let network = encoding
            .network
            .as_deref()
            .map(ZNetwork::parse)
            .transpose()?
            .unwrap_or(ZNetwork::Test);

        let birthday = encoding.birthday.map(BlockHeight::from).unwrap_or_else(|| {
            network
                .activation_height(NetworkUpgrade::Nu5)
                .expect("NU5 activation height is known")
        });

        let encrypted = encoding.encryption.as_deref() == Some(ENC_PASSPHRASE);

        Ok(WalletStore {
            network,
            birthday,
            seed_ciphertext: encoding.mnemonic,
            encrypted,
            pinned_ufvk: encoding.ufvk,
        })
    }

    /// Decrypt the stored mnemonic and derive the BIP-39 seed.
    pub fn decrypt_seed<'a>(
        &self,
        identities: impl Iterator<Item = &'a dyn age::Identity>,
    ) -> anyhow::Result<Option<SecretVec<u8>>> {
        self.seed_ciphertext
            .as_ref()
            .map(|ct| decrypt_seed(identities, ct))
            .transpose()
    }

    /// Derive the BIP-39 seed from a passphrase-encrypted mnemonic.
    pub fn decrypt_seed_with_passphrase(
        &self,
        passphrase: Passphrase,
    ) -> anyhow::Result<Option<SecretVec<u8>>> {
        self.seed_ciphertext
            .as_ref()
            .map(|ct| {
                let id = age::scrypt::Identity::new(passphrase);
                decrypt_seed(std::iter::once(&id as &dyn age::Identity), ct)
            })
            .transpose()
    }

    pub fn has_seed(&self) -> bool {
        self.seed_ciphertext.is_some()
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    pub fn pinned_ufvk(&self) -> Option<&str> {
        self.pinned_ufvk.as_deref()
    }
}

/// Serialize `encoding` to `keys.toml` atomically (temp + rename).
fn write_keys_atomic(path: &Path, encoding: &StoreEncoding, create_new: bool) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = toml::to_string(encoding).map_err(|_| anyhow!("serializing keys.toml"))?;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if create_new {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    if create_new {
        let mut file = opts
            .open(path)
            .map_err(|e| anyhow!("creating {}: {e}", path.display()))?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
    } else {
        let tmp = path.with_extension("toml.tmp");
        {
            let mut file = opts
                .open(&tmp)
                .map_err(|e| anyhow!("creating {}: {e}", tmp.display()))?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, path).map_err(|e| anyhow!("replacing {}: {e}", path.display()))?;
    }
    Ok(())
}

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

fn encrypt_phrase_with_passphrase(passphrase: Passphrase, phrase: &str) -> anyhow::Result<String> {
    let encryptor = age::Encryptor::with_user_passphrase(passphrase);
    let mut ciphertext = vec![];
    let mut writer = encryptor.wrap_output(age::armor::ArmoredWriter::wrap_output(
        &mut ciphertext,
        age::armor::Format::AsciiArmor,
    )?)?;
    writer.write_all(phrase.as_bytes())?;
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