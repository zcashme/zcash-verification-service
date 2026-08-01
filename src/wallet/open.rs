//! Opening and initializing the per-wallet `zcash_client_sqlite` databases.
//!
//! Ported from zecd's `wallet/open.rs`, simplified for ZFA (Orchard-only, no
//! transparent gap limits). The wallet DB is exclusively owned and migrated
//! by `zcash_client_sqlite` — ZFA response idempotence lives separately in
//! `responses.sqlite`.

use std::path::{Path, PathBuf};

use rand::rngs::OsRng;

use zcash_client_sqlite::chain::init::init_blockmeta_db;
use zcash_client_sqlite::chain::BlockMeta;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::init::init_wallet_db;
use zcash_client_sqlite::{FsBlockDb, WalletDb};

use crate::network::ZNetwork;

const DATA_DB: &str = "data.sqlite";
const BLOCKS_FOLDER: &str = "blocks";

/// A read/write wallet handle (uses a real clock + OS RNG, required for writes).
pub type WriteDb = WalletDb<rusqlite::Connection, ZNetwork, SystemClock, OsRng>;

pub fn data_db_path(wallet_dir: &Path) -> PathBuf {
    wallet_dir.join(DATA_DB)
}

pub fn block_path(wallet_dir: &Path, meta: &BlockMeta) -> PathBuf {
    meta.block_file_path(&wallet_dir.join(BLOCKS_FOLDER))
}

/// Open the wallet DB for writing (sync, sends, address generation).
pub fn open_write(network: ZNetwork, wallet_dir: &Path) -> anyhow::Result<WriteDb> {
    let path = data_db_path(wallet_dir);
    let conn = rusqlite::Connection::open(&path)?;
    restrict_wallet_db_permissions(&path)?;
    configure_writer_conn(&conn)?;
    Ok(WalletDb::from_connection(conn, network, SystemClock, OsRng))
}

/// `data.sqlite` contains the service viewing key and decrypted transaction
/// metadata. Keep it owner-readable only, like the encrypted key store.
#[cfg(unix)]
fn restrict_wallet_db_permissions(path: &Path) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = std::fs::metadata(path)
        .with_context(|| format!("reading wallet database permissions at {}", path.display()))?
        .permissions();
    if permissions.mode() & 0o077 != 0 {
        permissions.set_mode(0o600);
        std::fs::set_permissions(path, permissions).with_context(|| {
            format!(
                "restricting wallet database permissions at {}",
                path.display()
            )
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict_wallet_db_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// Apply the write-path PRAGMAs (and the array vtab module `WalletDb` requires).
fn configure_writer_conn(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    rusqlite::vtab::array::load_module(conn)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
}

/// Open the compact-block cache.
pub fn open_fsblockdb(wallet_dir: &Path) -> anyhow::Result<FsBlockDb> {
    FsBlockDb::for_path(wallet_dir).map_err(|e| anyhow::anyhow!("opening block-cache db: {e}"))
}

/// Initialize both the wallet DB and the block-cache DB (idempotent migrations).
pub fn init_dbs(network: ZNetwork, wallet_dir: &Path) -> anyhow::Result<WriteDb> {
    std::fs::create_dir_all(wallet_dir)?;
    enable_wal(wallet_dir)?;
    let mut db_cache = open_fsblockdb(wallet_dir)?;
    let mut db_data = open_write(network, wallet_dir)?;
    init_blockmeta_db(&mut db_cache)
        .map_err(|e| anyhow::anyhow!("initializing block-cache db: {e}"))?;
    init_wallet_db(&mut db_data, None)?;
    Ok(db_data)
}

/// Put the wallet DB into WAL journal mode (persistent, per-database setting).
fn enable_wal(wallet_dir: &Path) -> anyhow::Result<()> {
    let conn = rusqlite::Connection::open(data_db_path(wallet_dir))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.query_row("PRAGMA journal_mode=WAL;", [], |_| Ok(()))?;
    Ok(())
}
