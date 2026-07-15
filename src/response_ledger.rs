//! Durable, worker-local idempotence for OTP response transactions.
//!
//! This is deliberately not a login-session store. Consumer applications own
//! their sessions, expiry, and OTP verification. The worker records only the
//! fact that a particular incoming transaction has claimed one response, plus
//! the response transaction ID once the wallet has constructed it. It does
//! not retain session IDs, return addresses, payment amounts, or pool details:
//! none are necessary for idempotence, and retaining them would create a
//! needless address-to-login-history database.
//!
//! A crash after wallet construction but before recording `response_txid`
//! cannot safely be retried by constructing a second transaction, so the
//! `claimed` state is terminal until operator-assisted recovery is implemented.
//! That policy biases toward withholding a response over spending wallet funds
//! twice.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use rusqlite::{Connection, OptionalExtension};
use zcash_protocol::TxId;

/// The persistent status of one incoming authentication transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseState {
    /// A response was claimed but a transaction ID was not yet durably recorded.
    Claimed,
    /// The wallet constructed a response transaction; it has not yet been sent
    /// to the network. Safe to rebroadcast this txid.
    Created { response_txid: TxId },
    /// The response transaction is in flight to the network. A crash in this
    /// state leaves the actual network status unknown — the tx may or may not
    /// be in the mempool — so the restart path rebroadcasts defensively. The
    /// common LWD/zebra outcome for a rebroadcast is "already exists", which
    /// is exactly the precondition `record_broadcast` tracks.
    Broadcasting { response_txid: TxId },
    /// lightwalletd accepted the response transaction for broadcast (or
    /// acknowledged it as already known).
    Broadcast { response_txid: TxId },
}

/// Result of atomically claiming an incoming transaction for an OTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    Acquired,
    AlreadyHandled(ResponseState),
}

/// A response that was constructed locally but has not yet been acknowledged
/// by the configured lightwalletd/Zaino server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingBroadcast {
    pub incoming_txid: String,
    pub response_txid: TxId,
}

/// Initialize the worker-local response ledger.
pub fn init_db(path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("opening response ledger at {}", path.display()))?;
    restrict_permissions(path)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         CREATE TABLE IF NOT EXISTS otp_response_ledger (
             incoming_txid TEXT PRIMARY KEY NOT NULL,
             state TEXT NOT NULL CHECK (state IN ('claimed', 'created', 'broadcasting', 'broadcast')),
             response_txid BLOB,
             received_at INTEGER NOT NULL,
             created_at INTEGER,
             broadcast_at INTEGER,
             CHECK (
                (state = 'claimed' AND response_txid IS NULL)
                OR (state IN ('created', 'broadcasting', 'broadcast') AND response_txid IS NOT NULL)
             )
         );",
    )?;
    Ok(conn)
}

/// The ledger contains only public transaction identifiers, but it is kept
/// owner-readable to avoid disclosing service activity metadata.
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = std::fs::metadata(path)
        .with_context(|| format!("reading response ledger permissions at {}", path.display()))?
        .permissions();
    if permissions.mode() & 0o077 != 0 {
        permissions.set_mode(0o600);
        std::fs::set_permissions(path, permissions).with_context(|| {
            format!(
                "restricting response ledger permissions at {}",
                path.display()
            )
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// Claim an incoming auth payment. At most one response is ever created for a
/// transaction ID, even if a lightwalletd/Zaino stream reconnect replays it.
pub fn claim(conn: &mut Connection, incoming_txid: &str) -> anyhow::Result<Claim> {
    let transaction = conn.transaction()?;
    let inserted = transaction.execute(
        "INSERT OR IGNORE INTO otp_response_ledger
         (incoming_txid, state, received_at)
         VALUES (?1, 'claimed', ?2)",
        rusqlite::params![incoming_txid, now_unix_seconds()?],
    )?;

    let result = if inserted == 1 {
        Claim::Acquired
    } else {
        let (state, response_txid): (String, Option<Vec<u8>>) = transaction.query_row(
            "SELECT state, response_txid FROM otp_response_ledger WHERE incoming_txid = ?1",
            [incoming_txid],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Claim::AlreadyHandled(parse_state(&state, response_txid)?)
    };
    transaction.commit()?;
    Ok(result)
}

/// Record a wallet-created response transaction before attempting broadcast.
pub fn record_created(
    conn: &mut Connection,
    incoming_txid: &str,
    response_txid: &TxId,
) -> anyhow::Result<()> {
    let changed = conn.execute(
        "UPDATE otp_response_ledger
         SET state = 'created', response_txid = ?1, created_at = ?2
         WHERE incoming_txid = ?3 AND state = 'claimed' AND response_txid IS NULL",
        rusqlite::params![
            response_txid.as_ref().as_slice(),
            now_unix_seconds()?,
            incoming_txid
        ],
    )?;
    if changed != 1 {
        anyhow::bail!("response ledger transition claimed -> created was rejected");
    }
    Ok(())
}

/// Mark a previously-created response transaction as accepted by the server.
pub fn record_broadcast(
    conn: &mut Connection,
    incoming_txid: &str,
    response_txid: &TxId,
) -> anyhow::Result<()> {
    let changed = conn.execute(
        "UPDATE otp_response_ledger
         SET state = 'broadcast', broadcast_at = ?1
         WHERE incoming_txid = ?2 AND state = 'created' AND response_txid = ?3",
        rusqlite::params![
            now_unix_seconds()?,
            incoming_txid,
            response_txid.as_ref().as_slice()
        ],
    )?;
    if changed != 1 {
        anyhow::bail!("response ledger transition created -> broadcast was rejected");
    }
    Ok(())
}

/// Return the persisted status for an incoming transaction, if any.
pub fn get(conn: &Connection, incoming_txid: &str) -> anyhow::Result<Option<ResponseState>> {
    conn.query_row(
        "SELECT state, response_txid FROM otp_response_ledger WHERE incoming_txid = ?1",
        [incoming_txid],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
    )
    .optional()?
    .map(|(state, response_txid)| parse_state(&state, response_txid))
    .transpose()
}

/// List responses whose transaction was persisted in the wallet but has not
/// yet received a successful broadcast acknowledgement. Rebroadcasting one of
/// these transactions is safe and is how the worker recovers an interruption
/// after construction but before transmission.
pub fn pending_broadcasts(conn: &Connection) -> anyhow::Result<Vec<PendingBroadcast>> {
    let mut statement = conn.prepare(
        "SELECT incoming_txid, response_txid
         FROM otp_response_ledger
         WHERE state = 'created'
         ORDER BY created_at ASC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
    })?;
    rows.map(|row| {
        let (incoming_txid, response_txid) = row?;
        Ok(PendingBroadcast {
            incoming_txid,
            response_txid: parse_txid(
                response_txid
                    .ok_or_else(|| anyhow::anyhow!("created response has no transaction ID"))?,
            )?,
        })
    })
    .collect()
}

fn parse_state(state: &str, response_txid: Option<Vec<u8>>) -> anyhow::Result<ResponseState> {
    match (state, response_txid) {
        ("claimed", None) => Ok(ResponseState::Claimed),
        ("created", Some(response_txid)) => Ok(ResponseState::Created {
            response_txid: parse_txid(response_txid)?,
        }),
        ("broadcasting", Some(response_txid)) => Ok(ResponseState::Broadcasting {
            response_txid: parse_txid(response_txid)?,
        }),
        ("broadcast", Some(response_txid)) => Ok(ResponseState::Broadcast {
            response_txid: parse_txid(response_txid)?,
        }),
        _ => anyhow::bail!("invalid response ledger row"),
    }
}

fn parse_txid(bytes: Vec<u8>) -> anyhow::Result<TxId> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("response ledger contains an invalid txid"))?;
    Ok(TxId::from_bytes(bytes))
}

fn now_unix_seconds() -> anyhow::Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("system clock is before the Unix epoch"))?
        .as_secs();
    i64::try_from(seconds).map_err(|_| anyhow::anyhow!("Unix timestamp exceeds SQLite range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_incoming_transaction_can_only_be_claimed_once() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let mut conn = init_db(&dir.path().join("responses.sqlite")).expect("ledger");
        assert_eq!(claim(&mut conn, "txid",).expect("claim"), Claim::Acquired);
        assert_eq!(
            claim(&mut conn, "txid",).expect("duplicate claim"),
            Claim::AlreadyHandled(ResponseState::Claimed)
        );
    }

    #[test]
    fn created_transaction_can_be_rebroadcast_without_creating_another() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let mut conn = init_db(&dir.path().join("responses.sqlite")).expect("ledger");
        claim(&mut conn, "txid").expect("claim");
        let response_txid = TxId::from_bytes([7; 32]);
        record_created(&mut conn, "txid", &response_txid).expect("record creation");
        assert_eq!(
            get(&conn, "txid").expect("read"),
            Some(ResponseState::Created { response_txid })
        );
        assert_eq!(
            pending_broadcasts(&conn).expect("pending broadcasts"),
            vec![PendingBroadcast {
                incoming_txid: "txid".to_owned(),
                response_txid,
            }]
        );
        record_broadcast(&mut conn, "txid", &response_txid).expect("record broadcast");
        assert!(pending_broadcasts(&conn)
            .expect("pending broadcasts")
            .is_empty());
        assert_eq!(
            get(&conn, "txid").expect("read"),
            Some(ResponseState::Broadcast { response_txid })
        );
    }
}
