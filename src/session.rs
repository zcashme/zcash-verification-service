//! `zfa.db` — the ZFA session database, separate from the wallet DB.
//!
//! Two tables:
//!
//! - `sessions`: created by the frontend (pending), authenticated by the worker.
//! - `processed_txids`: written by the worker to deduplicate transaction
//!   processing across mempool stream reconnects.
//!
//! The authentication transition is **atomic**: claiming the txid and updating
//! the session from `pending` to `authenticated` happens in one SQLite
//! transaction. If either operation fails, nothing changes.

use anyhow::Context;
use rusqlite::Connection;
use std::path::Path;

/// Initialize the ZFA session database (creates tables if missing).
pub fn init_db(path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("opening zfa.db at {}", path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sessions (
            session_id   TEXT PRIMARY KEY,
            status       TEXT NOT NULL DEFAULT 'pending',
            address      TEXT,
            txid         TEXT,
            user_address TEXT,
            created_at   INTEGER NOT NULL,
            expires_at   INTEGER NOT NULL,
            authenticated_at INTEGER,
            otp_challenge    TEXT,
            otp_status        TEXT DEFAULT 'none'
        );

        CREATE TABLE IF NOT EXISTS processed_txids (
            txid         TEXT PRIMARY KEY,
            session_id   TEXT NOT NULL,
            processed_at INTEGER NOT NULL
        );",
    )?;
    Ok(conn)
}

/// Create a new pending session. Called by the frontend (or test harness).
pub fn create_session(
    conn: &Connection,
    session_id: &str,
    created_at: i64,
    expires_at: i64,
) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO sessions (session_id, status, created_at, expires_at)
         VALUES (?1, 'pending', ?2, ?3)",
        rusqlite::params![session_id, created_at, expires_at],
    )?;
    Ok(())
}
/// from `pending` to `authenticated` in one transaction. If the txid was already
/// processed, or the session is not pending or has expired, nothing changes.
///
/// Returns `true` if the session was authenticated, `false` if it was skipped
/// (duplicate txid, wrong status, or expired).
pub fn authenticate_session(
    conn: &mut Connection,
    session_id: &str,
    txid_hex: &str,
    address: &str,
    now: i64,
) -> anyhow::Result<bool> {
    let tx = conn.transaction()?;

    // Claim the txid — if it's already processed, this is a duplicate.
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO processed_txids (txid, session_id, processed_at)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![txid_hex, session_id, now],
    )?;
    if inserted == 0 {
        // Already processed — skip.
        tx.rollback()?;
        return Ok(false);
    }

    // Transition the session from pending to authenticated, guarded by status
    // and expiry. If the session is not pending or has expired, roll back the
    // txid claim too.
    let updated = tx.execute(
        "UPDATE sessions
         SET status = 'authenticated',
             address = ?1,
             txid = ?2,
             authenticated_at = ?3
         WHERE session_id = ?4
           AND status = 'pending'
           AND expires_at > ?3",
        rusqlite::params![address, txid_hex, now, session_id],
    )?;
    if updated == 0 {
        // Session not pending or expired — undo the txid claim.
        tx.rollback()?;
        return Ok(false);
    }

    tx.commit()?;
    Ok(true)
}

/// Get the status of a session. Returns `None` if the session doesn't exist.
pub fn session_status(conn: &Connection, session_id: &str) -> anyhow::Result<Option<SessionStatus>> {
    let mut stmt = conn.prepare(
        "SELECT status, address, txid, user_address, authenticated_at, otp_status
         FROM sessions WHERE session_id = ?1",
    )?;
    let row = stmt
        .query_row(rusqlite::params![session_id], |r| {
            Ok(SessionStatus {
                status: r.get(0)?,
                address: r.get(1)?,
                txid: r.get(2)?,
                user_address: r.get(3)?,
                authenticated_at: r.get(4)?,
                otp_status: r.get(5)?,
            })
        })
        .optional()?;
    Ok(row)
}

/// A snapshot of session state.
#[derive(Debug, Clone)]
pub struct SessionStatus {
    pub status: String,
    pub address: Option<String>,
    pub txid: Option<String>,
    pub user_address: Option<String>,
    pub authenticated_at: Option<i64>,
    pub otp_status: Option<String>,
}

use rusqlite::OptionalExtension;

/// Mark an OTP as sent for a session.
pub fn set_otp_sent(conn: &Connection, session_id: &str, otp_code: &str) -> anyhow::Result<()> {
    conn.execute(
        "UPDATE sessions SET otp_challenge = ?1, otp_status = 'sent' WHERE session_id = ?2",
        rusqlite::params![otp_code, session_id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> i64 {
        1_000_000
    }

    #[test]
    fn authenticate_pending_session() {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = init_db(&dir.path().join("zfa.db")).unwrap();
        create_session(&conn, "1234567890123456", now(), now() + 120).unwrap();

        let result = authenticate_session(&mut conn, "1234567890123456", "abc123", "zaddr", now() + 10).unwrap();
        assert!(result, "session should be authenticated");

        let status = session_status(&conn, "1234567890123456").unwrap().unwrap();
        assert_eq!(status.status, "authenticated");
        assert_eq!(status.address.as_deref(), Some("zaddr"));
        assert_eq!(status.txid.as_deref(), Some("abc123"));
    }

    #[test]
    fn duplicate_txid_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = init_db(&dir.path().join("zfa.db")).unwrap();
        create_session(&conn, "1111111111111111", now(), now() + 120).unwrap();
        create_session(&conn, "2222222222222222", now(), now() + 120).unwrap();

        let r1 = authenticate_session(&mut conn, "1111111111111111", "txid_001", "addr1", now() + 10).unwrap();
        assert!(r1);

        let r2 = authenticate_session(&mut conn, "2222222222222222", "txid_001", "addr2", now() + 10).unwrap();
        assert!(!r2, "duplicate txid must not authenticate a second session");

        let status = session_status(&conn, "2222222222222222").unwrap().unwrap();
        assert_eq!(status.status, "pending");
    }

    #[test]
    fn expired_session_not_authenticated() {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = init_db(&dir.path().join("zfa.db")).unwrap();
        create_session(&conn, "3333333333333333", now(), now() + 60).unwrap();

        let result = authenticate_session(&mut conn, "3333333333333333", "txid_002", "addr3", now() + 120).unwrap();
        assert!(!result, "expired session must not be authenticated");

        let status = session_status(&conn, "3333333333333333").unwrap().unwrap();
        assert_eq!(status.status, "pending");
    }

    #[test]
    fn already_authenticated_session_not_re_authenticated() {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = init_db(&dir.path().join("zfa.db")).unwrap();
        create_session(&conn, "4444444444444444", now(), now() + 120).unwrap();

        let r1 = authenticate_session(&mut conn, "4444444444444444", "txid_003", "addr4", now() + 10).unwrap();
        assert!(r1);

        let r2 = authenticate_session(&mut conn, "4444444444444444", "txid_004", "addr5", now() + 20).unwrap();
        assert!(!r2, "already-authenticated session must not be re-authenticated");
    }
}