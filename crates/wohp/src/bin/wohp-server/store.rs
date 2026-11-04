//! The server's own SQLite file: verification sessions and one-time codes.
//!
//! Separate from the core database and owned by this process (mode 0600). Ids and
//! codes are kept as SHA-256 only. `state`, `return_url` and the verifier nonce stay
//! in plaintext because the server must replay them; the redirect, which carries
//! the code, lives only until the code is redeemed or expires. No wallet claim,
//! name, birth date, presentation or token is stored.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{path::Path, sync::Mutex, time::Duration};

#[derive(Debug, PartialEq, Eq)]
pub struct StoreError;

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("server database error")
    }
}

impl std::error::Error for StoreError {}

fn sql<T>(result: rusqlite::Result<T>) -> Result<T, StoreError> {
    // SQL errors may contain stored values. Do not forward them.
    result.map_err(|_| StoreError)
}

const SCHEMA: &str = "
CREATE TABLE verifications (
    id_hash BLOB PRIMARY KEY CHECK (length(id_hash) = 32),
    client_id TEXT NOT NULL,
    flow TEXT NOT NULL CHECK (flow IN ('enroll','recover')),
    return_url TEXT NOT NULL,
    state TEXT NOT NULL,
    challenge_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    audience TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    presentation_id TEXT,
    presentation_url TEXT,
    processing INTEGER NOT NULL DEFAULT 0 CHECK (processing IN (0,1)),
    redirect TEXT
) STRICT;
CREATE INDEX verifications_expiry ON verifications(expires_at);
CREATE TABLE grants (
    code_hash BLOB PRIMARY KEY CHECK (length(code_hash) = 32),
    verification_hash BLOB NOT NULL,
    client_id TEXT NOT NULL,
    flow TEXT NOT NULL CHECK (flow IN ('enroll','recover')),
    kind TEXT NOT NULL CHECK (kind IN ('created','existing','recovered')),
    client_subject TEXT NOT NULL,
    authentication_epoch INTEGER NOT NULL,
    age_at_least INTEGER CHECK (age_at_least IN (13, 14, 16, 18)),
    age_valid_until INTEGER,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
) STRICT;
CREATE INDEX grants_expiry ON grants(expires_at);
PRAGMA user_version=2;
";

/// A verification as the handlers need it. Ids are passed as raw digests.
pub struct VerificationRow {
    pub client_id: String,
    pub flow: String,
    pub return_url: String,
    pub state: String,
    pub challenge_id: String,
    pub nonce: String,
    pub audience: String,
    pub expires_at: u64,
    /// Verifier transaction id and wallet URL, once the QR exists.
    pub presentation: Option<(String, String)>,
    pub processing: bool,
    pub redirect: Option<String>,
}

/// What a one-time code redeems for.
pub struct GrantRow {
    pub client_id: String,
    pub flow: String,
    pub kind: String,
    pub client_subject: String,
    pub authentication_epoch: u64,
    pub age_at_least: Option<u8>,
    pub age_valid_until: Option<u64>,
    pub expires_at: u64,
}

pub enum Claim {
    Missing,
    Expired,
    /// Already completed: the redirect to replay.
    Ready(String),
    /// No QR yet.
    Pending,
    /// Another poll is completing it.
    Busy,
    /// This caller now owns the completion attempt.
    Claimed(Box<VerificationRow>),
}

pub struct Store {
    connection: Mutex<Connection>,
}

#[cfg(unix)]
fn ensure_private_file(path: &Path) -> Result<(), StoreError> {
    use std::{
        fs,
        io::ErrorKind,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };

    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(|_| StoreError)?;
            if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
                return Err(StoreError);
            }
            Ok(())
        }
        Err(_) => Err(StoreError),
    }
}

fn verification(row: &rusqlite::Row<'_>) -> rusqlite::Result<VerificationRow> {
    let id: Option<String> = row.get(8)?;
    let url: Option<String> = row.get(9)?;
    Ok(VerificationRow {
        client_id: row.get(0)?,
        flow: row.get(1)?,
        return_url: row.get(2)?,
        state: row.get(3)?,
        challenge_id: row.get(4)?,
        nonce: row.get(5)?,
        audience: row.get(6)?,
        expires_at: row.get(7)?,
        presentation: id.zip(url),
        processing: row.get(10)?,
        redirect: row.get(11)?,
    })
}

const COLUMNS: &str = "client_id, flow, return_url, state, challenge_id, nonce, audience, \
                       expires_at, presentation_id, presentation_url, processing, redirect";

impl Store {
    /// Opens or creates the file, removes expired rows and releases attempts a
    /// crash left in progress (the next poll simply retries them).
    pub fn open(path: &Path, now: u64) -> Result<Self, StoreError> {
        #[cfg(unix)]
        ensure_private_file(path)?;
        let mut connection = sql(Connection::open(path))?;
        sql(connection.busy_timeout(Duration::from_secs(5)))?;
        sql(connection.pragma_update(None, "journal_mode", "WAL"))?;
        sql(connection.pragma_update(None, "synchronous", "FULL"))?;
        let tx = sql(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let version: u32 = sql(tx.pragma_query_value(None, "user_version", |r| r.get(0)))?;
        match version {
            0 => {
                let tables: u64 = sql(tx.query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                    [],
                    |r| r.get(0),
                ))?;
                if tables != 0 {
                    return Err(StoreError);
                }
                sql(tx.execute_batch(SCHEMA))?;
            }
            // Version 1 required an age on every grant: not opened, not migrated.
            2 => {}
            _ => return Err(StoreError),
        }
        sql(tx.execute("UPDATE verifications SET processing = 0", []))?;
        sql(tx.commit())?;
        let store = Self {
            connection: Mutex::new(connection),
        };
        store.sweep(now)?;
        Ok(store)
    }

    fn with<T>(
        &self,
        work: impl FnOnce(&mut Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut connection = self.connection.lock().map_err(|_| StoreError)?;
        work(&mut connection)
    }

    /// Removes expired verifications and codes.
    pub fn sweep(&self, now: u64) -> Result<(), StoreError> {
        self.with(|connection| {
            sql(connection.execute("DELETE FROM verifications WHERE expires_at <= ?1", [now]))?;
            sql(connection.execute("DELETE FROM grants WHERE expires_at <= ?1", [now]))?;
            Ok(())
        })
    }

    /// Live verifications, for the capacity bound.
    pub fn pending(&self, now: u64) -> Result<u64, StoreError> {
        self.with(|connection| {
            sql(connection.query_row(
                "SELECT count(*) FROM verifications WHERE expires_at > ?1",
                [now],
                |r| r.get(0),
            ))
        })
    }

    pub fn insert_verification(
        &self,
        id_hash: &[u8; 32],
        row: &VerificationRow,
    ) -> Result<(), StoreError> {
        self.with(|connection| {
            sql(connection.execute(
                "INSERT INTO verifications (id_hash, client_id, flow, return_url, state,
                 challenge_id, nonce, audience, expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    id_hash,
                    row.client_id,
                    row.flow,
                    row.return_url,
                    row.state,
                    row.challenge_id,
                    row.nonce,
                    row.audience,
                    row.expires_at,
                ],
            ))?;
            Ok(())
        })
    }

    pub fn verification(&self, id_hash: &[u8; 32]) -> Result<Option<VerificationRow>, StoreError> {
        self.with(|connection| {
            sql(connection
                .query_row(
                    &format!("SELECT {COLUMNS} FROM verifications WHERE id_hash = ?1"),
                    [id_hash],
                    verification,
                )
                .optional())
        })
    }

    pub fn delete_verification(&self, id_hash: &[u8; 32]) -> Result<(), StoreError> {
        self.with(|connection| {
            sql(connection.execute("DELETE FROM verifications WHERE id_hash = ?1", [id_hash]))?;
            Ok(())
        })
    }

    /// Records the verifier transaction unless a concurrent page view already
    /// did; returns the one that is kept.
    pub fn set_presentation(
        &self,
        id_hash: &[u8; 32],
        id: &str,
        url: &str,
    ) -> Result<Option<(String, String)>, StoreError> {
        self.with(|connection| {
            let tx = sql(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
            sql(tx.execute(
                "UPDATE verifications SET presentation_id = ?2, presentation_url = ?3
                 WHERE id_hash = ?1 AND presentation_id IS NULL",
                params![id_hash, id, url],
            ))?;
            let kept: Option<(String, String)> = sql(tx
                .query_row(
                    "SELECT presentation_id, presentation_url FROM verifications WHERE id_hash = ?1",
                    [id_hash],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional())?;
            sql(tx.commit())?;
            Ok(kept)
        })
    }

    /// Takes the right to complete a verification, at most one caller at a time.
    pub fn claim(&self, id_hash: &[u8; 32], now: u64) -> Result<Claim, StoreError> {
        self.with(|connection| {
            let tx = sql(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
            let Some(row) = sql(tx
                .query_row(
                    &format!("SELECT {COLUMNS} FROM verifications WHERE id_hash = ?1"),
                    [id_hash],
                    verification,
                )
                .optional())?
            else {
                return Ok(Claim::Missing);
            };
            let claim = if now >= row.expires_at {
                Claim::Expired
            } else if let Some(redirect) = row.redirect {
                Claim::Ready(redirect)
            } else if row.presentation.is_none() {
                Claim::Pending
            } else if row.processing {
                Claim::Busy
            } else {
                sql(tx.execute(
                    "UPDATE verifications SET processing = 1 WHERE id_hash = ?1",
                    [id_hash],
                ))?;
                Claim::Claimed(Box::new(row))
            };
            sql(tx.commit())?;
            Ok(claim)
        })
    }

    /// The wallet has not answered yet: another poll may try again.
    pub fn release(&self, id_hash: &[u8; 32]) -> Result<(), StoreError> {
        self.with(|connection| {
            sql(connection.execute(
                "UPDATE verifications SET processing = 0 WHERE id_hash = ?1",
                [id_hash],
            ))?;
            Ok(())
        })
    }

    /// Stores the code and the redirect that carries it, in one transaction.
    pub fn complete(
        &self,
        id_hash: &[u8; 32],
        code_hash: &[u8; 32],
        grant: &GrantRow,
        redirect: &str,
        max_grants: u64,
        now: u64,
    ) -> Result<bool, StoreError> {
        self.with(|connection| {
            let tx = sql(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
            sql(tx.execute("DELETE FROM grants WHERE expires_at <= ?1", [now]))?;
            let live: u64 = sql(tx.query_row("SELECT count(*) FROM grants", [], |r| r.get(0)))?;
            if live >= max_grants {
                return Ok(false);
            }
            sql(tx.execute(
                "INSERT INTO grants (code_hash, verification_hash, client_id, flow, kind,
                 client_subject, authentication_epoch, age_at_least, age_valid_until, expires_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    code_hash,
                    id_hash,
                    grant.client_id,
                    grant.flow,
                    grant.kind,
                    grant.client_subject,
                    grant.authentication_epoch,
                    grant.age_at_least,
                    grant.age_valid_until,
                    grant.expires_at,
                ],
            ))?;
            sql(tx.execute(
                "UPDATE verifications SET redirect = ?2, processing = 0 WHERE id_hash = ?1",
                params![id_hash, redirect],
            ))?;
            sql(tx.commit())?;
            Ok(true)
        })
    }

    /// Single use: the first caller marks the code used, whoever it is; the
    /// verification and its redirect go with it. Expired codes are removed.
    pub fn redeem(&self, code_hash: &[u8; 32], now: u64) -> Result<Option<GrantRow>, StoreError> {
        self.with(|connection| {
            let tx = sql(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
            sql(tx.execute("DELETE FROM grants WHERE expires_at <= ?1", [now]))?;
            let grant = sql(tx
                .query_row(
                    "UPDATE grants SET used_at = ?2
                     WHERE code_hash = ?1 AND used_at IS NULL AND expires_at > ?2
                     RETURNING client_id, flow, kind, client_subject, authentication_epoch,
                               age_at_least, age_valid_until, expires_at, verification_hash",
                    params![code_hash, now],
                    |r| {
                        Ok((
                            GrantRow {
                                client_id: r.get(0)?,
                                flow: r.get(1)?,
                                kind: r.get(2)?,
                                client_subject: r.get(3)?,
                                authentication_epoch: r.get(4)?,
                                age_at_least: r.get(5)?,
                                age_valid_until: r.get(6)?,
                                expires_at: r.get(7)?,
                            },
                            r.get::<_, Vec<u8>>(8)?,
                        ))
                    },
                )
                .optional())?;
            if let Some((_, verification)) = &grant {
                sql(tx.execute(
                    "DELETE FROM verifications WHERE id_hash = ?1",
                    [verification],
                ))?;
            }
            sql(tx.commit())?;
            Ok(grant.map(|(grant, _)| grant))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        sync::{Arc, Barrier},
    };

    struct Directory(PathBuf);

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn directory(name: &str) -> Directory {
        let path =
            std::env::temp_dir().join(format!("wohp-server-store-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        Directory(path)
    }

    fn row(expires_at: u64) -> VerificationRow {
        VerificationRow {
            client_id: "idp".into(),
            flow: "enroll".into(),
            return_url: "https://idp.example/return".into(),
            state: "s".into(),
            challenge_id: "challenge".into(),
            nonce: "nonce".into(),
            audience: "x509_hash:a".into(),
            expires_at,
            presentation: None,
            processing: false,
            redirect: None,
        }
    }

    fn grant(expires_at: u64) -> GrantRow {
        GrantRow {
            client_id: "idp".into(),
            flow: "enroll".into(),
            kind: "created".into(),
            client_subject: "A".repeat(43),
            authentication_epoch: 1,
            age_at_least: Some(18),
            age_valid_until: Some(9_999),
            expires_at,
        }
    }

    #[test]
    fn concurrent_redeems_on_separate_connections_succeed_once() {
        let dir = directory("concurrent");
        let path = dir.0.join("server.sqlite3");
        let store = Store::open(&path, 100).unwrap();
        store.insert_verification(&[1; 32], &row(500)).unwrap();
        assert!(
            store
                .complete(&[1; 32], &[2; 32], &grant(220), "r", 8, 100)
                .unwrap()
        );
        drop(store);
        let barrier = Arc::new(Barrier::new(8));
        let winners: usize = (0..8)
            .map(|_| {
                let (path, barrier) = (path.clone(), barrier.clone());
                std::thread::spawn(move || {
                    let store = Store::open(&path, 100).unwrap();
                    barrier.wait();
                    usize::from(store.redeem(&[2; 32], 101).unwrap().is_some())
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .sum();
        assert_eq!(winners, 1);
    }

    #[test]
    fn expired_rows_are_swept_and_never_redeemed() {
        let dir = directory("expiry");
        let store = Store::open(&dir.0.join("server.sqlite3"), 100).unwrap();
        store.insert_verification(&[1; 32], &row(150)).unwrap();
        store
            .complete(&[1; 32], &[2; 32], &grant(120), "r", 8, 100)
            .unwrap();
        assert!(store.redeem(&[2; 32], 120).unwrap().is_none());
        store.sweep(150).unwrap();
        assert!(store.verification(&[1; 32]).unwrap().is_none());
        let count = |table: &str| -> u64 {
            store
                .with(|c| {
                    sql(c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0)))
                })
                .unwrap()
        };
        assert_eq!((count("verifications"), count("grants")), (0, 0));
    }

    #[test]
    fn a_crash_releases_attempts_in_progress_and_the_file_is_private() {
        let dir = directory("restart");
        let path = dir.0.join("server.sqlite3");
        let store = Store::open(&path, 100).unwrap();
        store.insert_verification(&[1; 32], &row(500)).unwrap();
        store
            .set_presentation(&[1; 32], "tx", "openid4vp://?x")
            .unwrap();
        assert!(matches!(
            store.claim(&[1; 32], 100).unwrap(),
            Claim::Claimed(_)
        ));
        assert!(matches!(store.claim(&[1; 32], 100).unwrap(), Claim::Busy));
        drop(store);
        let store = Store::open(&path, 100).unwrap();
        assert!(matches!(
            store.claim(&[1; 32], 100).unwrap(),
            Claim::Claimed(_)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            drop(store);
            assert!(Store::open(&path, 100).is_err());
        }
    }
}
