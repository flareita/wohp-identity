//! Consistent snapshots of the identity database and their offline restore
//! (specification v1.0.1, §13).
//!
//! A snapshot keeps every subject, lookup reference, client subject, epoch and
//! revocation as they were when it was taken. It never contains the lookup key:
//! the key is kept separately and must match the snapshot on restore.
//!
//! Restoring brings back an older state, so it reopens login only after:
//! - discarding every pending challenge, so no verification started before the
//!   snapshot can be completed or replayed;
//! - setting every authentication epoch to the restore time, recorded as an
//!   authenticator reset. Relying parties never accept an epoch going back,
//!   and the epochs reached after the snapshot were in the database that is
//!   usually lost. Epochs are small counters that advance by one per recovery,
//!   revocation or reset, so the restore time in seconds is above any of them
//!   unless a person advanced more times than seconds passed since the
//!   previous restore. Relying parties then drop every credential and session
//!   issued before the restore.
//!
//! What happened after the snapshot is lost: people enrolled later get a new
//! subject when they verify again, and revocations made later must be applied
//! again by the operator.
use crate::{LookupKey, store::SCHEMA_VERSION};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use std::{
    fs,
    io::{self, ErrorKind},
    path::{Path, PathBuf},
    time::Duration,
};
use wohp_api::{Error, Timestamp};

/// What a snapshot holds, without any identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupSummary {
    pub path: PathBuf,
    pub humans: u64,
    pub clients: u64,
}

/// What a restore changed, without any identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreSummary {
    pub humans: u64,
    /// Verifications that were still pending in the snapshot.
    pub discarded_challenges: u64,
    /// The authentication epoch of every restored person: the restore time.
    pub epoch: u64,
}

fn sql<T>(result: rusqlite::Result<T>) -> Result<T, Error> {
    // SQL errors may contain schema values and identifiers. Do not forward them.
    result.map_err(|_| Error::Storage)
}

fn io<T>(result: io::Result<T>) -> Result<T, Error> {
    result.map_err(|_| Error::Storage)
}

/// An existing regular file (not a symlink) that only its owner can access.
fn private_file(path: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::InvalidConfiguration)?;
    if !metadata.file_type().is_file() {
        return Err(Error::InvalidConfiguration);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::InvalidConfiguration);
        }
    }
    Ok(())
}

/// An existing directory (not a symlink) that only its owner can access.
fn private_directory(path: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::InvalidConfiguration)?;
    if !metadata.file_type().is_dir() {
        return Err(Error::InvalidConfiguration);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::InvalidConfiguration);
        }
    }
    Ok(())
}

/// Creates an empty file only its owner can access; an existing name is refused.
fn create_private(path: &Path) -> Result<fs::File, Error> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|error| match error.kind() {
        ErrorKind::AlreadyExists => Error::InvalidConfiguration,
        _ => Error::Storage,
    })
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Makes a completed rename or link durable.
fn sync_directory(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    io(fs::File::open(path).and_then(|directory| directory.sync_all()))?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Opens an existing database without ever creating one.
pub(crate) fn open_existing(path: &Path, flags: OpenFlags) -> Result<Connection, Error> {
    let connection = sql(Connection::open_with_flags(
        path,
        flags | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ))?;
    sql(connection.busy_timeout(Duration::from_secs(5)))?;
    Ok(connection)
}

/// A self-contained, intact identity database of the current schema that
/// belongs to `key`. Returns the number of people and clients.
fn check(connection: &Connection, key: &LookupKey) -> Result<(u64, u64), Error> {
    // One file, no write-ahead log next to it.
    let mode: String = sql(connection.query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0)))?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(Error::Storage);
    }
    let integrity: String = sql(connection.query_row("PRAGMA integrity_check", [], |r| r.get(0)))?;
    let orphans = sql(connection
        .prepare("PRAGMA foreign_key_check")
        .and_then(|mut statement| statement.query([])?.next().map(|row| row.is_some())))?;
    if integrity != "ok" || orphans {
        return Err(Error::Storage);
    }
    let version: u32 = sql(connection.pragma_query_value(None, "user_version", |r| r.get(0)))?;
    if version != SCHEMA_VERSION {
        return Err(Error::ConfigurationMismatch);
    }
    let identity: Vec<u8> = sql(connection.query_row(
        "SELECT lookup_key_identity FROM deployment WHERE singleton = 1",
        [],
        |r| r.get(0),
    ))?;
    if identity != key.identity() {
        return Err(Error::ConfigurationMismatch);
    }
    let humans = sql(connection.query_row("SELECT count(*) FROM humans", [], |r| r.get(0)))?;
    let clients = sql(connection.query_row("SELECT count(*) FROM clients", [], |r| r.get(0)))?;
    Ok((humans, clients))
}

/// Writes a consistent snapshot of `database` to
/// `directory/wohp-identity-<now>.sqlite3` (mode 0600). Safe while the server
/// runs: SQLite copies one read transaction, including the write-ahead log.
///
/// The directory must be private (0700) and `key` must be the database's
/// lookup key, so a backup is never kept without the key that reads it.
pub fn backup(
    database: &Path,
    key: &LookupKey,
    directory: &Path,
    now: Timestamp,
) -> Result<BackupSummary, Error> {
    private_directory(directory)?;
    private_file(database)?;
    let path = directory.join(format!("wohp-identity-{now}.sqlite3"));
    let target = path.to_str().ok_or(Error::InvalidConfiguration)?;
    drop(create_private(&path)?);
    let written = (|| {
        // Read-only: the copy can never change the server's database.
        let source = open_existing(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        sql(source.execute("VACUUM INTO ?1", [target]))?;
        drop(source);
        let snapshot = open_existing(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let (humans, clients) = check(&snapshot, key)?;
        drop(snapshot);
        io(fs::File::open(&path).and_then(|file| file.sync_all()))?;
        sync_directory(directory)?;
        Ok((humans, clients))
    })();
    match written {
        Ok((humans, clients)) => Ok(BackupSummary {
            path,
            humans,
            clients,
        }),
        Err(error) => {
            let _ = fs::remove_file(&path);
            Err(error)
        }
    }
}

/// Installs `snapshot` as a new `database`, offline. The database (and its
/// write-ahead files) must not exist: the operator stops the server and moves
/// the old files aside. The snapshot is copied, checked against `key`, cleared
/// of pending challenges and every epoch is set to `now` before it gets its
/// name. A snapshot with an epoch at or above `now` means a clock behind a
/// previous restore: refused.
pub fn restore(
    snapshot: &Path,
    key: &LookupKey,
    database: &Path,
    now: Timestamp,
) -> Result<RestoreSummary, Error> {
    if [
        database,
        &sibling(database, "-wal"),
        &sibling(database, "-shm"),
    ]
    .iter()
    .any(|path| exists(path))
    {
        return Err(Error::InvalidConfiguration);
    }
    private_file(snapshot)?;
    // A live database with its write-ahead log, or one with a hot rollback
    // journal from an interrupted write, is not a snapshot: copying the file
    // alone would lose or tear committed changes.
    if exists(&sibling(snapshot, "-wal")) || exists(&sibling(snapshot, "-journal")) {
        return Err(Error::InvalidInput);
    }
    let directory = parent(database);
    private_directory(directory)?;
    let temporary = sibling(database, ".restore");
    let mut file = create_private(&temporary)?;
    let restored = (|| {
        io(fs::File::open(snapshot).and_then(|mut source| io::copy(&mut source, &mut file)))?;
        io(file.sync_all())?;
        let mut connection = open_existing(&temporary, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        sql(connection.pragma_update(None, "foreign_keys", true))?;
        check(&connection, key)?;
        let tx = sql(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let discarded: u64 = sql(tx.query_row(
            "SELECT count(*) FROM challenges WHERE consumed = 0",
            [],
            |r| r.get(0),
        ))?;
        sql(tx.execute("DELETE FROM challenges", []))?;
        let highest: Option<u64> = sql(tx.query_row(
            "SELECT max(authentication_epoch) FROM humans",
            [],
            |r| r.get(0),
        ))?;
        if now > i64::MAX as u64 || highest.is_some_and(|epoch| epoch >= now) {
            return Err(Error::Clock);
        }
        let humans = sql(tx.execute("UPDATE humans SET authentication_epoch = ?1", [now]))?;
        sql(tx.execute(
            "INSERT INTO security_events(subject, event, occurred_at)
             SELECT subject, 'AUTHENTICATORS_RESET', ?1 FROM humans",
            [now],
        ))?;
        sql(tx.commit())?;
        drop(connection);
        // A hard link never replaces a database created in the meantime.
        fs::hard_link(&temporary, database).map_err(|error| match error.kind() {
            ErrorKind::AlreadyExists => Error::InvalidConfiguration,
            _ => Error::Storage,
        })?;
        Ok(RestoreSummary {
            humans: humans as u64,
            discarded_challenges: discarded,
            epoch: now,
        })
    })();
    drop(file);
    let _ = fs::remove_file(&temporary);
    let _ = fs::remove_file(sibling(&temporary, "-journal"));
    let summary = restored?;
    sync_directory(directory)?;
    Ok(summary)
}
