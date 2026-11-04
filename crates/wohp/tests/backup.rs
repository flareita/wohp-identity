#![forbid(unsafe_code)]
//! Backup and restore of the identity database (specification v1.0.1, §13).

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use wohp::{
    Clock, Config, LookupKey, Service,
    backup::{backup, restore},
};
use wohp_api::{
    ClientId, ClientRegistration, CompletionKind, Error, IdentityFlow, IdentityService, Subject,
};
use wohp_mock::{MockIdentityProvider, Scenario};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const CLIENT: &str = "first-party-idp";

/// A private (0700) temporary directory.
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wohp-backup-test-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        set_mode(&path, 0o700);
        Self(path)
    }
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> Result<u64, Error> {
        Ok(1_000_000)
    }
}

fn key() -> LookupKey {
    LookupKey::from_bytes(&[7; 32]).unwrap()
}

fn open(
    path: &Path,
    provider: &Arc<MockIdentityProvider>,
) -> Service<MockIdentityProvider, FixedClock> {
    let mut service = Service::open(
        path,
        Config::development(),
        Arc::clone(provider),
        key(),
        FixedClock,
    )
    .unwrap();
    service
        .register_client(
            ClientRegistration::new(ClientId::parse(CLIENT).unwrap(), "idp.network", None).unwrap(),
        )
        .unwrap();
    service
}

fn enroll(
    service: &mut impl IdentityService,
    provider: &MockIdentityProvider,
    person: &str,
) -> (CompletionKind, Subject) {
    let context = service.begin(IdentityFlow::Enrollment).unwrap();
    let proof = provider
        .issue(&context, Scenario::person(person, Some(true)))
        .unwrap();
    let completion = service.complete(&context.challenge_id, &proof).unwrap();
    (completion.kind, completion.subject)
}

fn count(path: &Path, query: &str) -> u64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(query, [], |row| row.get(0))
        .unwrap()
}

/// A database with alice enrolled, and a snapshot of it in `backups`.
fn snapshot(provider: &Arc<MockIdentityProvider>) -> (Directory, Directory, PathBuf) {
    let live = Directory::new();
    let backups = Directory::new();
    let mut service = open(&live.join("identity.sqlite3"), provider);
    enroll(&mut service, provider, "alice");
    let summary = backup(&live.join("identity.sqlite3"), &key(), &backups.0, 100).unwrap();
    drop(service);
    (live, backups, summary.path)
}

#[test]
fn a_live_backup_restores_subjects_discards_challenges_and_advances_epochs() {
    let provider = Arc::new(MockIdentityProvider::default());
    let live = Directory::new();
    let database = live.join("identity.sqlite3");
    let mut service = open(&database, &provider);
    let (_, alice) = enroll(&mut service, &provider, "alice");
    let client = ClientId::parse(CLIENT).unwrap();
    let pairwise = service.client_subject(&client, &alice).unwrap();
    assert_eq!(service.status(&alice).unwrap().authentication_epoch, 1);
    // Started before the snapshot, completed only after the restore.
    let pending = service.begin(IdentityFlow::Enrollment).unwrap();
    let late_proof = provider
        .issue(&pending, Scenario::person("carol", Some(true)))
        .unwrap();

    // Taken while the service holds the database open in WAL mode.
    let backups = Directory::new();
    let summary = backup(&database, &key(), &backups.0, 100).unwrap();
    assert_eq!((summary.humans, summary.clients), (1, 1));
    assert_eq!(summary.path, backups.join("wohp-identity-100.sqlite3"));
    assert_eq!(
        backups.names(),
        ["wohp-identity-100.sqlite3"],
        "one self-contained file"
    );
    #[cfg(unix)]
    assert_eq!(mode(&summary.path), 0o600);

    // Lost with the old database.
    let (_, bob) = enroll(&mut service, &provider, "bob");
    drop(service);

    let restored = Directory::new();
    let target = restored.join("identity.sqlite3");
    let outcome = restore(&summary.path, &key(), &target, 2_000_000).unwrap();
    assert_eq!((outcome.humans, outcome.discarded_challenges), (1, 1));
    assert_eq!(
        restored.names(),
        ["identity.sqlite3"],
        "no temporary file is left"
    );
    #[cfg(unix)]
    assert_eq!(mode(&target), 0o600);
    assert_eq!(
        count(
            &target,
            "SELECT count(*) FROM security_events WHERE event = 'AUTHENTICATORS_RESET' AND occurred_at = 2000000"
        ),
        1
    );

    let mut service = open(&target, &provider);
    // Same person, same subjects; credentials from before the restore are stale.
    assert_eq!(
        service.status(&alice).unwrap().authentication_epoch,
        2_000_000,
        "the restore time"
    );
    assert_eq!(service.client_subject(&client, &alice).unwrap(), pairwise);
    assert_eq!(
        enroll(&mut service, &provider, "alice"),
        (CompletionKind::ExistingRequiresAuthentication, alice)
    );
    // The verification started before the snapshot cannot be completed.
    assert!(
        service
            .complete(&pending.challenge_id, &late_proof)
            .is_err()
    );
    // Bob enrolled after the snapshot: he is new again, with a new subject.
    assert_eq!(service.status(&bob).unwrap_err(), Error::SubjectNotFound);
    let (kind, again) = enroll(&mut service, &provider, "bob");
    assert_eq!(kind, CompletionKind::Created);
    assert_ne!(again, bob);
    assert_eq!(count(&target, "SELECT count(*) FROM humans"), 2);
}

#[test]
fn restore_never_overwrites_and_refuses_foreign_keys_live_files_and_damage() {
    let provider = Arc::new(MockIdentityProvider::default());
    let (live, backups, snapshot) = snapshot(&provider);
    let database = live.join("identity.sqlite3");

    // An existing database is never replaced, even with the right snapshot.
    let before = fs::read(&database).unwrap();
    assert_eq!(
        restore(&snapshot, &key(), &database, 2_000).unwrap_err(),
        Error::InvalidConfiguration
    );
    assert_eq!(fs::read(&database).unwrap(), before);

    let target = Directory::new();
    let path = target.join("identity.sqlite3");
    // Another key could not recognise anyone in it.
    let other = LookupKey::from_bytes(&[9; 32]).unwrap();
    assert_eq!(
        restore(&snapshot, &other, &path, 2_000).unwrap_err(),
        Error::ConfigurationMismatch
    );
    assert!(
        target.names().is_empty(),
        "nothing is installed or left behind"
    );

    // A database still in use, with its write-ahead log, is not a snapshot.
    let service = open(&database, &provider);
    assert_eq!(
        restore(&database, &key(), &path, 2_000).unwrap_err(),
        Error::InvalidInput
    );
    drop(service);

    // A hot rollback journal means the file alone may be torn: refused.
    let journal = PathBuf::from(format!("{}-journal", snapshot.display()));
    fs::write(&journal, b"").unwrap();
    assert_eq!(
        restore(&snapshot, &key(), &path, 2_000).unwrap_err(),
        Error::InvalidInput
    );
    assert!(target.names().is_empty());
    fs::remove_file(&journal).unwrap();

    // A damaged snapshot is refused.
    let damaged = backups.join("damaged.sqlite3");
    let mut bytes = fs::read(&snapshot).unwrap();
    let half = bytes.len() / 2;
    bytes.truncate(half);
    fs::write(&damaged, &bytes).unwrap();
    set_mode(&damaged, 0o600);
    assert!(restore(&damaged, &key(), &path, 2_000).is_err());
    assert!(target.names().is_empty());

    #[cfg(unix)]
    {
        // A snapshot readable by others, or a public target directory, is refused.
        set_mode(&snapshot, 0o644);
        assert_eq!(
            restore(&snapshot, &key(), &path, 2_000).unwrap_err(),
            Error::InvalidConfiguration
        );
        set_mode(&snapshot, 0o600);
        set_mode(&target.0, 0o755);
        assert_eq!(
            restore(&snapshot, &key(), &path, 2_000).unwrap_err(),
            Error::InvalidConfiguration
        );
        set_mode(&target.0, 0o700);
    }

    // The same snapshot restores once the target is free.
    assert_eq!(restore(&snapshot, &key(), &path, 2_000).unwrap().humans, 1);
}

#[test]
fn backup_needs_a_private_directory_the_matching_key_and_a_new_name() {
    let provider = Arc::new(MockIdentityProvider::default());
    let (live, backups, first) = snapshot(&provider);
    let database = live.join("identity.sqlite3");

    // A second snapshot in the same second never overwrites the first.
    let original = fs::read(&first).unwrap();
    assert_eq!(
        backup(&database, &key(), &backups.0, 100).unwrap_err(),
        Error::InvalidConfiguration
    );
    assert_eq!(fs::read(&first).unwrap(), original);

    // Without the database's key the snapshot could never be restored.
    let other = LookupKey::from_bytes(&[9; 32]).unwrap();
    assert_eq!(
        backup(&database, &other, &backups.0, 101).unwrap_err(),
        Error::ConfigurationMismatch
    );
    assert_eq!(backups.names(), ["wohp-identity-100.sqlite3"]);

    // A missing database is never created by a backup.
    let missing = live.join("missing.sqlite3");
    assert_eq!(
        backup(&missing, &key(), &backups.0, 102).unwrap_err(),
        Error::InvalidConfiguration
    );
    assert!(!missing.exists());

    #[cfg(unix)]
    {
        set_mode(&backups.0, 0o755);
        assert_eq!(
            backup(&database, &key(), &backups.0, 103).unwrap_err(),
            Error::InvalidConfiguration
        );
        set_mode(&backups.0, 0o700);
    }
    assert_eq!(backups.names(), ["wohp-identity-100.sqlite3"]);
}

#[test]
fn a_backup_of_a_stopped_database_only_reads_it() {
    let provider = Arc::new(MockIdentityProvider::default());
    let (live, backups, _) = snapshot(&provider);
    let database = live.join("identity.sqlite3");
    // The server is stopped: its write-ahead files were removed on close.
    let before = fs::read(&database).unwrap();

    let summary = backup(&database, &key(), &backups.0, 200).unwrap();
    assert_eq!((summary.humans, summary.clients), (1, 1));
    assert_eq!(
        fs::read(&database).unwrap(),
        before,
        "the source is never written"
    );
    assert_eq!(mode(&summary.path), 0o600);
}

#[test]
fn epochs_end_above_every_value_reached_after_the_snapshot() {
    let provider = Arc::new(MockIdentityProvider::default());
    let live = Directory::new();
    let database = live.join("identity.sqlite3");
    let client = ClientId::parse(CLIENT).unwrap();
    let mut service = open(&database, &provider);
    let (_, alice) = enroll(&mut service, &provider, "alice");
    let alice_pairwise = service.client_subject(&client, &alice).unwrap();
    let backups = Directory::new();
    let snapshot = backup(&database, &key(), &backups.0, 100).unwrap().path;

    // After the snapshot alice is reset twice: relying parties saw epoch 3.
    for expected in [2, 3] {
        assert_eq!(
            service
                .reset_authenticators_for_client(&client, &alice_pairwise)
                .unwrap(),
            expected
        );
    }
    drop(service);
    // The live database is lost: only the snapshot (epoch 1) is left.
    fs::remove_dir_all(&live.0).unwrap();

    let restored = Directory::new();
    let target = restored.join("identity.sqlite3");
    let outcome = restore(&snapshot, &key(), &target, 2_000).unwrap();
    assert_eq!((outcome.humans, outcome.epoch), (1, 2_000));
    let mut service = open(&target, &provider);
    assert_eq!(service.status(&alice).unwrap().authentication_epoch, 2_000);
    // Later resets keep counting from there.
    assert_eq!(
        service
            .reset_authenticators_for_client(&client, &alice_pairwise)
            .unwrap(),
        2_001
    );
    drop(service);

    // A second restore must happen later than the epochs the first produced:
    // a clock behind them is refused and nothing is installed.
    let backups = Directory::new();
    let second = backup(&target, &key(), &backups.0, 2_100).unwrap().path;
    let again = Directory::new();
    let path = again.join("identity.sqlite3");
    assert_eq!(
        restore(&second, &key(), &path, 2_001).unwrap_err(),
        Error::Clock
    );
    assert!(again.names().is_empty());
    assert_eq!(restore(&second, &key(), &path, 3_000).unwrap().epoch, 3_000);
}
