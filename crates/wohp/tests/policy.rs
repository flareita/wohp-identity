#![forbid(unsafe_code)]
//! Offline diagnosis of deployment configuration mismatches.
//!
//! Age policy is not a deployment setting: each registered client has its own
//! minimum age, changed through `Service::register_client` and audited in
//! `client_events`.

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
    policy::{Mismatch, diagnose},
};
use wohp_api::{Error, IdentityProvider};
use wohp_mock::MockIdentityProvider;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const NOW: u64 = 1_000_000;

/// A private (0700) temporary directory.
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wohp-policy-test-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }
    fn database(&self) -> PathBuf {
        self.0.join("identity.sqlite3")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> Result<u64, Error> {
        Ok(NOW)
    }
}

fn key() -> LookupKey {
    LookupKey::from_bytes(&[7; 32]).unwrap()
}

fn open(
    path: &Path,
    config: Config,
) -> Result<
    (
        Service<MockIdentityProvider, FixedClock>,
        Arc<MockIdentityProvider>,
    ),
    Error,
> {
    let provider = Arc::new(MockIdentityProvider::default());
    let service = Service::open(path, config, Arc::clone(&provider), key(), FixedClock)?;
    Ok((service, provider))
}

#[test]
fn diagnose_names_each_difference() {
    let dir = Directory::new();
    let path = dir.database();
    drop(open(&path, Config::development()).unwrap());
    let descriptor = MockIdentityProvider::default().descriptor();

    let matching = Config::development();
    assert_eq!(diagnose(&path, &matching, &descriptor, &key()), Ok(vec![]));

    let mut other = Config::development();
    other.provider_audience = "another-verifier".into();
    let foreign_key = LookupKey::from_bytes(&[9; 32]).unwrap();
    assert_eq!(
        diagnose(&path, &other, &descriptor, &foreign_key),
        Ok(vec![Mismatch::LookupKey, Mismatch::Audience])
    );

    let mut production = Config::development();
    production.environment = wohp::Environment::Production;
    assert_eq!(
        diagnose(&path, &production, &descriptor, &key()),
        Ok(vec![Mismatch::Environment])
    );

    let mut other_provider = descriptor.clone();
    other_provider.policy_version = "replaced-policy".into();
    assert_eq!(
        diagnose(&path, &matching, &other_provider, &key()),
        Ok(vec![Mismatch::Provider])
    );
    // Diagnosing never leaves write-ahead files behind.
    assert!(!dir.0.join("identity.sqlite3-wal").exists());
}

#[test]
fn diagnose_reports_an_earlier_schema_and_never_migrates_it() {
    let dir = Directory::new();
    let path = dir.database();
    drop(open(&path, Config::development()).unwrap());
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.pragma_update(None, "user_version", 4).unwrap();
    }
    let descriptor = MockIdentityProvider::default().descriptor();
    let config = Config::development();
    assert_eq!(
        diagnose(&path, &config, &descriptor, &key()),
        Ok(vec![Mismatch::Schema])
    );
    // Still the schema the operator left: opening the database is refused.
    assert!(matches!(
        open(&path, config),
        Err(Error::ConfigurationMismatch)
    ));
    let version: u32 = rusqlite::Connection::open(&path)
        .unwrap()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 4, "diagnose does not migrate");
}

#[test]
fn diagnose_refuses_a_missing_database_without_creating_it() {
    let dir = Directory::new();
    let path = dir.0.join("missing.sqlite3");
    let descriptor = MockIdentityProvider::default().descriptor();
    assert_eq!(
        diagnose(&path, &Config::development(), &descriptor, &key()),
        Err(Error::InvalidConfiguration)
    );
    assert!(!path.exists());
}
