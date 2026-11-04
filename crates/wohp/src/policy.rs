//! Operator view of the deployment settings stored in an identity database.
//!
//! `diagnose` explains, field by field, why `Service::open` refused a database
//! with `ConfigurationMismatch`. It reports setting names only, never people
//! or subjects. Age policy is not a deployment setting: each registered client
//! has its own minimum age (`Service::register_client`).
use crate::{
    Config, LookupKey,
    backup::open_existing,
    store::{SCHEMA_VERSION, class_name, environment_name},
};
use rusqlite::OpenFlags;
use std::{fmt, path::Path};
use wohp_api::{Error, ProviderDescriptor};

fn sql<T>(result: rusqlite::Result<T>) -> Result<T, Error> {
    // SQL errors may contain schema values and identifiers. Do not forward them.
    result.map_err(|_| Error::Storage)
}

/// One deployment setting that differs between a database and the
/// configuration it was opened with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mismatch {
    /// The file is not an identity database of this schema; earlier schemas
    /// are not migrated, the database must be created again.
    Schema,
    /// The lookup key belongs to another database.
    LookupKey,
    /// Development versus production.
    Environment,
    /// Provider integration, evidence class or policy version.
    Provider,
    /// The identity presentation audience.
    Audience,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Schema => "not an identity database of the current schema (no migration)",
            Self::LookupKey => "the lookup key belongs to another database",
            Self::Environment => "environment (development/production) differs",
            Self::Provider => "identity provider integration, evidence class or policy differs",
            Self::Audience => "identity presentation audience differs",
        })
    }
}

/// Lists every setting of `database` that differs from `config`, `provider`
/// and `key`. It only reads; an empty list means the deployment settings
/// match.
pub fn diagnose(
    database: &Path,
    config: &Config,
    provider: &ProviderDescriptor,
    key: &LookupKey,
) -> Result<Vec<Mismatch>, Error> {
    // Opened read-write (never created) only so that closing it removes the
    // write-ahead files of this WAL database; a read-only handle leaves them.
    if !database.exists() {
        return Err(Error::InvalidConfiguration);
    }
    let connection = open_existing(database, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let version: u32 = sql(connection.pragma_query_value(None, "user_version", |r| r.get(0)))?;
    if version != SCHEMA_VERSION {
        return Ok(vec![Mismatch::Schema]);
    }
    let (environment, integration, class, policy, audience, identity) = sql(connection.query_row(
        "SELECT environment, integration_id, evidence_class, policy_version, audience,
                    lookup_key_identity
             FROM deployment WHERE singleton = 1",
        [],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Vec<u8>>(5)?,
            ))
        },
    ))?;
    let mut found = Vec::new();
    if identity != key.identity() {
        found.push(Mismatch::LookupKey);
    }
    if environment != environment_name(config.environment) {
        found.push(Mismatch::Environment);
    }
    if integration != provider.integration_id
        || class != class_name(provider.evidence_class)
        || policy != provider.policy_version
    {
        found.push(Mismatch::Provider);
    }
    if audience != config.provider_audience {
        found.push(Mismatch::Audience);
    }
    Ok(found)
}
