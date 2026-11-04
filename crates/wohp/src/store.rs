use crate::{Config, Environment, LookupKey, crypto};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{path::Path, time::Duration};
use wohp_api::{
    AgeThreshold, BindingStatus, ClientId, ClientRegistration, Completion, CompletionKind, Error,
    EvidenceClass, IdentityFlow, IdentityStatus, ProviderDescriptor, Purpose, Registration,
    Subject, Timestamp, VerificationContext, VerifiedPerson,
};

/// `PRAGMA user_version` of `schema.sql`. Older files are refused, never migrated.
pub(crate) const SCHEMA_VERSION: u32 = 5;

pub(crate) struct Store {
    connection: Connection,
}

pub(crate) struct RecoveryTarget {
    subject: Subject,
    epoch: u64,
}

/// A consumed challenge: what it was issued for.
pub(crate) struct Consumed {
    pub(crate) context: VerificationContext,
    pub(crate) target: Option<RecoveryTarget>,
    /// The requesting client's minimum age when the challenge was issued.
    pub(crate) minimum_age: Option<AgeThreshold>,
}

fn sql<T>(result: rusqlite::Result<T>) -> Result<T, Error> {
    // SQL errors may contain schema values and identifiers. Do not forward them.
    result.map_err(|_| Error::Storage)
}

#[cfg(unix)]
fn ensure_private_database_file(path: &Path) -> Result<(), Error> {
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
            let metadata = fs::symlink_metadata(path).map_err(|_| Error::Storage)?;
            if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::InvalidConfiguration);
            }
            Ok(())
        }
        Err(_) => Err(Error::Storage),
    }
}

/// How `deployment.environment` spells an environment.
pub(crate) fn environment_name(environment: Environment) -> &'static str {
    match environment {
        Environment::Development => "development",
        Environment::Production => "production",
    }
}

/// How `deployment.evidence_class` spells an evidence class.
pub(crate) fn class_name(class: EvidenceClass) -> &'static str {
    match class {
        EvidenceClass::Production => "production",
        _ => "development",
    }
}

/// A stored age threshold column; anything else is a corrupt row.
pub(crate) fn threshold(years: Option<u8>) -> Result<Option<AgeThreshold>, Error> {
    years
        .map(|years| AgeThreshold::from_years(years).ok_or(Error::Storage))
        .transpose()
}

impl Store {
    pub(crate) fn open(
        path: &Path,
        config: &Config,
        provider: &ProviderDescriptor,
        key: &LookupKey,
    ) -> Result<Self, Error> {
        #[cfg(unix)]
        ensure_private_database_file(path)?;
        let mut connection = sql(Connection::open(path))?;
        sql(connection.busy_timeout(Duration::from_secs(5)))?;
        sql(connection.pragma_update(None, "foreign_keys", true))?;
        sql(connection.pragma_update(None, "journal_mode", "WAL"))?;
        sql(connection.pragma_update(None, "synchronous", "FULL"))?;
        let tx = sql(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let version: u32 = sql(tx.pragma_query_value(None, "user_version", |r| r.get(0)))?;
        let environment = environment_name(config.environment);
        let class = class_name(provider.evidence_class);
        if version == 0 {
            let tables: u64 = sql(tx.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                [], |r| r.get(0),
            ))?;
            if tables != 0 {
                return Err(Error::ConfigurationMismatch);
            }
            sql(tx.execute_batch(include_str!("schema.sql")))?;
            sql(tx.execute(
                "INSERT INTO deployment (singleton,environment,integration_id,evidence_class,policy_version,audience,lookup_key_identity) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    environment,
                    provider.integration_id,
                    class,
                    provider.policy_version,
                    config.provider_audience,
                    key.identity()
                ],
            ))?;
        } else if version != SCHEMA_VERSION {
            // No upgrade path: databases of earlier schemas are not opened.
            return Err(Error::ConfigurationMismatch);
        }
        let matches: bool = sql(tx.query_row(
            "SELECT environment = ?1 AND integration_id = ?2 AND evidence_class = ?3
             AND policy_version = ?4 AND audience = ?5 AND lookup_key_identity = ?6
             FROM deployment WHERE singleton = 1",
            params![
                environment,
                provider.integration_id,
                class,
                provider.policy_version,
                config.provider_audience,
                key.identity()
            ],
            |r| r.get(0),
        ))?;
        if !matches {
            return Err(Error::ConfigurationMismatch);
        }
        // Relying parties are registered explicitly by the operator; none is
        // implied.
        sql(tx.commit())?;
        Ok(Self { connection })
    }

    /// Registers a client or updates its minimum age to the configured one.
    /// A different scope for an existing client id is refused: its pairwise
    /// subjects belong to that scope. Registrations and changes are audited.
    pub(crate) fn register_client(
        &mut self,
        registration: &ClientRegistration,
        now: Timestamp,
    ) -> Result<Registration, Error> {
        let tx = sql(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let existing: Option<(String, Option<u8>)> = sql(tx
            .query_row(
                "SELECT application_scope, minimum_age FROM clients WHERE client_id=?1",
                [registration.client_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional())?;
        let client = registration.client_id.as_str();
        let current = registration.minimum_age;
        let years = current.map(AgeThreshold::years);
        let outcome = match existing {
            Some((scope, _)) if scope != registration.application_scope => {
                return Err(Error::ConfigurationMismatch);
            }
            Some((_, stored)) if stored == years => Registration::Unchanged,
            Some((_, stored)) => {
                sql(tx.execute(
                    "UPDATE clients SET minimum_age=?2 WHERE client_id=?1",
                    params![client, years],
                ))?;
                sql(tx.execute(
                    "INSERT INTO client_events(client_id,event,minimum_age,occurred_at)
                     VALUES(?1,'MINIMUM_AGE_CHANGED',?2,?3)",
                    params![client, years, now],
                ))?;
                Registration::MinimumAgeChanged {
                    previous: threshold(stored)?,
                    current,
                }
            }
            None => {
                sql(tx.execute(
                    "INSERT INTO clients(client_id,application_scope,minimum_age) VALUES(?1,?2,?3)",
                    params![client, registration.application_scope, years],
                ))?;
                sql(tx.execute(
                    "INSERT INTO client_events(client_id,event,minimum_age,occurred_at)
                     VALUES(?1,'REGISTERED',?2,?3)",
                    params![client, years, now],
                ))?;
                Registration::Created
            }
        };
        sql(tx.commit())?;
        Ok(outcome)
    }

    pub(crate) fn client_registration(
        &self,
        client_id: &ClientId,
    ) -> Result<ClientRegistration, Error> {
        let row: Option<(String, Option<u8>)> = sql(self
            .connection
            .query_row(
                "SELECT application_scope, minimum_age FROM clients WHERE client_id=?1",
                [client_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional())?;
        let (scope, minimum_age) = row.ok_or(Error::UnknownClient)?;
        ClientRegistration::new(client_id.clone(), &scope, threshold(minimum_age)?)
            .map_err(|_| Error::Storage)
    }

    pub(crate) fn client_subject(
        &mut self,
        client_id: &ClientId,
        profile_subject: &Subject,
    ) -> Result<Subject, Error> {
        let tx = sql(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let registered: bool = sql(tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM clients WHERE client_id=?1)",
            [client_id.as_str()],
            |row| row.get(0),
        ))?;
        if !registered {
            return Err(Error::UnknownClient);
        }
        let subject: Option<String> = sql(tx
            .query_row(
                "SELECT subject FROM client_subjects WHERE client_id=?1 AND profile_subject=?2",
                params![client_id.as_str(), profile_subject.as_str()],
                |row| row.get(0),
            )
            .optional())?;
        let subject = match subject {
            Some(subject) => subject,
            None => {
                let subject = crypto::random_token()?;
                sql(tx.execute(
                    "INSERT INTO client_subjects(client_id,profile_subject,subject) VALUES(?1,?2,?3)",
                    params![client_id.as_str(), profile_subject.as_str(), subject],
                ))?;
                subject
            }
        };
        sql(tx.commit())?;
        Subject::parse(&subject).map_err(|_| Error::Storage)
    }

    /// Reverse lookup of a pairwise client subject. Unknown clients, unknown
    /// subjects and subjects issued to another client all return the same error.
    pub(crate) fn profile_for_client_subject(
        &self,
        client_id: &ClientId,
        client_subject: &Subject,
    ) -> Result<Subject, Error> {
        let profile: Option<String> = sql(self
            .connection
            .query_row(
                "SELECT profile_subject FROM client_subjects WHERE client_id=?1 AND subject=?2",
                params![client_id.as_str(), client_subject.as_str()],
                |row| row.get(0),
            )
            .optional())?;
        let profile = profile.ok_or(Error::SubjectNotFound)?;
        Subject::parse(&profile).map_err(|_| Error::Storage)
    }

    /// The minimum age of a registered client.
    pub(crate) fn client_minimum_age(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<AgeThreshold>, Error> {
        let row: Option<Option<u8>> = sql(self
            .connection
            .query_row(
                "SELECT minimum_age FROM clients WHERE client_id=?1",
                [client_id.as_str()],
                |row| row.get(0),
            )
            .optional())?;
        threshold(row.ok_or(Error::UnknownClient)?)
    }

    pub(crate) fn begin(
        &mut self,
        context: &VerificationContext,
        flow: IdentityFlow,
        minimum_age: Option<AgeThreshold>,
    ) -> Result<(), Error> {
        let tx = sql(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        sql(tx.execute(
            "DELETE FROM challenges WHERE expires_at <= ?1",
            [context.issued_at],
        ))?;
        let pending: u64 = sql(tx.query_row("SELECT count(*) FROM challenges", [], |r| r.get(0)))?;
        if pending >= 1024 {
            return Err(Error::Capacity);
        }
        let target = match flow {
            IdentityFlow::Enrollment => None,
            IdentityFlow::Recovery { subject } => Some(subject),
        };
        let epoch = if let Some(subject) = &target {
            Some(
                sql(tx
                    .query_row(
                        "SELECT authentication_epoch FROM humans WHERE subject=?1",
                        [subject.as_str()],
                        |r| r.get::<_, u64>(0),
                    )
                    .optional())?
                .ok_or(Error::SubjectNotFound)?,
            )
        } else {
            None
        };
        sql(tx.execute(
            "INSERT INTO challenges (id, nonce, audience, target_subject, issued_at, expires_at, target_epoch, minimum_age)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![context.challenge_id, context.nonce, context.audience,
                target.as_ref().map(Subject::as_str), context.issued_at, context.expires_at, epoch,
                minimum_age.map(AgeThreshold::years)],
        ))?;
        sql(tx.commit())
    }

    pub(crate) fn consume(&mut self, id: &str, now: Timestamp) -> Result<Consumed, Error> {
        let tx = sql(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let row = sql(tx.query_row(
            "SELECT nonce, audience, target_subject, issued_at, expires_at, consumed, target_epoch, minimum_age FROM challenges WHERE id = ?1",
            [id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?,
                r.get::<_, u64>(3)?, r.get::<_, u64>(4)?, r.get::<_, bool>(5)?, r.get::<_, Option<u64>>(6)?,
                r.get::<_, Option<u8>>(7)?)),
        ).optional())?.ok_or(Error::ChallengeRejected)?;
        if row.5 {
            return Err(Error::ChallengeRejected);
        }
        if now < row.3 || now >= row.4 {
            return Err(Error::Expired);
        }
        sql(tx.execute("UPDATE challenges SET consumed = 1 WHERE id = ?1", [id]))?;
        sql(tx.commit())?;
        let target = match (row.2, row.6) {
            (Some(subject), Some(epoch)) => Some(RecoveryTarget {
                subject: Subject::parse(&subject).map_err(|_| Error::Storage)?,
                epoch,
            }),
            (None, None) => None,
            _ => return Err(Error::Storage),
        };
        let purpose = if target.is_some() {
            Purpose::Recovery
        } else {
            Purpose::Enrollment
        };
        Ok(Consumed {
            context: VerificationContext {
                challenge_id: id.into(),
                nonce: row.0,
                audience: row.1,
                purpose,
                issued_at: row.3,
                expires_at: row.4,
            },
            target,
            minimum_age: threshold(row.7)?,
        })
    }

    pub(crate) fn apply(
        &mut self,
        lookup: &[u8],
        target: Option<&RecoveryTarget>,
        proof: &VerifiedPerson,
        now: Timestamp,
    ) -> Result<Completion, Error> {
        let tx = sql(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let existing = sql(tx
            .query_row(
                "SELECT subject, authentication_epoch FROM humans WHERE lookup_key = ?1",
                [lookup],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?)),
            )
            .optional())?;
        let (subject, epoch, kind) = match (target, existing) {
            (None, Some((subject, epoch))) => {
                // Matching alone must NEVER restore access, renew evidence or
                // clear a revocation. Caller must authenticate or recover.
                (
                    subject,
                    epoch,
                    CompletionKind::ExistingRequiresAuthentication,
                )
            }
            (None, None) => {
                let subject = crypto::random_token()?;
                sql(tx.execute(
                    "INSERT INTO humans (subject, lookup_key, authentication_epoch, verified_at,
                     valid_until, age_at_least, age_valid_until, created_at) VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7)",
                    params![subject, lookup, proof.verified_at, proof.valid_until,
                        proof.age.map(|a| a.at_least.years()), proof.age.map(|a| a.valid_until), now],
                ))?;
                sql(tx.execute("INSERT INTO security_events(subject,event,occurred_at) VALUES (?1,'ENROLLED',?2)", params![subject, now]))?;
                (subject, 1, CompletionKind::Created)
            }
            (Some(target), Some((subject, epoch))) if subject == target.subject.as_str() => {
                if epoch != target.epoch {
                    return Err(Error::EpochMismatch);
                }
                let epoch = epoch
                    .checked_add(1)
                    .filter(|value| *value <= i64::MAX as u64)
                    .ok_or(Error::Storage)?;
                sql(tx.execute(
                    "UPDATE humans SET revoked = 0, authentication_epoch = ?2, verified_at = ?3,
                      valid_until = ?4, age_at_least = ?5, age_valid_until = ?6 WHERE subject = ?1",
                    params![
                        subject,
                        epoch,
                        proof.verified_at,
                        proof.valid_until,
                        proof.age.map(|a| a.at_least.years()),
                        proof.age.map(|a| a.valid_until)
                    ],
                ))?;
                sql(tx.execute(
                    "UPDATE challenges SET consumed = 1 WHERE target_subject = ?1",
                    [&subject],
                ))?;
                sql(tx.execute("INSERT INTO security_events(subject,event,occurred_at) VALUES (?1,'RECOVERED',?2)", params![subject, now]))?;
                (subject, epoch, CompletionKind::Recovered)
            }
            (Some(_), _) => return Err(Error::SubjectMismatch),
        };
        sql(tx.commit())?;
        Ok(Completion {
            subject: Subject::parse(&subject).map_err(|_| Error::Storage)?,
            authentication_epoch: epoch,
            kind,
            evidence_class: proof.evidence_class,
        })
    }

    /// Status of a person for a policy: with a `minimum_age`, the binding is
    /// valid only while current age evidence meets it; without one, age does
    /// not matter (deduplication only).
    pub(crate) fn status(
        &self,
        subject: &Subject,
        now: Timestamp,
        minimum_age: Option<AgeThreshold>,
    ) -> Result<BindingStatus, Error> {
        let row = sql(self.connection.query_row(
            "SELECT revoked, authentication_epoch, verified_at, valid_until, age_at_least, age_valid_until
             FROM humans WHERE subject = ?1", [subject.as_str()],
            |r| Ok((r.get::<_, bool>(0)?, r.get::<_, u64>(1)?, r.get::<_, u64>(2)?,
                 r.get::<_, u64>(3)?, r.get::<_, Option<u8>>(4)?, r.get::<_, Option<u64>>(5)?)),
        ).optional())?.ok_or(Error::SubjectNotFound)?;
        let age =
            threshold(row.4)?.filter(|_| row.5.is_some_and(|until| until > now) && now >= row.2);
        let valid_until = row.3.min(if minimum_age.is_some() {
            row.5.unwrap_or(0)
        } else {
            row.3
        });
        let status = if row.0 {
            IdentityStatus::Revoked
        } else if now < row.2
            || now >= valid_until
            || minimum_age.is_some_and(|floor| !age.is_some_and(|value| value >= floor))
        {
            IdentityStatus::RevalidationRequired
        } else {
            IdentityStatus::Valid
        };
        Ok(BindingStatus {
            status,
            policy_version: String::new(),
            authentication_epoch: row.1,
            age_at_least: age,
            age_valid_until: row.5.filter(|_| age.is_some()),
            checked_at: now,
            valid_until,
            evidence_class: EvidenceClass::DevelopmentOnly,
        })
    }

    pub(crate) fn revoke(&mut self, subject: &Subject, now: Timestamp) -> Result<(), Error> {
        self.advance_epoch(subject, now, true).map(|_| ())
    }

    /// Compromise reset: the client's authenticators were revoked. The epoch
    /// advances so sessions bound to the old one end; the identity status is
    /// unchanged. Pending recoveries bound to the old epoch are cancelled.
    pub(crate) fn reset_authenticators(
        &mut self,
        subject: &Subject,
        now: Timestamp,
    ) -> Result<u64, Error> {
        self.advance_epoch(subject, now, false)
    }

    fn advance_epoch(
        &mut self,
        subject: &Subject,
        now: Timestamp,
        revoke: bool,
    ) -> Result<u64, Error> {
        let tx = sql(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let epoch: u64 = sql(tx
            .query_row(
                "SELECT authentication_epoch FROM humans WHERE subject=?1",
                [subject.as_str()],
                |r| r.get(0),
            )
            .optional())?
        .ok_or(Error::SubjectNotFound)?;
        let epoch = epoch
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(Error::Storage)?;
        sql(tx.execute(
            "UPDATE humans SET revoked = (revoked OR ?3), authentication_epoch=?2 WHERE subject=?1",
            params![subject.as_str(), epoch, revoke],
        ))?;
        sql(tx.execute(
            "UPDATE challenges SET consumed=1 WHERE target_subject=?1",
            [subject.as_str()],
        ))?;
        sql(tx.execute(
            "INSERT INTO security_events(subject,event,occurred_at) VALUES (?1,?2,?3)",
            params![
                subject.as_str(),
                if revoke {
                    "REVOKED"
                } else {
                    "AUTHENTICATORS_RESET"
                },
                now
            ],
        ))?;
        sql(tx.commit())?;
        Ok(epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(name: &str) -> (std::path::PathBuf, Store) {
        let dir = std::env::temp_dir().join(format!("wohp-store-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("core.sqlite3");
        let _ = std::fs::remove_file(&path);
        let descriptor = ProviderDescriptor {
            integration_id: "source".into(),
            policy_version: "policy".into(),
            evidence_class: EvidenceClass::DevelopmentOnly,
        };
        let key = LookupKey::from_bytes(&[9; 32]).unwrap();
        let store = Store::open(&path, &Config::development(), &descriptor, &key).unwrap();
        (dir, store)
    }

    #[test]
    fn earlier_schemas_are_refused_not_migrated() {
        let (dir, store) = store("old-schema");
        store
            .connection
            .execute_batch("PRAGMA user_version=4;")
            .unwrap();
        drop(store);
        let descriptor = ProviderDescriptor {
            integration_id: "source".into(),
            policy_version: "policy".into(),
            evidence_class: EvidenceClass::DevelopmentOnly,
        };
        let key = LookupKey::from_bytes(&[9; 32]).unwrap();
        assert!(matches!(
            Store::open(
                &dir.join("core.sqlite3"),
                &Config::development(),
                &descriptor,
                &key
            ),
            Err(Error::ConfigurationMismatch)
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn authenticator_reset_only_advances_the_epoch() {
        let (dir, mut store) = store("reset");
        let subject = crypto::random_token().unwrap();
        store
            .connection
            .execute(
                "INSERT INTO humans (subject, lookup_key, authentication_epoch, verified_at, valid_until, created_at)
                 VALUES (?1, ?2, 1, 900, 3000, 900)",
                params![subject, &[2_u8; 32][..]],
            )
            .unwrap();
        let parsed = Subject::parse(&subject).unwrap();
        assert_eq!(store.reset_authenticators(&parsed, 1000).unwrap(), 2);
        let status = store.status(&parsed, 1001, None).unwrap();
        assert_eq!(status.status, IdentityStatus::Valid);
        assert_eq!(status.authentication_epoch, 2);
        store.revoke(&parsed, 1002).unwrap();
        let status = store.status(&parsed, 1003, None).unwrap();
        assert_eq!(
            (status.status, status.authentication_epoch),
            (IdentityStatus::Revoked, 3)
        );
        // A reset never clears a revocation.
        assert_eq!(store.reset_authenticators(&parsed, 1004).unwrap(), 4);
        assert_eq!(
            store.status(&parsed, 1005, None).unwrap().status,
            IdentityStatus::Revoked
        );
        let events: Vec<String> = store
            .connection
            .prepare("SELECT event FROM security_events ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            events,
            ["AUTHENTICATORS_RESET", "REVOKED", "AUTHENTICATORS_RESET"]
        );
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
