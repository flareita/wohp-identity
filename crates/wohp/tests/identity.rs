#![forbid(unsafe_code)]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
    thread,
};
use wohp::{Clock, Config, Environment, LookupKey, Service};
use wohp_api::{
    AgeThreshold, ClientId, ClientRegistration, Completion, CompletionKind, Error, EvidenceClass,
    IdentityFlow, IdentityProvider, IdentityService, IdentityStatus, Presentation,
    ProviderDescriptor, ProviderError, Purpose, Registration, Subject, VerificationContext,
    VerificationOutcome,
};
use wohp_mock::{MockIdentityProvider, Scenario};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

const DAY: u64 = 86_400;

struct Database {
    directory: PathBuf,
}
impl Database {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "wohp-test-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self { directory }
    }
    fn path(&self) -> PathBuf {
        self.directory.join("identity.sqlite3")
    }
    fn humans(&self) -> u64 {
        rusqlite::Connection::open(self.path())
            .unwrap()
            .query_row("SELECT count(*) FROM humans", [], |r| r.get(0))
            .unwrap()
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);
impl TestClock {
    fn new() -> Self {
        Self(Arc::new(AtomicU64::new(1_000_000)))
    }
    fn advance(&self, seconds: u64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}
impl Clock for TestClock {
    fn now(&self) -> Result<u64, Error> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

/// Opens the service and registers the test client with `floor` as its
/// minimum age.
fn open<P: IdentityProvider>(
    path: &Path,
    provider: Arc<P>,
    clock: TestClock,
    floor: Option<AgeThreshold>,
) -> Service<P, TestClock> {
    let mut service = Service::open(
        path,
        Config::development(),
        provider,
        LookupKey::from_bytes(&[7; 32]).unwrap(),
        clock,
    )
    .unwrap();
    service
        .register_client(
            ClientRegistration::new(ClientId::parse(IDP_CLIENT).unwrap(), "idp.network", floor)
                .unwrap(),
        )
        .unwrap();
    service
}

fn idp() -> ClientId {
    ClientId::parse(IDP_CLIENT).unwrap()
}

/// The first-party identity provider client every test service registers.
const IDP_CLIENT: &str = "first-party-idp";

fn attempt(
    service: &mut impl IdentityService,
    provider: &MockIdentityProvider,
    flow: IdentityFlow,
    scenario: Scenario,
) -> Result<Completion, Error> {
    let context = service.begin(flow)?;
    let proof = provider.issue(&context, scenario).unwrap();
    service.complete(&context.challenge_id, &proof)
}

/// A verification started by the test client: its minimum age applies.
fn attempt_for<P: IdentityProvider>(
    service: &mut Service<P, TestClock>,
    provider: &MockIdentityProvider,
    flow: IdentityFlow,
    scenario: Scenario,
) -> Result<Completion, Error> {
    let context = service.begin_for_client(&idp(), flow)?;
    let proof = provider.issue(&context, scenario).unwrap();
    service.complete(&context.challenge_id, &proof)
}

fn enroll(
    service: &mut impl IdentityService,
    provider: &MockIdentityProvider,
    person: &str,
) -> Completion {
    attempt(
        service,
        provider,
        IdentityFlow::Enrollment,
        Scenario::person(person, Some(true)),
    )
    .unwrap()
}

#[test]
fn a_client_minimum_age_is_enforced_before_storing_and_follows_its_configuration() {
    let db = Database::new();
    let clock = TestClock::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let mut service = open(
        &db.path(),
        Arc::clone(&provider),
        clock.clone(),
        Some(AgeThreshold::Sixteen),
    );
    for young in [
        Some(AgeThreshold::Thirteen),
        Some(AgeThreshold::Fourteen),
        None,
    ] {
        assert_eq!(
            attempt_for(
                &mut service,
                &provider,
                IdentityFlow::Enrollment,
                Scenario::aged("young", young)
            )
            .unwrap_err(),
            Error::AgeRequired
        );
    }
    assert_eq!(db.humans(), 0, "refused people are never stored");
    let original = attempt_for(
        &mut service,
        &provider,
        IdentityFlow::Enrollment,
        Scenario::aged("sixteen", Some(AgeThreshold::Sixteen)),
    )
    .unwrap();
    let original_client = service.client_subject(&idp(), &original.subject).unwrap();
    // Without a client there is no age requirement.
    let unknown = attempt(
        &mut service,
        &provider,
        IdentityFlow::Enrollment,
        Scenario::aged("unknown", None),
    )
    .unwrap();
    assert_eq!(
        service.status(&unknown.subject).unwrap().status,
        IdentityStatus::Valid
    );

    let reconfigure = |service: &mut Service<MockIdentityProvider, TestClock>,
                       floor: Option<AgeThreshold>| {
        service
            .register_client(ClientRegistration::new(idp(), "idp.network", floor).unwrap())
            .unwrap()
    };
    assert_eq!(
        reconfigure(&mut service, Some(AgeThreshold::Sixteen)),
        Registration::Unchanged
    );
    assert_eq!(
        reconfigure(&mut service, Some(AgeThreshold::Thirteen)),
        Registration::MinimumAgeChanged {
            previous: Some(AgeThreshold::Sixteen),
            current: Some(AgeThreshold::Thirteen),
        }
    );
    let younger = attempt_for(
        &mut service,
        &provider,
        IdentityFlow::Enrollment,
        Scenario::aged("thirteen", Some(AgeThreshold::Thirteen)),
    )
    .unwrap();
    let younger_client = service.client_subject(&idp(), &younger.subject).unwrap();
    reconfigure(&mut service, Some(AgeThreshold::Eighteen));
    for subject in [&original_client, &younger_client] {
        assert_eq!(
            service.status_for_client(&idp(), subject).unwrap().status,
            IdentityStatus::RevalidationRequired
        );
    }
    // The people themselves are untouched: subjects and epochs stay.
    assert_eq!(
        service.status(&original.subject).unwrap().status,
        IdentityStatus::Valid
    );
    reconfigure(&mut service, None);
    assert_eq!(
        service
            .status_for_client(&idp(), &younger_client)
            .unwrap()
            .status,
        IdentityStatus::Valid
    );
    assert_eq!(db.humans(), 3);
    let events: Vec<(String, Option<u8>)> = rusqlite::Connection::open(db.path())
        .unwrap()
        .prepare("SELECT event, minimum_age FROM client_events ORDER BY id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        events,
        [
            ("REGISTERED".to_owned(), Some(16)),
            ("MINIMUM_AGE_CHANGED".to_owned(), Some(13)),
            ("MINIMUM_AGE_CHANGED".to_owned(), Some(18)),
            ("MINIMUM_AGE_CHANGED".to_owned(), None),
        ]
    );
    // A different scope for a registered client id is refused.
    assert_eq!(
        service
            .register_client(ClientRegistration::new(idp(), "other.network", None).unwrap())
            .unwrap_err(),
        Error::ConfigurationMismatch
    );
}

#[test]
fn a_client_without_an_age_floor_stores_young_evidence() {
    let db = Database::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let mut service = open(&db.path(), Arc::clone(&provider), TestClock::new(), None);
    let completion = attempt_for(
        &mut service,
        &provider,
        IdentityFlow::Enrollment,
        Scenario::aged("young", Some(AgeThreshold::Fourteen)),
    )
    .unwrap();
    let client_subject = service.client_subject(&idp(), &completion.subject).unwrap();
    let status = service.status_for_client(&idp(), &client_subject).unwrap();
    assert_eq!(status.status, IdentityStatus::Valid);
    assert_eq!(status.age_at_least, Some(AgeThreshold::Fourteen));
    assert_eq!(db.humans(), 1);
}

#[test]
fn subject_persists_across_restarts_and_distinct_presentations() {
    let db = Database::new();
    let clock = TestClock::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let mut service = open(&db.path(), Arc::clone(&provider), clock.clone(), None);
    let original = enroll(&mut service, &provider, "canonical-alice");
    assert_eq!(original.kind, CompletionKind::Created);
    assert_eq!(original.subject.as_str().len(), 43);
    assert_eq!(original.evidence_class, EvidenceClass::DevelopmentOnly);
    drop(service);
    let mut restarted = open(&db.path(), Arc::clone(&provider), clock, None);
    let same = enroll(&mut restarted, &provider, "canonical-alice");
    assert_eq!(same.kind, CompletionKind::ExistingRequiresAuthentication);
    assert_eq!(same.subject, original.subject);
    let other = enroll(&mut restarted, &provider, "canonical-bob");
    assert_ne!(other.subject, same.subject);
    assert_eq!(db.humans(), 2);
    assert_eq!(
        restarted.status(&same.subject).unwrap().age_at_least,
        Some(AgeThreshold::Eighteen)
    );
}

#[test]
fn registered_clients_receive_stable_pairwise_subjects() {
    let db = Database::new();
    let clock = TestClock::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let mut service = open(&db.path(), Arc::clone(&provider), clock.clone(), None);
    let profile = enroll(&mut service, &provider, "canonical-alice").subject;
    let bootstrap = ClientId::parse(IDP_CLIENT).unwrap();
    let bootstrap_subject = service.client_subject(&bootstrap, &profile).unwrap();
    assert_eq!(
        service.client_subject(&bootstrap, &profile).unwrap(),
        bootstrap_subject
    );

    let other = ClientId::parse("example-service").unwrap();
    assert_eq!(
        service.client_subject(&other, &profile).unwrap_err(),
        Error::UnknownClient
    );
    service
        .register_client(ClientRegistration::new(other.clone(), "example.service", None).unwrap())
        .unwrap();
    let other_subject = service.client_subject(&other, &profile).unwrap();
    assert_ne!(bootstrap_subject, other_subject);
    assert_eq!(
        service
            .client_registration(&other)
            .unwrap()
            .application_scope,
        "example.service"
    );
    drop(service);

    let mut reopened = open(&db.path(), provider, clock, None);
    assert_eq!(
        reopened.client_subject(&bootstrap, &profile).unwrap(),
        bootstrap_subject
    );
    assert_eq!(
        reopened.client_subject(&other, &profile).unwrap(),
        other_subject
    );
}

#[test]
fn status_for_client_resolves_only_the_issued_pairwise_subject() {
    let db = Database::new();
    let clock = TestClock::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let mut service = open(&db.path(), Arc::clone(&provider), clock.clone(), None);
    let alice = enroll(&mut service, &provider, "canonical-alice").subject;
    let bob = enroll(&mut service, &provider, "canonical-bob").subject;
    let bootstrap = ClientId::parse(IDP_CLIENT).unwrap();
    let alice_subject = service.client_subject(&bootstrap, &alice).unwrap();
    let bob_subject = service.client_subject(&bootstrap, &bob).unwrap();

    let status = service
        .status_for_client(&bootstrap, &alice_subject)
        .unwrap();
    assert_eq!(status.status, IdentityStatus::Valid);
    assert_eq!(status.authentication_epoch, 1);
    assert_eq!(
        service
            .profile_for_client_subject(&bootstrap, &bob_subject)
            .unwrap(),
        bob
    );

    // A profile subject is not a client subject, and another client's subject
    // does not resolve either: all failures look the same.
    let other = ClientId::parse("example-service").unwrap();
    service
        .register_client(ClientRegistration::new(other.clone(), "example.service", None).unwrap())
        .unwrap();
    let other_subject = service.client_subject(&other, &alice).unwrap();
    for (client, subject) in [
        (&bootstrap, &alice),
        (&bootstrap, &other_subject),
        (&other, &alice_subject),
        (&ClientId::parse("unregistered").unwrap(), &alice_subject),
    ] {
        assert_eq!(
            service.status_for_client(client, subject).unwrap_err(),
            Error::SubjectNotFound
        );
    }

    // Revocation is visible through the client subject, with the new epoch.
    service.revoke(&alice).unwrap();
    let revoked = service
        .status_for_client(&bootstrap, &alice_subject)
        .unwrap();
    assert_eq!(revoked.status, IdentityStatus::Revoked);
    assert_eq!(revoked.authentication_epoch, 2);
}

#[test]
fn client_registration_rejects_non_protocol_tokens() {
    assert!(ClientId::parse("client id").is_err());
    let client = ClientId::parse("example-service").unwrap();
    assert!(ClientRegistration::new(client, "example service", None).is_err());
}

#[test]
fn concurrent_duplicate_enrollment_across_connections_creates_one_human() {
    let db = Database::new();
    let clock = TestClock::new();
    let provider = Arc::new(MockIdentityProvider::default());
    drop(open(&db.path(), Arc::clone(&provider), clock.clone(), None));
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let path = db.path();
            let clock = clock.clone();
            let provider = Arc::clone(&provider);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut service = open(&path, Arc::clone(&provider), clock, None);
                barrier.wait();
                enroll(&mut service, &provider, "same-canonical-person")
            })
        })
        .collect();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert!(
        outcomes
            .iter()
            .all(|outcome| outcome.subject == outcomes[0].subject)
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome.kind == CompletionKind::Created)
            .count(),
        1
    );
    assert_eq!(db.humans(), 1);
}

#[test]
fn ambiguity_unavailability_and_invalid_proofs_create_no_profiles_and_burn_attempts() {
    let db = Database::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let mut service = open(&db.path(), Arc::clone(&provider), TestClock::new(), None);
    for (scenario, expected) in [
        (Scenario::Ambiguous, Error::AmbiguousIdentity),
        (Scenario::Unavailable, Error::ProviderUnavailable),
        (Scenario::Invalid, Error::InvalidEvidence),
    ] {
        let context = service.begin(IdentityFlow::Enrollment).unwrap();
        let evidence = provider.issue(&context, scenario).unwrap();
        assert_eq!(
            service
                .complete(&context.challenge_id, &evidence)
                .unwrap_err(),
            expected
        );
        assert_eq!(
            service
                .complete(&context.challenge_id, &evidence)
                .unwrap_err(),
            Error::ChallengeRejected
        );
    }
    assert_eq!(db.humans(), 0);
}

#[test]
fn expired_challenges_and_cross_challenge_presentations_are_rejected() {
    let db = Database::new();
    let clock = TestClock::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let mut service = open(&db.path(), Arc::clone(&provider), clock.clone(), None);
    let first = service.begin(IdentityFlow::Enrollment).unwrap();
    let second = service.begin(IdentityFlow::Enrollment).unwrap();
    let evidence = provider
        .issue(&first, Scenario::person("alice", None))
        .unwrap();
    assert_eq!(
        service
            .complete(&second.challenge_id, &evidence)
            .unwrap_err(),
        Error::InvalidEvidence
    );
    let evidence = provider
        .issue(&first, Scenario::person("alice", None))
        .unwrap();
    clock.advance(300);
    assert_eq!(
        service
            .complete(&first.challenge_id, &evidence)
            .unwrap_err(),
        Error::Expired
    );
    assert_eq!(db.humans(), 0);
}

#[test]
fn successful_challenge_is_single_use_even_after_restart() {
    let db = Database::new();
    let clock = TestClock::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let mut service = open(&db.path(), Arc::clone(&provider), clock.clone(), None);
    let context = service.begin(IdentityFlow::Enrollment).unwrap();
    let evidence = provider
        .issue(&context, Scenario::person("alice", None))
        .unwrap();
    service.complete(&context.challenge_id, &evidence).unwrap();
    drop(service);
    let mut service = open(&db.path(), Arc::clone(&provider), clock, None);
    assert_eq!(
        service
            .complete(&context.challenge_id, &evidence)
            .unwrap_err(),
        Error::ChallengeRejected
    );
    assert_eq!(db.humans(), 1);
}

#[test]
fn concurrent_completion_consumes_once() {
    let db = Database::new();
    let clock = TestClock::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let mut service = open(&db.path(), Arc::clone(&provider), clock.clone(), None);
    let context = service.begin(IdentityFlow::Enrollment).unwrap();
    let evidence = provider
        .issue(&context, Scenario::person("alice", None))
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let path = db.path();
            let clock = clock.clone();
            let evidence = evidence.clone();
            let provider = Arc::clone(&provider);
            let barrier = Arc::clone(&barrier);
            let id = context.challenge_id.clone();
            thread::spawn(move || {
                let mut service = open(&path, provider, clock, None);
                barrier.wait();
                service.complete(&id, &evidence)
            })
        })
        .collect();
    let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(
        outcomes
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| *e == Error::ChallengeRejected)
    );
}

#[test]
fn recovery_preserves_subject_increments_epoch_and_reenrollment_never_restores_revocation() {
    let db = Database::new();
    let clock = TestClock::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let mut service = open(&db.path(), Arc::clone(&provider), clock.clone(), None);
    let alice = enroll(&mut service, &provider, "alice");
    service.revoke(&alice.subject).unwrap();
    let again = enroll(&mut service, &provider, "alice");
    assert_eq!(again.kind, CompletionKind::ExistingRequiresAuthentication);
    assert_eq!(
        service.status(&alice.subject).unwrap().status,
        IdentityStatus::Revoked
    );
    assert_eq!(
        service.validate_epoch(&alice.subject, 1).unwrap_err(),
        Error::EpochMismatch
    );
    assert_eq!(
        service.validate_epoch(&alice.subject, 2).unwrap_err(),
        Error::Revoked
    );
    let wrong = attempt(
        &mut service,
        &provider,
        IdentityFlow::Recovery {
            subject: alice.subject.clone(),
        },
        Scenario::person("bob", None),
    );
    assert_eq!(wrong.unwrap_err(), Error::SubjectMismatch);
    assert_eq!(db.humans(), 1);
    let recovered = attempt(
        &mut service,
        &provider,
        IdentityFlow::Recovery {
            subject: alice.subject.clone(),
        },
        Scenario::person("alice", None),
    )
    .unwrap();
    assert_eq!(recovered.subject, alice.subject);
    assert_eq!(recovered.kind, CompletionKind::Recovered);
    assert_eq!(recovered.authentication_epoch, 3);
    assert_eq!(
        service.validate_epoch(&alice.subject, 2).unwrap_err(),
        Error::EpochMismatch
    );
    assert_eq!(
        service.validate_epoch(&alice.subject, 3).unwrap().status,
        IdentityStatus::Valid
    );
    drop(service);
    assert_eq!(
        open(&db.path(), provider, clock, None)
            .status(&alice.subject)
            .unwrap()
            .authentication_epoch,
        3
    );
}

#[test]
fn evidence_expiry_requires_revalidation_without_identity_reset() {
    let db = Database::new();
    let clock = TestClock::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let mut service = open(&db.path(), Arc::clone(&provider), clock.clone(), None);
    let alice = enroll(&mut service, &provider, "alice");
    clock.advance(2 * DAY);
    assert_eq!(
        service.status(&alice.subject).unwrap().status,
        IdentityStatus::RevalidationRequired
    );
    assert_eq!(
        service.validate_epoch(&alice.subject, 1).unwrap_err(),
        Error::Expired
    );
    let again = enroll(&mut service, &provider, "alice");
    assert_eq!(again.subject, alice.subject);
    assert_eq!(
        service.status(&alice.subject).unwrap().status,
        IdentityStatus::RevalidationRequired
    );
}

#[test]
fn a_required_age_is_not_inferred_from_missing_or_negative_evidence() {
    let db = Database::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let clock = TestClock::new();
    let mut service = open(
        &db.path(),
        Arc::clone(&provider),
        clock.clone(),
        Some(AgeThreshold::Eighteen),
    );
    for adult in [None, Some(false)] {
        let result = attempt_for(
            &mut service,
            &provider,
            IdentityFlow::Enrollment,
            Scenario::person("alice", adult),
        );
        assert_eq!(result.unwrap_err(), Error::AgeRequired);
    }
    assert_eq!(db.humans(), 0);
    let alice = attempt_for(
        &mut service,
        &provider,
        IdentityFlow::Enrollment,
        Scenario::person("alice", Some(true)),
    )
    .unwrap();
    assert_eq!(
        service.status(&alice.subject).unwrap().age_at_least,
        Some(AgeThreshold::Eighteen)
    );
    clock.advance(2 * DAY);
    let status = service.status(&alice.subject).unwrap();
    assert_eq!(status.age_at_least, None);
    assert_eq!(status.status, IdentityStatus::RevalidationRequired);
}

#[test]
fn production_rejects_mock_provider_before_database_creation() {
    let db = Database::new();
    let mut config = Config::development();
    config.environment = Environment::Production;
    let result = Service::open(
        db.path(),
        config,
        Arc::new(MockIdentityProvider::default()),
        LookupKey::from_bytes(&[7; 32]).unwrap(),
        TestClock::new(),
    );
    assert!(matches!(result, Err(Error::MockInProduction)));
    assert!(!db.path().exists());
}

#[cfg(unix)]
#[test]
fn sqlite_identity_file_is_private_and_rejects_broader_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let db = Database::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let clock = TestClock::new();
    let service = open(&db.path(), Arc::clone(&provider), clock.clone(), None);
    let metadata = fs::metadata(db.path()).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o077, 0);
    drop(service);

    fs::set_permissions(db.path(), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        Service::open(
            db.path(),
            Config::development(),
            provider,
            LookupKey::from_bytes(&[7; 32]).unwrap(),
            clock
        ),
        Err(Error::InvalidConfiguration)
    ));
}

// Deliberately misbehaving trusted adapter: test the application's defense in depth.
struct IncorrectAdapter {
    inner: MockIdentityProvider,
    mutation: Mutation,
}
#[derive(Clone, Copy)]
enum Mutation {
    AdvertiseProduction,
    WrongContext,
    WrongPolicy,
    ExpiredEvidence,
    FutureVerification,
    ExpiredAge,
    ShortAge,
    SameDayAge,
}
impl IdentityProvider for IncorrectAdapter {
    fn descriptor(&self) -> ProviderDescriptor {
        let mut descriptor = self.inner.descriptor();
        if matches!(self.mutation, Mutation::AdvertiseProduction) {
            descriptor.evidence_class = EvidenceClass::Production;
        }
        descriptor
    }
    fn verify(
        &self,
        context: &VerificationContext,
        evidence: &Presentation,
        now: u64,
    ) -> Result<VerificationOutcome, ProviderError> {
        let mut outcome = self.inner.verify(context, evidence, now)?;
        if let VerificationOutcome::Established(ref mut proof) = outcome {
            match self.mutation {
                Mutation::AdvertiseProduction => (), // Actual evidence remains development-only.
                Mutation::WrongContext => proof.context.nonce = "wrong".into(),
                Mutation::WrongPolicy => proof.policy_version = "wrong".into(),
                Mutation::ExpiredEvidence => proof.valid_until = now,
                Mutation::FutureVerification => proof.verified_at = now + 1,
                Mutation::ExpiredAge => proof.age.as_mut().unwrap().valid_until = now,
                Mutation::ShortAge => {
                    proof.valid_until = now + 3 * DAY;
                    proof.age.as_mut().unwrap().valid_until = now + 2 * DAY;
                }
                Mutation::SameDayAge => proof.age.as_mut().unwrap().valid_until = now + 1200,
            }
        }
        Ok(outcome)
    }
}

#[test]
fn age_evidence_expiring_today_counts_as_expired() {
    let provider = Arc::new(IncorrectAdapter {
        inner: MockIdentityProvider::default(),
        mutation: Mutation::SameDayAge,
    });
    let scenario = || Scenario::aged("sixteen", Some(AgeThreshold::Sixteen));

    let required = Database::new();
    let mut service = open(
        &required.path(),
        Arc::clone(&provider),
        TestClock::new(),
        Some(AgeThreshold::Sixteen),
    );
    let context = service
        .begin_for_client(&idp(), IdentityFlow::Enrollment)
        .unwrap();
    let evidence = provider.inner.issue(&context, scenario()).unwrap();
    assert_eq!(
        service
            .complete(&context.challenge_id, &evidence)
            .unwrap_err(),
        Error::AgeRequired
    );
    assert_eq!(required.humans(), 0);

    let optional = Database::new();
    let mut service = open(
        &optional.path(),
        Arc::clone(&provider),
        TestClock::new(),
        None,
    );
    let context = service.begin(IdentityFlow::Enrollment).unwrap();
    let evidence = provider.inner.issue(&context, scenario()).unwrap();
    let completion = service.complete(&context.challenge_id, &evidence).unwrap();
    let status = service.status(&completion.subject).unwrap();
    assert_eq!(status.age_at_least, None);
    assert_eq!(status.age_valid_until, None);
}

#[test]
fn age_evidence_expiry_blocks_access_before_identity_evidence_expires() {
    let db = Database::new();
    let clock = TestClock::new();
    let provider = Arc::new(IncorrectAdapter {
        inner: MockIdentityProvider::default(),
        mutation: Mutation::ShortAge,
    });
    let mut service = open(
        &db.path(),
        Arc::clone(&provider),
        clock.clone(),
        Some(AgeThreshold::Sixteen),
    );
    let context = service
        .begin_for_client(&idp(), IdentityFlow::Enrollment)
        .unwrap();
    let evidence = provider
        .inner
        .issue(
            &context,
            Scenario::aged("sixteen", Some(AgeThreshold::Sixteen)),
        )
        .unwrap();
    let completion = service.complete(&context.challenge_id, &evidence).unwrap();
    let client_subject = service.client_subject(&idp(), &completion.subject).unwrap();
    let current = service.status_for_client(&idp(), &client_subject).unwrap();
    // 1_000_000 + 2 days, rounded down to the UTC day.
    assert_eq!(current.age_valid_until, Some(13 * DAY));
    assert_eq!(current.status, IdentityStatus::Valid);
    clock.advance(13 * DAY - 1_000_000);
    assert_eq!(
        service
            .status_for_client(&idp(), &client_subject)
            .unwrap()
            .status,
        IdentityStatus::RevalidationRequired
    );
    assert_eq!(db.humans(), 1);
}

#[test]
fn core_checks_adapter_output_instead_of_trusting_a_success_flag() {
    for (mutation, expected) in [
        (Mutation::AdvertiseProduction, Error::MockInProduction),
        (Mutation::WrongContext, Error::InvalidEvidence),
        (Mutation::WrongPolicy, Error::InvalidEvidence),
        (Mutation::ExpiredEvidence, Error::Expired),
        (Mutation::FutureVerification, Error::InvalidEvidence),
        (Mutation::ExpiredAge, Error::InvalidEvidence),
    ] {
        let db = Database::new();
        let provider = Arc::new(IncorrectAdapter {
            inner: MockIdentityProvider::default(),
            mutation,
        });
        let mut config = Config::development();
        if matches!(mutation, Mutation::AdvertiseProduction) {
            config.environment = Environment::Production;
        }
        let mut service = Service::open(
            db.path(),
            config,
            Arc::clone(&provider),
            LookupKey::from_bytes(&[7; 32]).unwrap(),
            TestClock::new(),
        )
        .unwrap();
        service
            .register_client(
                ClientRegistration::new(idp(), "idp.network", Some(AgeThreshold::Eighteen))
                    .unwrap(),
            )
            .unwrap();
        let context = service
            .begin_for_client(&idp(), IdentityFlow::Enrollment)
            .unwrap();
        let proof = provider
            .inner
            .issue(&context, Scenario::person("alice", Some(true)))
            .unwrap();
        assert_eq!(
            service.complete(&context.challenge_id, &proof).unwrap_err(),
            expected
        );
        assert_eq!(db.humans(), 0);
    }
}

#[test]
fn database_refuses_silent_key_policy_audience_and_environment_changes() {
    let db = Database::new();
    let clock = TestClock::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let mut service = open(&db.path(), Arc::clone(&provider), clock.clone(), None);
    let alice = enroll(&mut service, &provider, "alice");
    drop(service);
    let result = Service::open(
        db.path(),
        Config::development(),
        Arc::clone(&provider),
        LookupKey::from_bytes(&[8; 32]).unwrap(),
        clock.clone(),
    );
    assert!(matches!(result, Err(Error::ConfigurationMismatch)));
    let mut config = Config::development();
    config.provider_audience = "another-audience".into();
    assert!(matches!(
        Service::open(
            db.path(),
            config,
            Arc::clone(&provider),
            LookupKey::from_bytes(&[7; 32]).unwrap(),
            clock.clone()
        ),
        Err(Error::ConfigurationMismatch)
    ));
    let mut config = Config::development();
    config.environment = Environment::Production;
    let production_adapter = Arc::new(IncorrectAdapter {
        inner: MockIdentityProvider::default(),
        mutation: Mutation::AdvertiseProduction,
    });
    assert!(matches!(
        Service::open(
            db.path(),
            config,
            production_adapter,
            LookupKey::from_bytes(&[7; 32]).unwrap(),
            clock.clone()
        ),
        Err(Error::ConfigurationMismatch)
    ));
    let service = open(&db.path(), provider, clock, None);
    assert_eq!(
        service.status(&alice.subject).unwrap().authentication_epoch,
        1
    );
}

struct BlockingProvider {
    inner: Arc<MockIdentityProvider>,
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}
impl IdentityProvider for BlockingProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        self.inner.descriptor()
    }
    fn verify(
        &self,
        context: &VerificationContext,
        evidence: &Presentation,
        now: u64,
    ) -> Result<VerificationOutcome, ProviderError> {
        if context.purpose == Purpose::Recovery {
            self.entered.wait();
            self.release.wait();
        }
        self.inner.verify(context, evidence, now)
    }
}

#[test]
fn recovery_in_flight_cannot_undo_a_later_revocation() {
    let db = Database::new();
    let clock = TestClock::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let mut operator = open(&db.path(), Arc::clone(&provider), clock.clone(), None);
    let alice = enroll(&mut operator, &provider, "alice");
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let blocking = Arc::new(BlockingProvider {
        inner: Arc::clone(&provider),
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    });
    let mut recovery = open(&db.path(), blocking, clock, None);
    let context = recovery
        .begin(IdentityFlow::Recovery {
            subject: alice.subject.clone(),
        })
        .unwrap();
    let proof = provider
        .issue(&context, Scenario::person("alice", None))
        .unwrap();
    let handle = thread::spawn(move || recovery.complete(&context.challenge_id, &proof));
    entered.wait();
    operator.revoke(&alice.subject).unwrap();
    release.wait();
    assert_eq!(handle.join().unwrap().unwrap_err(), Error::EpochMismatch);
    assert_eq!(
        operator.status(&alice.subject).unwrap().status,
        IdentityStatus::Revoked
    );
}

#[test]
fn private_references_are_hmac_lookups_not_stored_attributes() {
    let db = Database::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let mut service = open(&db.path(), Arc::clone(&provider), TestClock::new(), None);
    let marker = "PRIVATE-CIVIL-REFERENCE-NEVER-PERSIST";
    enroll(&mut service, &provider, marker);
    drop(service);
    for entry in fs::read_dir(&db.directory).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !bytes
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        );
    }
}

#[test]
fn bounded_inputs_and_debug_do_not_leak_identifiers() {
    assert!(Presentation::new(Vec::new()).is_err());
    assert!(Presentation::new(vec![0; wohp_api::MAX_PRESENTATION_BYTES + 1]).is_err());
    let presentation = Presentation::new(b"sensitive-presentation".to_vec()).unwrap();
    assert!(!format!("{presentation:?}").contains("sensitive-presentation"));
    let person = wohp_api::CanonicalPerson::new("namespace", "secret-person").unwrap();
    assert!(!format!("{person:?}").contains("secret-person"));
    assert!(Subject::parse(&"A".repeat(42)).is_err());
    assert!(Subject::parse(&format!("{}B", "A".repeat(42))).is_err());
}

#[test]
fn no_relying_party_is_registered_implicitly() {
    let db = Database::new();
    let clock = TestClock::new();
    let provider = Arc::new(MockIdentityProvider::default());
    let mut service = open(&db.path(), Arc::clone(&provider), clock, None);
    let profile = enroll(&mut service, &provider, "canonical-alice").subject;
    // Only the client registered by the test helper exists.
    let unregistered = ClientId::parse("unregistered-client").unwrap();
    assert_eq!(
        service.client_subject(&unregistered, &profile).unwrap_err(),
        Error::UnknownClient
    );
    assert_eq!(
        service.client_registration(&unregistered).unwrap_err(),
        Error::UnknownClient
    );
}
