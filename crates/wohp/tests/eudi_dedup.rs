//! Sandbox deduplication through the real core and the EUDI adapter, against a
//! loopback fake verifier. Presentations are bound to their challenge nonce.
#![forbid(unsafe_code)]

use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use wohp::{Config, Environment, LookupKey, Service, SystemClock};
use wohp_api::{
    AgeThreshold, ClientId, ClientRegistration, Completion, CompletionKind, Error, IdentityFlow,
    IdentityService, IdentityStatus,
};
use wohp_eudi::{
    DEFAULT_WINDOW_SECONDS, EudiVerifierProvider, PID_VCT, fake::FakeVerifier, sd_jwt_presentation,
};

const AUDIENCE: &str = "x509_hash:test-verifier";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Database(PathBuf);
impl Database {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "wohp-eudi-test-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(directory)
    }
    fn path(&self) -> PathBuf {
        self.0.join("identity.sqlite3")
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
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Birthdate of a person who is `age` years old today, give or take a year.
fn born(age: u64) -> String {
    format!("{}-01-01", 1970 + now() / 31_556_952 - age)
}

/// The deployment configuration and the minimum age of the test client.
fn config(floor: Option<AgeThreshold>) -> (Config, Option<AgeThreshold>) {
    let mut config = Config::development();
    config.provider_audience = AUDIENCE.into();
    (config, floor)
}

fn open(
    path: &Path,
    verifier: &FakeVerifier,
    (config, floor): (Config, Option<AgeThreshold>),
) -> Result<Service<EudiVerifierProvider>, Error> {
    let provider = Arc::new(
        EudiVerifierProvider::new(verifier.origin(), None, DEFAULT_WINDOW_SECONDS).unwrap(),
    );
    let mut service = Service::open(
        path,
        config,
        provider,
        LookupKey::from_bytes(&[9; 32]).unwrap(),
        SystemClock,
    )?;
    service.register_client(
        ClientRegistration::new(ClientId::parse(IDP_CLIENT).unwrap(), "idp.network", floor)
            .unwrap(),
    )?;
    Ok(service)
}

/// The first-party identity provider client every test service registers.
const IDP_CLIENT: &str = "first-party-idp";

fn pid(extra: Value) -> Value {
    let mut claims = json!({"vct": PID_VCT, "exp": now() + 86_400});
    claims
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    claims
}

fn alice() -> Value {
    pid(
        json!({"issuing_country": "IT", "personal_administrative_number": "PAN-ALICE",
        "family_name": "Rossi", "given_name": "Anna", "birthdate": born(30)}),
    )
}

fn bob() -> Value {
    pid(
        json!({"issuing_country": "IT", "personal_administrative_number": "PAN-BOB",
        "family_name": "Bianchi", "given_name": "Bruno", "birthdate": born(40)}),
    )
}

/// One wallet round trip: begin, the verifier binds the token to this
/// challenge's nonce, the core completes with the resulting presentation.
fn present(
    service: &mut Service<EudiVerifierProvider>,
    verifier: &FakeVerifier,
    claims: &Value,
    flow: IdentityFlow,
) -> Result<Completion, Error> {
    // Through the registered client: its minimum age applies.
    let context = service.begin_for_client(&ClientId::parse(IDP_CLIENT).unwrap(), flow)?;
    let token = format!("token-{}", context.challenge_id);
    verifier.issue(&token, claims, &context.nonce, &context.audience);
    service.complete(&context.challenge_id, &sd_jwt_presentation(&token).unwrap())
}

fn enroll(
    service: &mut Service<EudiVerifierProvider>,
    verifier: &FakeVerifier,
    claims: &Value,
) -> Result<Completion, Error> {
    present(service, verifier, claims, IdentityFlow::Enrollment)
}

#[test]
fn the_same_person_resolves_to_the_same_profile_and_client_subject() {
    let db = Database::new();
    let verifier = FakeVerifier::start();
    let mut service = open(&db.path(), &verifier, config(Some(AgeThreshold::Sixteen))).unwrap();
    let first = enroll(&mut service, &verifier, &alice()).unwrap();
    assert_eq!(first.kind, CompletionKind::Created);
    assert_eq!(first.authentication_epoch, 1);

    // Another QR, same person, other attributes around the same PAN.
    let mut renamed = alice();
    renamed["family_name"] = json!("Verdi");
    let second = enroll(&mut service, &verifier, &renamed).unwrap();
    assert_eq!(second.kind, CompletionKind::ExistingRequiresAuthentication);
    assert_eq!(second.subject, first.subject);
    assert_eq!(db.humans(), 1);

    let bootstrap = ClientId::parse(IDP_CLIENT).unwrap();
    assert_eq!(
        service.client_subject(&bootstrap, &first.subject).unwrap(),
        service.client_subject(&bootstrap, &second.subject).unwrap()
    );
    let other = enroll(&mut service, &verifier, &bob()).unwrap();
    assert_eq!(other.kind, CompletionKind::Created);
    assert_ne!(other.subject, first.subject);
    assert_eq!(db.humans(), 2);

    // The match is persistent across a restart.
    drop(service);
    let mut restarted = open(&db.path(), &verifier, config(Some(AgeThreshold::Sixteen))).unwrap();
    let again = enroll(&mut restarted, &verifier, &alice()).unwrap();
    assert_eq!(again.subject, first.subject);
    assert_eq!(again.kind, CompletionKind::ExistingRequiresAuthentication);
    let status = restarted.status(&first.subject).unwrap();
    assert_eq!(status.status, IdentityStatus::Valid);
    assert_eq!(status.age_at_least, Some(AgeThreshold::Eighteen));
    assert!(status.age_valid_until.unwrap() <= now() + DEFAULT_WINDOW_SECONDS);
}

#[test]
fn attributes_without_a_number_deduplicate_too_and_never_collide_with_numbers() {
    let db = Database::new();
    let verifier = FakeVerifier::start();
    let mut service = open(&db.path(), &verifier, config(None)).unwrap();
    let attrs = pid(json!({"issuing_country": "IT", "family_name": "Rossi",
        "given_name": "Anna", "birthdate": born(30),
        "place_of_birth": {"country": "IT", "locality": "Roma"}}));
    let first = enroll(&mut service, &verifier, &attrs).unwrap();
    assert_eq!(first.kind, CompletionKind::Created);
    assert_eq!(
        enroll(&mut service, &verifier, &attrs).unwrap().subject,
        first.subject
    );
    // The same civil data with a number is a different namespace: not silently merged.
    let numbered = pid(
        json!({"issuing_country": "IT", "personal_administrative_number": "1",
        "family_name": "Rossi", "given_name": "Anna", "birthdate": born(30)}),
    );
    assert_ne!(
        enroll(&mut service, &verifier, &numbered).unwrap().subject,
        first.subject
    );
    assert_eq!(db.humans(), 2);
}

#[test]
fn concurrent_enrollments_of_one_person_create_one_profile() {
    let db = Database::new();
    let verifier = Arc::new(FakeVerifier::start());
    drop(open(&db.path(), &verifier, config(None)).unwrap());
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (path, verifier, barrier) =
                (db.path(), Arc::clone(&verifier), Arc::clone(&barrier));
            thread::spawn(move || {
                let mut service = open(&path, &verifier, config(None)).unwrap();
                let context = service.begin(IdentityFlow::Enrollment).unwrap();
                let token = format!("token-{}", context.challenge_id);
                verifier.issue(&token, &alice(), &context.nonce, &context.audience);
                barrier.wait();
                service.complete(&context.challenge_id, &sd_jwt_presentation(&token).unwrap())
            })
        })
        .collect();
    let results: Vec<Completion> = handles
        .into_iter()
        .map(|h| h.join().unwrap().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|c| c.kind == CompletionKind::Created)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|c| c.kind == CompletionKind::ExistingRequiresAuthentication)
            .count(),
        7
    );
    assert!(results.iter().all(|c| c.subject == results[0].subject));
    assert_eq!(db.humans(), 1);
}

#[test]
fn insufficient_claims_are_ambiguous_and_leave_no_profile() {
    let db = Database::new();
    let verifier = FakeVerifier::start();
    let mut service = open(&db.path(), &verifier, config(None)).unwrap();
    for claims in [
        pid(json!({"issuing_country": "IT"})),
        pid(json!({"personal_administrative_number": "1"})),
        pid(json!({"issuing_country": "IT", "family_name": "Rossi", "given_name": "Anna"})),
        // Without the place of birth the attribute binding is not a match.
        pid(
            json!({"issuing_country": "IT", "family_name": "Rossi", "given_name": "Anna",
            "birthdate": born(30)}),
        ),
    ] {
        assert_eq!(
            enroll(&mut service, &verifier, &claims).unwrap_err(),
            Error::AmbiguousIdentity
        );
    }
    assert_eq!(db.humans(), 0);
}

#[test]
fn verifier_outage_burns_the_challenge_and_creates_nothing() {
    let db = Database::new();
    let verifier = FakeVerifier::start();
    let mut service = open(&db.path(), &verifier, config(None)).unwrap();
    verifier.force_status(Some(503));
    let context = service.begin(IdentityFlow::Enrollment).unwrap();
    let token = format!("token-{}", context.challenge_id);
    verifier.issue(&token, &alice(), &context.nonce, &context.audience);
    let presentation = sd_jwt_presentation(&token).unwrap();
    assert_eq!(
        service
            .complete(&context.challenge_id, &presentation)
            .unwrap_err(),
        Error::ProviderUnavailable
    );
    // No retry on the same challenge, even after the verifier is back.
    verifier.force_status(None);
    assert_eq!(
        service
            .complete(&context.challenge_id, &presentation)
            .unwrap_err(),
        Error::ChallengeRejected
    );
    assert_eq!(db.humans(), 0);
    assert_eq!(
        enroll(&mut service, &verifier, &alice()).unwrap().kind,
        CompletionKind::Created
    );
}

#[test]
fn replayed_expired_wrong_type_and_underage_evidence_is_rejected() {
    let db = Database::new();
    let verifier = FakeVerifier::start();
    let mut service = open(&db.path(), &verifier, config(Some(AgeThreshold::Sixteen))).unwrap();

    // A presentation obtained for one challenge does not complete another.
    let first = service.begin(IdentityFlow::Enrollment).unwrap();
    let second = service.begin(IdentityFlow::Enrollment).unwrap();
    verifier.issue("replayed", &alice(), &first.nonce, &first.audience);
    assert_eq!(
        service
            .complete(
                &second.challenge_id,
                &sd_jwt_presentation("replayed").unwrap()
            )
            .unwrap_err(),
        Error::InvalidEvidence
    );

    let mut expired = alice();
    expired["exp"] = json!(now() - 1);
    assert_eq!(
        enroll(&mut service, &verifier, &expired).unwrap_err(),
        Error::InvalidEvidence
    );
    let mut wrong_type = alice();
    wrong_type["vct"] = json!("urn:example:other");
    assert_eq!(
        enroll(&mut service, &verifier, &wrong_type).unwrap_err(),
        Error::InvalidEvidence
    );

    for age in [14, 11] {
        let mut young = alice();
        young["birthdate"] = json!(born(age));
        assert_eq!(
            enroll(&mut service, &verifier, &young).unwrap_err(),
            Error::AgeRequired,
            "{age}"
        );
    }
    assert_eq!(db.humans(), 0);
    let mut teen = alice();
    teen["birthdate"] = json!(born(17));
    assert_eq!(
        enroll(&mut service, &verifier, &teen).unwrap().kind,
        CompletionKind::Created
    );
}

#[test]
fn production_and_silent_audience_changes_are_refused() {
    let db = Database::new();
    let verifier = FakeVerifier::start();
    let mut production = config(Some(AgeThreshold::Sixteen));
    production.0.environment = Environment::Production;
    assert_eq!(
        open(&db.path(), &verifier, production).err(),
        Some(Error::MockInProduction)
    );
    assert!(
        !db.path().exists(),
        "refused before the database is touched"
    );

    let mut service = open(&db.path(), &verifier, config(None)).unwrap();
    enroll(&mut service, &verifier, &alice()).unwrap();
    drop(service);
    let mut moved = config(None);
    moved.0.provider_audience = "x509_hash:replaced-certificate".into();
    assert_eq!(
        open(&db.path(), &verifier, moved).err(),
        Some(Error::ConfigurationMismatch)
    );
    assert_eq!(db.humans(), 1);
}

#[test]
fn recovery_through_the_wallet_keeps_the_subject_and_advances_the_epoch() {
    let db = Database::new();
    let verifier = FakeVerifier::start();
    let mut service = open(&db.path(), &verifier, config(None)).unwrap();
    let created = enroll(&mut service, &verifier, &alice()).unwrap();
    let bootstrap = ClientId::parse(IDP_CLIENT).unwrap();
    let client_subject = service
        .client_subject(&bootstrap, &created.subject)
        .unwrap();

    let profile = service
        .profile_for_client_subject(&bootstrap, &client_subject)
        .unwrap();
    let recovered = present(
        &mut service,
        &verifier,
        &alice(),
        IdentityFlow::Recovery { subject: profile },
    )
    .unwrap();
    assert_eq!(recovered.kind, CompletionKind::Recovered);
    assert_eq!(recovered.subject, created.subject);
    assert_eq!(recovered.authentication_epoch, 2);
    assert_eq!(
        service
            .status_for_client(&bootstrap, &client_subject)
            .unwrap()
            .authentication_epoch,
        2
    );

    // Another person cannot recover this profile.
    let profile = service
        .profile_for_client_subject(&bootstrap, &client_subject)
        .unwrap();
    assert_eq!(
        present(
            &mut service,
            &verifier,
            &bob(),
            IdentityFlow::Recovery { subject: profile }
        )
        .unwrap_err(),
        Error::SubjectMismatch
    );
    assert_eq!(db.humans(), 1);
}

#[test]
fn nothing_secret_reaches_debug_output_or_the_database() {
    let db = Database::new();
    let verifier = FakeVerifier::start();
    let mut service = open(&db.path(), &verifier, config(None)).unwrap();
    let context = service.begin(IdentityFlow::Enrollment).unwrap();
    let presentation = sd_jwt_presentation("secret-token-value").unwrap();
    assert!(!format!("{presentation:?}").contains("secret-token-value"));
    assert!(!format!("{context:?}").contains(&context.nonce));
    enroll(&mut service, &verifier, &alice()).unwrap();
    drop(service);
    let bytes = fs::read(db.path()).unwrap();
    for secret in ["PAN-ALICE", "Rossi", "Anna", &born(30)] {
        assert!(
            !bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "{secret} must not be stored"
        );
    }
}

#[test]
fn each_client_applies_its_own_minimum_age_to_the_same_people() {
    let db = Database::new();
    let verifier = FakeVerifier::start();
    // The test client deduplicates only: a child of 11 is enrolled.
    let mut service = open(&db.path(), &verifier, config(None)).unwrap();
    let mut child = alice();
    child["birthdate"] = json!(born(11));
    let enrolled = enroll(&mut service, &verifier, &child).unwrap();
    assert_eq!(enrolled.kind, CompletionKind::Created);
    assert_eq!(
        service.status(&enrolled.subject).unwrap().age_at_least,
        None
    );
    // A second attempt is the same person: one vote, one profile.
    assert_eq!(
        enroll(&mut service, &verifier, &child).unwrap().kind,
        CompletionKind::ExistingRequiresAuthentication
    );

    let social = ClientId::parse("social").unwrap();
    service
        .register_client(
            ClientRegistration::new(
                social.clone(),
                "social.network",
                Some(AgeThreshold::Fourteen),
            )
            .unwrap(),
        )
        .unwrap();
    let present_to = |service: &mut Service<EudiVerifierProvider>, claims: &Value| {
        let context = service
            .begin_for_client(&social, IdentityFlow::Enrollment)
            .unwrap();
        let token = format!("token-{}", context.challenge_id);
        verifier.issue(&token, claims, &context.nonce, &context.audience);
        service.complete(&context.challenge_id, &sd_jwt_presentation(&token).unwrap())
    };
    // Below the social client's minimum age: refused, nothing new stored.
    let mut thirteen = bob();
    thirteen["birthdate"] = json!(born(13));
    assert_eq!(
        present_to(&mut service, &thirteen).unwrap_err(),
        Error::AgeRequired
    );
    assert_eq!(db.humans(), 1);
    let mut fourteen = bob();
    fourteen["birthdate"] = json!(born(14));
    let teen = present_to(&mut service, &fourteen).unwrap();
    assert_eq!(teen.kind, CompletionKind::Created);
    assert_eq!(
        service.status(&teen.subject).unwrap().age_at_least,
        Some(AgeThreshold::Fourteen)
    );
    assert_eq!(db.humans(), 2);
}
