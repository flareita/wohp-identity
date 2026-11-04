#![forbid(unsafe_code)]

use serde_json::{Value, json};
use wohp_api::{
    IdentityProvider, Presentation, ProviderError, Purpose, VerificationContext,
    VerificationOutcome,
};
use wohp_eudi::{
    EudiVerifierProvider, PID_DOCTYPE, PID_VCT, fake::FakeVerifier, mdoc_presentation,
    sd_jwt_presentation,
};

const NOW: u64 = 1_792_800_000;
const AUDIENCE: &str = "x509_hash:test-verifier";

fn context(nonce: &str) -> VerificationContext {
    VerificationContext {
        challenge_id: format!("challenge-{nonce}"),
        nonce: nonce.into(),
        audience: AUDIENCE.into(),
        purpose: Purpose::Enrollment,
        issued_at: NOW - 5,
        expires_at: NOW + 295,
    }
}

fn pid(extra: Value) -> Value {
    let mut claims = json!({"vct": PID_VCT, "exp": NOW + 100_000});
    claims
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    claims
}

fn provider(verifier: &FakeVerifier, bearer: Option<&str>) -> EudiVerifierProvider {
    EudiVerifierProvider::new(verifier.origin(), bearer, 3600).unwrap()
}

fn presentation(token: &str) -> Presentation {
    sd_jwt_presentation(token).unwrap()
}

#[test]
fn nonce_audience_and_bearer_are_forwarded_for_every_challenge() {
    let verifier = FakeVerifier::start();
    let claims = pid(json!({"issuing_country": "IT", "personal_administrative_number": "1"}));
    verifier.issue("token-one", &claims, "nonce-one", AUDIENCE);
    verifier.issue("token-two", &claims, "nonce-two", AUDIENCE);
    let provider = provider(&verifier, Some("verifier-secret"));

    for (token, nonce) in [("token-one", "nonce-one"), ("token-two", "nonce-two")] {
        assert!(matches!(
            provider
                .verify(&context(nonce), &presentation(token), NOW)
                .unwrap(),
            VerificationOutcome::Established(_)
        ));
    }
    let requests = verifier.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests
            .iter()
            .map(|r| r.nonce.as_str())
            .collect::<Vec<_>>(),
        ["nonce-one", "nonce-two"]
    );
    assert!(requests.iter().all(|r| r.audience == AUDIENCE));
    assert!(
        requests
            .iter()
            .all(|r| r.authorization.as_deref() == Some("Bearer verifier-secret"))
    );
}

#[test]
fn a_presentation_replayed_on_another_challenge_or_audience_is_rejected() {
    let verifier = FakeVerifier::start();
    let claims = pid(json!({"issuing_country": "IT", "personal_administrative_number": "1"}));
    verifier.issue("token", &claims, "nonce-one", AUDIENCE);
    let provider = provider(&verifier, None);

    assert_eq!(
        provider
            .verify(&context("nonce-two"), &presentation("token"), NOW)
            .unwrap_err(),
        ProviderError::InvalidEvidence
    );
    let mut other_audience = context("nonce-one");
    other_audience.audience = "x509_hash:another-verifier".into();
    assert_eq!(
        provider
            .verify(&other_audience, &presentation("token"), NOW)
            .unwrap_err(),
        ProviderError::InvalidEvidence
    );
    assert_eq!(
        provider
            .verify(&context("nonce-one"), &presentation("unknown-token"), NOW)
            .unwrap_err(),
        ProviderError::InvalidEvidence
    );
    assert!(
        provider
            .verify(&context("nonce-one"), &presentation("token"), NOW)
            .is_ok()
    );
}

#[test]
fn verifier_failures_are_unavailable_but_bad_credentials_are_invalid() {
    let verifier = FakeVerifier::start();
    verifier.issue(
        "wrong-vct",
        &json!({"vct": "urn:other", "exp": NOW + 100, "issuing_country": "IT",
            "personal_administrative_number": "1"}),
        "n",
        AUDIENCE,
    );
    verifier.issue(
        "expired",
        &pid(
            json!({"exp": NOW - 1, "issuing_country": "IT", "personal_administrative_number": "1"}),
        ),
        "n",
        AUDIENCE,
    );
    verifier.issue(
        "missing",
        &pid(json!({"issuing_country": "IT"})),
        "n",
        AUDIENCE,
    );
    let provider = provider(&verifier, None);
    for token in ["wrong-vct", "expired"] {
        assert_eq!(
            provider
                .verify(&context("n"), &presentation(token), NOW)
                .unwrap_err(),
            ProviderError::InvalidEvidence,
            "{token}"
        );
    }
    // 200 with too few claims is not an error of the verifier: nobody is established.
    assert!(matches!(
        provider
            .verify(&context("n"), &presentation("missing"), NOW)
            .unwrap(),
        VerificationOutcome::Ambiguous
    ));

    for status in [500, 502, 503, 401, 404] {
        verifier.force_status(Some(status));
        assert_eq!(
            provider
                .verify(&context("n"), &presentation("missing"), NOW)
                .unwrap_err(),
            ProviderError::Unavailable,
            "{status}"
        );
    }
    verifier.force_status(None);

    let unreachable = {
        let gone = FakeVerifier::start();
        let origin = gone.origin().to_owned();
        drop(gone);
        EudiVerifierProvider::new(&origin, None, 3600).unwrap()
    };
    assert_eq!(
        unreachable
            .verify(&context("n"), &presentation("x"), NOW)
            .unwrap_err(),
        ProviderError::Unavailable
    );
}

#[test]
fn mdoc_is_excluded_by_default_and_malformed_envelopes_never_reach_the_verifier() {
    let verifier = FakeVerifier::start();
    let provider = provider(&verifier, None);
    for raw in [
        &br#"{"format":"mso_mdoc","token":"abc"}"#[..],
        br#"{"format":"dc+sd-jwt"}"#,
        b"garbage",
    ] {
        let presentation = Presentation::new(raw.to_vec()).unwrap();
        assert_eq!(
            provider
                .verify(&context("n"), &presentation, NOW)
                .unwrap_err(),
            ProviderError::InvalidEvidence
        );
    }
    assert!(verifier.requests().is_empty());
}

fn documents() -> Value {
    json!([{"docType": PID_DOCTYPE, "attributes": {PID_DOCTYPE: {
        "family_name": "Rossi", "given_name": "Anna", "issuing_country": "IT",
        "administrative_number": "PAN-1", "birth_date": "1990-01-01"
    }}}])
}

#[test]
fn unbound_mdoc_needs_an_explicit_opt_in_and_a_different_policy() {
    let verifier = FakeVerifier::start();
    verifier.issue_mdoc("device-response", &documents());
    let strict = provider(&verifier, None);
    assert_eq!(
        strict
            .verify(
                &context("n"),
                &mdoc_presentation("device-response").unwrap(),
                NOW
            )
            .unwrap_err(),
        ProviderError::InvalidEvidence
    );
    assert!(verifier.requests().is_empty());

    let relaxed = provider(&verifier, Some("secret")).allow_unbound_mdoc(true);
    assert_ne!(relaxed.descriptor(), strict.descriptor());
    let established = relaxed
        .verify(
            &context("n"),
            &mdoc_presentation("device-response").unwrap(),
            NOW,
        )
        .unwrap();
    let VerificationOutcome::Established(person) = established else {
        panic!("expected an established person");
    };
    assert_eq!(person.person.reference(), "IT|PAN-1");
    assert_eq!(person.policy_version, relaxed.descriptor().policy_version);
    let requests = verifier.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0]
            .path
            .ends_with("/utilities/validations/msoMdoc/deviceResponse")
    );
    assert_eq!(requests[0].token, "device-response");
    assert_eq!(requests[0].authorization.as_deref(), Some("Bearer secret"));
    assert_eq!(
        relaxed
            .verify(&context("n"), &mdoc_presentation("unknown").unwrap(), NOW)
            .unwrap_err(),
        ProviderError::InvalidEvidence
    );
}
