//! Adapter from an EUDI Verifier Endpoint to the WOHP `IdentityProvider` port.
//!
//! HTTP and JSON types stay inside this crate. The evidence is a sandbox
//! development fixture (`EvidenceClass::DevelopmentOnly`): the public test
//! verifier does not restrict issuers and PID values are chosen by the tester,
//! so the matching rule below exercises deduplication, concurrency, ambiguity
//! and recovery. It does NOT identify real persons.
//!
//! SD-JWT VC presentations are validated by the verifier against the challenge
//! nonce and audience. The mdoc validation endpoint takes neither a nonce nor a
//! session transcript, so mdoc is EXCLUDED unless the operator explicitly opts in
//! with `allow_unbound_mdoc`. The opt-in is part of the policy version stored in
//! the database, so it cannot be flipped silently. The presentation never passes
//! through the browser: the caller fetches it from the verifier transaction it
//! created with the challenge nonce.
//!
//! `EudiVerifierProvider` uses `reqwest::blocking`: build it, and drop it, outside
//! an asynchronous runtime context, and call `verify` from a blocking thread.
#![forbid(unsafe_code)]

#[cfg(feature = "fake-verifier")]
pub mod fake;

use reqwest::{Url, blocking::Client, redirect::Policy};
use serde_json::{Value, json};
use std::{fmt, io::Read, time::Duration};
use unicode_normalization::{UnicodeNormalization, char::is_combining_mark};
use wohp_api::{
    AgeEvidence, AgeThreshold, CanonicalPerson, EvidenceClass, IdentityProvider, InvalidInput,
    MAX_PRESENTATION_BYTES, Presentation, ProviderDescriptor, ProviderError, Timestamp,
    VerificationContext, VerificationOutcome, VerifiedPerson,
};

pub const INTEGRATION_ID: &str = "eudi-sandbox-verifier";
/// Version 2: attribute matching follows IT-Wallet 11.2.3 (place of birth and
/// normalisation). A database created under version 1 refuses to reopen.
pub const POLICY_VERSION: &str = "sandbox-eudi-2";
/// Policy version when mdoc without nonce binding has been explicitly allowed.
pub const POLICY_VERSION_UNBOUND_MDOC: &str = "sandbox-eudi-2+mdoc-unbound";
pub const SD_JWT_FORMAT: &str = "dc+sd-jwt";
pub const MDOC_FORMAT: &str = "mso_mdoc";
pub const PID_VCT: &str = "urn:eudi:pid:1";
pub const PID_DOCTYPE: &str = "eu.europa.ec.eudi.pid.1";
/// Matching namespaces are labelled `sandbox`: they are not person-level keys.
pub const NAMESPACE_PAN: &str = "eudi-sandbox.pan.v1";
pub const NAMESPACE_ATTRS: &str = "eudi-sandbox.attrs.v2";
/// Sandbox validity window: the sandbox cannot revalidate a presentation.
pub const DEFAULT_WINDOW_SECONDS: u64 = 30 * 24 * 60 * 60;

const MAX_WINDOW_SECONDS: u64 = 90 * 24 * 60 * 60;
const MAX_RESPONSE_BYTES: u64 = 65_536;
const MAX_TOKEN_BYTES: usize = MAX_PRESENTATION_BYTES - 256;
const SECONDS_PER_DAY: u64 = 86_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidConfiguration;

impl fmt::Display for InvalidConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid EUDI verifier configuration")
    }
}
impl std::error::Error for InvalidConfiguration {}

/// Wraps a verifier-validated SD-JWT VC into the opaque `Presentation` bytes
/// that `verify` expects. The token is never logged.
pub fn sd_jwt_presentation(token: &str) -> Result<Presentation, InvalidInput> {
    envelope(SD_JWT_FORMAT, token)
}

/// Same envelope for an mdoc device response. `verify` rejects it unless the
/// provider was built with `allow_unbound_mdoc`.
pub fn mdoc_presentation(token: &str) -> Result<Presentation, InvalidInput> {
    envelope(MDOC_FORMAT, token)
}

fn envelope(format: &str, token: &str) -> Result<Presentation, InvalidInput> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES || token.chars().any(char::is_control) {
        return Err(InvalidInput);
    }
    Presentation::new(
        json!({"format": format, "token": token})
            .to_string()
            .into_bytes(),
    )
}

pub struct EudiVerifierProvider {
    client: Client,
    base: Url,
    bearer: Option<String>,
    window_seconds: u64,
    unbound_mdoc: bool,
}

impl fmt::Debug for EudiVerifierProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EudiVerifierProvider")
            .field("integration_id", &INTEGRATION_ID)
            .finish_non_exhaustive()
    }
}

impl EudiVerifierProvider {
    /// `verifier_origin` must be an HTTPS origin or a loopback HTTP origin.
    pub fn new(
        verifier_origin: &str,
        bearer_token: Option<&str>,
        window_seconds: u64,
    ) -> Result<Self, InvalidConfiguration> {
        let base = Url::parse(verifier_origin).map_err(|_| InvalidConfiguration)?;
        let local_http =
            base.scheme() == "http" && matches!(base.host_str(), Some("127.0.0.1" | "localhost"));
        if base.username() != ""
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
            || !(base.scheme() == "https" || local_http)
            || window_seconds == 0
            || window_seconds > MAX_WINDOW_SECONDS
            || bearer_token
                .is_some_and(|t| t.is_empty() || t.len() > 4096 || t.chars().any(char::is_control))
        {
            return Err(InvalidConfiguration);
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(Policy::none())
            .build()
            .map_err(|_| InvalidConfiguration)?;
        Ok(Self {
            client,
            base,
            bearer: bearer_token.map(str::to_owned),
            window_seconds,
            unbound_mdoc: false,
        })
    }

    /// Accepts mdoc device responses although the validation endpoint does not
    /// bind them to the challenge nonce. Changes the descriptor policy version.
    #[must_use]
    pub fn allow_unbound_mdoc(mut self, allow: bool) -> Self {
        self.unbound_mdoc = allow;
        self
    }

    fn policy_version(&self) -> &'static str {
        if self.unbound_mdoc {
            POLICY_VERSION_UNBOUND_MDOC
        } else {
            POLICY_VERSION
        }
    }

    /// Asks the verifier to validate the SD-JWT VC against the challenge nonce
    /// and audience. The verifier's answer is the only source of claims.
    fn validate_sd_jwt(
        &self,
        token: &str,
        nonce: &str,
        audience: &str,
    ) -> Result<Value, ProviderError> {
        self.post_form(
            "utilities/validations/sdJwtVc",
            &[
                ("sd_jwt_vc", token),
                ("nonce", nonce),
                ("audience", audience),
            ],
        )
    }

    fn validate_mdoc(&self, token: &str) -> Result<Value, ProviderError> {
        self.post_form(
            "utilities/validations/msoMdoc/deviceResponse",
            &[("device_response", token)],
        )
    }

    fn post_form(&self, path: &str, pairs: &[(&str, &str)]) -> Result<Value, ProviderError> {
        let form = Url::parse_with_params("http://localhost/", pairs)
            .map_err(|_| ProviderError::InvalidEvidence)?;
        let url = self
            .base
            .join(path)
            .map_err(|_| ProviderError::Unavailable)?;
        let mut request = self
            .client
            .post(url)
            .header("accept", "application/json")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form.query().unwrap_or_default().to_owned());
        if let Some(bearer) = &self.bearer {
            request = request.bearer_auth(bearer);
        }
        let response = request.send().map_err(|_| ProviderError::Unavailable)?;
        match response.status().as_u16() {
            200 => (),
            400 | 422 => return Err(ProviderError::InvalidEvidence),
            _ => return Err(ProviderError::Unavailable),
        }
        let mut body = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| ProviderError::Unavailable)?;
        if body.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(ProviderError::Unavailable);
        }
        serde_json::from_slice(&body).map_err(|_| ProviderError::InvalidEvidence)
    }
}

impl IdentityProvider for EudiVerifierProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            integration_id: INTEGRATION_ID.into(),
            policy_version: self.policy_version().into(),
            evidence_class: EvidenceClass::DevelopmentOnly,
        }
    }

    fn verify(
        &self,
        context: &VerificationContext,
        presentation: &Presentation,
        now: Timestamp,
    ) -> Result<VerificationOutcome, ProviderError> {
        let (format, token) = decode_presentation(presentation)?;
        let claims = match format {
            Format::SdJwt => self.validate_sd_jwt(&token, &context.nonce, &context.audience)?,
            Format::Mdoc if self.unbound_mdoc => {
                let documents = self.validate_mdoc(&token)?;
                mdoc_claims(&documents, now, self.window_seconds)?
            }
            Format::Mdoc => return Err(ProviderError::InvalidEvidence),
        };
        established(
            &claims,
            context,
            now,
            self.window_seconds,
            self.policy_version(),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    SdJwt,
    Mdoc,
}

fn decode_presentation(presentation: &Presentation) -> Result<(Format, String), ProviderError> {
    let value: Value = serde_json::from_slice(presentation.as_bytes())
        .map_err(|_| ProviderError::InvalidEvidence)?;
    let format = match value.get("format").and_then(Value::as_str) {
        Some(SD_JWT_FORMAT) => Format::SdJwt,
        Some(MDOC_FORMAT) => Format::Mdoc,
        _ => return Err(ProviderError::InvalidEvidence),
    };
    let token = value
        .get("token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .ok_or(ProviderError::InvalidEvidence)?;
    Ok((format, token))
}

/// A string claim, trimmed. Absent and empty are the same; a non-string is invalid.
fn text_claim<'a>(claims: &'a Value, names: &[&str]) -> Result<Option<&'a str>, ProviderError> {
    for name in names {
        if let Some(value) = claims.get(*name) {
            let text = value.as_str().ok_or(ProviderError::InvalidEvidence)?.trim();
            return Ok((!text.is_empty()).then_some(text));
        }
    }
    Ok(None)
}

/// Maps verifier-validated claims to an established person, or to `Ambiguous`
/// when the claims cannot support the matching rule. No raw value is retained.
fn established(
    claims: &Value,
    context: &VerificationContext,
    now: Timestamp,
    window_seconds: u64,
    policy_version: &str,
) -> Result<VerificationOutcome, ProviderError> {
    if !claims.is_object() || claims.get("vct").and_then(Value::as_str) != Some(PID_VCT) {
        return Err(ProviderError::InvalidEvidence);
    }
    let expires = claims
        .get("exp")
        .and_then(Value::as_u64)
        .filter(|exp| *exp > now)
        .ok_or(ProviderError::InvalidEvidence)?;
    let country = text_claim(claims, &["issuing_country"])?;
    let number = text_claim(claims, &["personal_administrative_number"])?;
    let family = text_claim(claims, &["family_name"])?;
    let given = text_claim(claims, &["given_name"])?;
    let birthdate = text_claim(claims, &["birthdate", "birth_date"])?;
    let place = place_of_birth(claims)?;

    let born = match birthdate {
        Some(raw) => Some(parse_birthdate(raw).ok_or(ProviderError::InvalidEvidence)?),
        None => None,
    };
    let attributes = Attributes {
        family,
        given,
        birthdate,
        place: place.as_ref(),
    };
    let Some(person) = canonical_person(country, number, &attributes) else {
        return Ok(VerificationOutcome::Ambiguous);
    };

    let valid_until = expires.min(now.saturating_add(window_seconds));
    let age = match born {
        Some(born) => {
            let years = age_years(born, civil_from_days(now / SECONDS_PER_DAY))
                .ok_or(ProviderError::InvalidEvidence)?;
            age_threshold(years).map(|at_least| AgeEvidence {
                at_least,
                valid_until,
            })
        }
        None => None,
    };
    Ok(VerificationOutcome::Established(Box::new(VerifiedPerson {
        person,
        context: context.clone(),
        policy_version: policy_version.into(),
        evidence_class: EvidenceClass::DevelopmentOnly,
        verified_at: now,
        valid_until,
        age,
    })))
}

/// The attributes of the attribute-based binding, already trimmed.
struct Attributes<'a> {
    family: Option<&'a str>,
    given: Option<&'a str>,
    birthdate: Option<&'a str>,
    place: Option<&'a [String; 3]>,
}

/// Sandbox matching rule, aligned with IT-Wallet section 11.2.3:
///
/// - with `personal_administrative_number`: `issuing_country | number`,
///   trimmed only (the national identifier is the primary key);
/// - otherwise: `issuing_country | family | given | birthdate | place of
///   birth country | region | locality`, with names and place normalised
///   (case, whitespace, diacritics). The place of birth is required: a subset
///   without it is not a match.
///
/// It is still a sandbox rule, not a person-level identifier. A component
/// containing the separator would make the reference ambiguous.
fn canonical_person(
    country: Option<&str>,
    number: Option<&str>,
    attributes: &Attributes<'_>,
) -> Option<CanonicalPerson> {
    let (namespace, parts): (&str, Vec<String>) = match number {
        Some(number) => (NAMESPACE_PAN, vec![country?.into(), number.into()]),
        None => {
            let family = normalise(attributes.family?);
            let given = normalise(attributes.given?);
            if family.is_empty() || given.is_empty() {
                return None;
            }
            let place = attributes.place?;
            let mut parts = vec![country?.into(), family, given, attributes.birthdate?.into()];
            parts.extend(place.iter().map(|part| normalise(part)));
            (NAMESPACE_ATTRS, parts)
        }
    };
    if parts.iter().any(|part| part.contains('|')) {
        return None;
    }
    CanonicalPerson::new(namespace, &parts.join("|")).ok()
}

/// IT-Wallet normalisation of case, whitespace and diacritics: canonical
/// decomposition without combining marks, lower case, single spaces.
fn normalise(value: &str) -> String {
    let stripped: String = value.nfd().filter(|c| !is_combining_mark(*c)).collect();
    stripped
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// `place_of_birth` as `[country, region, locality]`, each trimmed and empty
/// when absent. An object of strings, or a plain string read as the locality.
/// `None` when absent or empty; any other shape is invalid evidence.
fn place_of_birth(claims: &Value) -> Result<Option<[String; 3]>, ProviderError> {
    let place = match claims.get("place_of_birth") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(locality)) => [String::new(), String::new(), locality.trim().into()],
        Some(Value::Object(members)) => {
            let mut place: [String; 3] = Default::default();
            for (slot, name) in place.iter_mut().zip(["country", "region", "locality"]) {
                match members.get(name) {
                    None | Some(Value::Null) => {}
                    Some(Value::String(text)) => *slot = text.trim().into(),
                    Some(_) => return Err(ProviderError::InvalidEvidence),
                }
            }
            place
        }
        Some(_) => return Err(ProviderError::InvalidEvidence),
    };
    Ok((!place.iter().all(String::is_empty)).then_some(place))
}

/// A claim value as the verifier renders it: a string, `{"value": ...}` or a
/// one-element array.
fn claim_string(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.get("value").and_then(Value::as_str))
        .or_else(|| {
            value
                .as_array()
                .and_then(|v| v.first())
                .and_then(Value::as_str)
        })
}

/// mdoc `birth_date` as `YYYY-MM-DD`: a string, a `YYYYMMDD` number, or an
/// epoch in days, seconds or milliseconds. Strict validation happens later.
fn birthdate_from_json(value: &Value) -> Option<String> {
    if let Some(text) = claim_string(value).filter(|text| text.len() == 10) {
        return Some(text.to_owned());
    }
    let number = value.as_i64()?;
    let (year, month, day) = if (19_000_101..=21_001_231).contains(&number) {
        (
            number / 10_000,
            (number / 100 % 100) as u32,
            (number % 100) as u32,
        )
    } else if (0..=100_000).contains(&number) {
        civil_from_days(number as u64)
    } else if (0..=4_000_000_000).contains(&number) {
        civil_from_days(number as u64 / SECONDS_PER_DAY)
    } else if (0..=4_000_000_000_000).contains(&number) {
        civil_from_days(number as u64 / (SECONDS_PER_DAY * 1000))
    } else {
        return None;
    };
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

/// Flattens the validated PID document of an mdoc device response into the claim
/// names used for SD-JWT, so one matching rule serves both formats. The mdoc has
/// no `exp` here: the sandbox window applies.
fn mdoc_claims(
    documents: &Value,
    now: Timestamp,
    window_seconds: u64,
) -> Result<Value, ProviderError> {
    let list = documents
        .as_array()
        .or_else(|| documents.get("documents").and_then(Value::as_array))
        .ok_or(ProviderError::InvalidEvidence)?;
    let attributes = list
        .iter()
        .find(|doc| doc.get("docType").and_then(Value::as_str) == Some(PID_DOCTYPE))
        .and_then(|doc| doc.get("attributes"))
        .and_then(|attrs| attrs.get(PID_DOCTYPE))
        .and_then(Value::as_object)
        .ok_or(ProviderError::InvalidEvidence)?;
    let mut claims = serde_json::Map::new();
    claims.insert("vct".into(), json!(PID_VCT));
    claims.insert("exp".into(), json!(now.saturating_add(window_seconds)));
    for (source, name) in [
        ("family_name", "family_name"),
        ("given_name", "given_name"),
        ("issuing_country", "issuing_country"),
        ("administrative_number", "personal_administrative_number"),
        (
            "personal_administrative_number",
            "personal_administrative_number",
        ),
    ] {
        if let Some(value) = attributes.get(source) {
            let text = claim_string(value).ok_or(ProviderError::InvalidEvidence)?;
            claims.insert(name.into(), json!(text));
        }
    }
    if let Some(value) = attributes.get("birth_date") {
        let text = birthdate_from_json(value).ok_or(ProviderError::InvalidEvidence)?;
        claims.insert("birthdate".into(), json!(text));
    }
    if let Some(value) = attributes.get("place_of_birth") {
        // A map of country, region and locality; the verifier may wrap it.
        let value = value.get("value").unwrap_or(value);
        if !(value.is_object() || value.is_string()) {
            return Err(ProviderError::InvalidEvidence);
        }
        claims.insert("place_of_birth".into(), value.clone());
    }
    Ok(Value::Object(claims))
}

type Date = (i64, u32, u32);

/// Days since 1970-01-01 to a proleptic Gregorian (year, month, day).
fn civil_from_days(days: u64) -> Date {
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        _ => 28,
    }
}

/// Strict `YYYY-MM-DD` with a real calendar check; years before 1900 are rejected.
fn parse_birthdate(value: &str) -> Option<Date> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = &value[range];
        part.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (year, month, day) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    let year = i64::from(year);
    ((1900..=9999).contains(&year)
        && (1..=12).contains(&month)
        && (1..=days_in_month(year, month)).contains(&day))
    .then_some((year, month, day))
}

/// Completed years on `today` (UTC, inclusive: the birthday itself counts).
/// `None` for a birth date in the future.
fn age_years(born: Date, today: Date) -> Option<u32> {
    if born > today {
        return None;
    }
    let years = today.0 - born.0 - i64::from((today.1, today.2) < (born.1, born.2));
    u32::try_from(years).ok()
}

fn age_threshold(years: u32) -> Option<AgeThreshold> {
    [
        AgeThreshold::Eighteen,
        AgeThreshold::Sixteen,
        AgeThreshold::Fourteen,
        AgeThreshold::Thirteen,
    ]
    .into_iter()
    .find(|threshold| years >= u32::from(threshold.years()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wohp_api::Purpose;

    const NOW: u64 = 1_792_800_000; // 2026-10-24T00:00:00Z

    fn context() -> VerificationContext {
        VerificationContext {
            challenge_id: "c".into(),
            nonce: "n".into(),
            audience: "a".into(),
            purpose: Purpose::Enrollment,
            issued_at: NOW - 10,
            expires_at: NOW + 290,
        }
    }

    fn claims(extra: Value) -> Value {
        let mut base = json!({"vct": PID_VCT, "exp": NOW + 100_000});
        base.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        base
    }

    fn outcome(claims: &Value) -> Result<VerificationOutcome, ProviderError> {
        established(
            claims,
            &context(),
            NOW,
            DEFAULT_WINDOW_SECONDS,
            POLICY_VERSION,
        )
    }

    fn person(claims: &Value) -> VerifiedPerson {
        match outcome(claims).unwrap() {
            VerificationOutcome::Established(person) => *person,
            _ => panic!("expected an established person"),
        }
    }

    #[test]
    fn civil_dates_round_trip_known_days() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(NOW / SECONDS_PER_DAY), (2026, 10, 24));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    }

    #[test]
    fn birthdates_are_strict_calendar_dates() {
        assert_eq!(parse_birthdate("2008-02-29"), Some((2008, 2, 29)));
        for bad in [
            "2007-02-29",
            "2026-02-30",
            "2026-13-01",
            "2026-00-10",
            "2008-1-01",
            "20081024",
            "2008/10/24",
            "1899-12-31",
            "٢٠٠٨-10-24",
            "2008-10-2a",
            "",
        ] {
            assert_eq!(parse_birthdate(bad), None, "{bad}");
        }
    }

    #[test]
    fn age_thresholds_are_inclusive_on_the_birthday_in_utc() {
        let today = (2026, 10, 24);
        for (born, expected) in [
            ((2008, 10, 24), Some(AgeThreshold::Eighteen)),
            ((2008, 10, 25), Some(AgeThreshold::Sixteen)),
            ((2010, 10, 24), Some(AgeThreshold::Sixteen)),
            ((2010, 10, 25), Some(AgeThreshold::Fourteen)),
            ((2012, 10, 24), Some(AgeThreshold::Fourteen)),
            ((2012, 10, 25), Some(AgeThreshold::Thirteen)),
            ((2013, 10, 24), Some(AgeThreshold::Thirteen)),
            ((2013, 10, 25), None),
        ] {
            assert_eq!(
                age_threshold(age_years(born, today).unwrap()),
                expected,
                "{born:?}"
            );
        }
        assert_eq!(age_years((2026, 10, 25), today), None);
        // A leap-day birthday counts from 1 March in a common year.
        assert_eq!(age_years((2008, 2, 29), (2026, 2, 28)), Some(17));
        assert_eq!(age_years((2008, 2, 29), (2026, 3, 1)), Some(18));
    }

    #[test]
    fn personal_administrative_number_wins_and_ignores_names_and_birthdate() {
        let one = person(&claims(json!({
            "issuing_country": "IT", "personal_administrative_number": " 123 ",
            "family_name": "Rossi", "given_name": "Anna", "birthdate": "1990-01-01"
        })));
        let two = person(&claims(json!({
            "issuing_country": "IT", "personal_administrative_number": "123",
            "family_name": "Other", "given_name": "Name", "birthdate": "1985-05-05"
        })));
        assert_eq!(one.person, two.person);
        assert_eq!(one.person.namespace(), NAMESPACE_PAN);
        assert_eq!(one.person.reference(), "IT|123");
        let other_country = person(&claims(json!({
            "issuing_country": "FR", "personal_administrative_number": "123"
        })));
        assert_ne!(one.person, other_country.person);
    }

    fn attrs(family: &str, given: &str, place: Value) -> Value {
        claims(json!({
            "issuing_country": "IT", "family_name": family, "given_name": given,
            "birthdate": "1990-01-01", "place_of_birth": place
        }))
    }

    #[test]
    fn attributes_include_the_place_of_birth_and_are_normalised() {
        let roma = json!({"country": "IT", "region": "Lazio", "locality": "Roma"});
        let anna = person(&attrs("Rossi", "Anna", roma.clone()));
        assert_eq!(anna.person.namespace(), NAMESPACE_ATTRS);
        assert_eq!(
            anna.person.reference(),
            "IT|rossi|anna|1990-01-01|it|lazio|roma"
        );
        // Case, whitespace and diacritics do not split a person.
        for (family, given, place) in [
            (" ROSSI ", "anna", roma.clone()),
            (
                "Rossi",
                "  Anna  ",
                json!({"country": "it", "region": " LAZIO", "locality": "Róma"}),
            ),
        ] {
            assert_eq!(person(&attrs(family, given, place)).person, anna.person);
        }
        let accents = person(&attrs("Nicolò  D'Àlessandro", "Zoë", roma.clone()));
        assert_eq!(
            accents.person.reference(),
            "IT|nicolo d'alessandro|zoe|1990-01-01|it|lazio|roma"
        );
        // Every attribute of the minimum set takes part in the match.
        for other in [
            attrs(
                "Rossi",
                "Anna",
                json!({"country": "IT", "region": "Lazio", "locality": "Milano"}),
            ),
            attrs(
                "Rossi",
                "Anna",
                json!({"country": "FR", "region": "Lazio", "locality": "Roma"}),
            ),
            attrs("Rossi", "Maria", roma.clone()),
        ] {
            assert_ne!(person(&other).person, anna.person);
        }
    }

    #[test]
    fn place_of_birth_accepts_partial_objects_and_a_plain_locality() {
        let only_locality = person(&attrs("Rossi", "Anna", json!({"locality": "Roma"})));
        assert_eq!(
            only_locality.person.reference(),
            "IT|rossi|anna|1990-01-01|||roma"
        );
        let string = person(&attrs("Rossi", "Anna", json!("Roma")));
        assert_eq!(string.person, only_locality.person);
        for bad in [json!(7), json!(["Roma"]), json!({"locality": 7})] {
            assert_eq!(
                outcome(&attrs("Rossi", "Anna", bad.clone())).unwrap_err(),
                ProviderError::InvalidEvidence,
                "{bad}"
            );
        }
    }

    #[test]
    fn insufficient_or_unsafe_claims_are_ambiguous_not_a_profile() {
        let ambiguous = |extra: Value| {
            assert!(matches!(
                outcome(&claims(extra)).unwrap(),
                VerificationOutcome::Ambiguous
            ));
        };
        ambiguous(json!({}));
        ambiguous(json!({"personal_administrative_number": "123"}));
        ambiguous(json!({"issuing_country": "IT", "family_name": "Rossi", "given_name": "Anna"}));
        // Names and birth date without the place of birth are not a match (CI_202).
        ambiguous(
            json!({"issuing_country": "IT", "family_name": "Rossi", "given_name": "Anna",
            "birthdate": "1990-01-01"}),
        );
        ambiguous(
            json!({"issuing_country": "IT", "family_name": "Rossi", "given_name": "Anna",
            "birthdate": "1990-01-01", "place_of_birth": {"country": " ", "locality": ""}}),
        );
        ambiguous(
            json!({"issuing_country": "IT", "family_name": "Rossi", "given_name": "Anna",
            "birthdate": "1990-01-01", "place_of_birth": {"locality": "Ro|ma"}}),
        );
        ambiguous(
            json!({"issuing_country": "IT", "family_name": "  ", "given_name": "Anna",
            "birthdate": "1990-01-01", "place_of_birth": {"locality": "Roma"}}),
        );
        ambiguous(json!({"issuing_country": "IT", "personal_administrative_number": "1|2"}));
        ambiguous(json!({"issuing_country": "I|T", "personal_administrative_number": "12"}));
    }

    #[test]
    fn invalid_credentials_are_rejected_before_matching() {
        let good = json!({"issuing_country": "IT", "personal_administrative_number": "1"});
        let reject = |claims: Value| {
            assert_eq!(
                outcome(&claims).unwrap_err(),
                ProviderError::InvalidEvidence
            );
        };
        reject(
            json!({"vct": "urn:other", "exp": NOW + 10, "issuing_country": "IT",
            "personal_administrative_number": "1"}),
        );
        reject(json!({"exp": NOW + 10}));
        reject(
            json!({"vct": PID_VCT, "issuing_country": "IT", "personal_administrative_number": "1"}),
        );
        reject(json!({"vct": PID_VCT, "exp": NOW, "issuing_country": "IT",
            "personal_administrative_number": "1"}));
        reject(
            json!({"vct": PID_VCT, "exp": NOW - 1, "issuing_country": "IT",
            "personal_administrative_number": "1"}),
        );
        let mut typed = claims(good.clone());
        typed["issuing_country"] = json!(7);
        reject(typed);
        let mut future = claims(good.clone());
        future["birthdate"] = json!("2999-01-01");
        reject(future);
        let mut malformed = claims(good);
        malformed["birthdate"] = json!("1990-02-30");
        reject(malformed);
        assert!(outcome(&json!([1])).is_err());
    }

    #[test]
    fn evidence_window_is_the_shorter_of_expiry_and_sandbox_window() {
        let base = json!({"issuing_country": "IT", "personal_administrative_number": "1",
            "birthdate": "1990-01-01"});
        let long = person(&claims(base.clone()));
        assert_eq!(long.valid_until, NOW + 100_000);
        assert_eq!(long.age.unwrap().valid_until, long.valid_until);
        assert_eq!(long.age.unwrap().at_least, AgeThreshold::Eighteen);
        let mut far = claims(base);
        far["exp"] = json!(NOW + 10 * DEFAULT_WINDOW_SECONDS);
        assert_eq!(person(&far).valid_until, NOW + DEFAULT_WINDOW_SECONDS);
        assert_eq!(person(&far).verified_at, NOW);
        assert_eq!(person(&far).evidence_class, EvidenceClass::DevelopmentOnly);
    }

    #[test]
    fn missing_birthdate_leaves_age_unknown_and_under_thirteen_has_no_threshold() {
        let pan = json!({"issuing_country": "IT", "personal_administrative_number": "1"});
        assert!(person(&claims(pan)).age.is_none());
        let child = json!({"issuing_country": "IT", "personal_administrative_number": "1",
            "birthdate": "2020-01-01"});
        assert!(person(&claims(child)).age.is_none());
    }

    #[test]
    fn presentation_envelope_carries_format_and_hides_the_token() {
        let presentation = sd_jwt_presentation("header.payload.signature~").unwrap();
        assert_eq!(
            decode_presentation(&presentation).unwrap(),
            (Format::SdJwt, "header.payload.signature~".to_owned())
        );
        assert_eq!(format!("{presentation:?}"), "Presentation([REDACTED])");
        assert_eq!(
            decode_presentation(&mdoc_presentation("abc").unwrap()).unwrap(),
            (Format::Mdoc, "abc".to_owned())
        );
        for raw in [
            &b"not json"[..],
            br#"{"format":"dc+sd-jwt"}"#,
            br#"{"format":"dc+sd-jwt","token":""}"#,
            br#"{"format":"other","token":"abc"}"#,
        ] {
            let bad = Presentation::new(raw.to_vec()).unwrap();
            assert_eq!(
                decode_presentation(&bad).unwrap_err(),
                ProviderError::InvalidEvidence
            );
        }
        assert!(sd_jwt_presentation("").is_err());
        assert!(sd_jwt_presentation("a\nb").is_err());
        assert!(sd_jwt_presentation(&"x".repeat(MAX_PRESENTATION_BYTES)).is_err());
    }

    #[test]
    fn mdoc_birth_date_supports_string_yyyymmdd_and_epoch_encodings() {
        for value in [
            json!("1972-09-11"),
            json!(19_720_911),
            json!(984),
            json!(85_017_600),
            json!(85_017_600_000_i64),
            json!({"value": "1972-09-11"}),
            json!(["1972-09-11"]),
        ] {
            assert_eq!(
                birthdate_from_json(&value).as_deref(),
                Some("1972-09-11"),
                "{value}"
            );
        }
        assert_eq!(birthdate_from_json(&json!("1972-9-11")), None);
        assert_eq!(birthdate_from_json(&json!(-1)), None);
    }

    #[test]
    fn mdoc_documents_are_flattened_to_the_sd_jwt_claim_names() {
        let documents = json!([
            {"docType": "org.iso.18013.5.1.mDL", "attributes": {"org.iso.18013.5.1": {"family_name": "Other"}}},
            {"docType": PID_DOCTYPE, "attributes": {PID_DOCTYPE: {
                "family_name": "Rossi", "given_name": "Anna", "issuing_country": "IT",
                "administrative_number": "PAN-1", "birth_date": 19_900_101, "nationality": "IT",
                "place_of_birth": {"value": {"country": "IT", "locality": "Roma"}}
            }}}
        ]);
        let claims = mdoc_claims(&documents, NOW, 100).unwrap();
        assert_eq!(claims["personal_administrative_number"], "PAN-1");
        assert_eq!(claims["birthdate"], "1990-01-01");
        assert_eq!(
            claims["place_of_birth"],
            json!({"country": "IT", "locality": "Roma"})
        );
        assert_eq!(claims["exp"], NOW + 100);
        assert!(claims.get("nationality").is_none());
        let person = match established(&claims, &context(), NOW, 100, POLICY_VERSION_UNBOUND_MDOC)
            .unwrap()
        {
            VerificationOutcome::Established(person) => *person,
            _ => panic!("expected an established person"),
        };
        assert_eq!(person.person.reference(), "IT|PAN-1");
        assert_eq!(person.policy_version, POLICY_VERSION_UNBOUND_MDOC);
        assert_eq!(person.valid_until, NOW + 100);
        for bad in [
            json!([]),
            json!({"documents": []}),
            json!("x"),
            json!([{"docType": PID_DOCTYPE, "attributes": {}}]),
            json!([{"docType": PID_DOCTYPE, "attributes": {PID_DOCTYPE: {"family_name": 7}}}]),
            json!([{"docType": PID_DOCTYPE, "attributes": {PID_DOCTYPE: {"place_of_birth": 7}}}]),
        ] {
            assert!(mdoc_claims(&bad, NOW, 100).is_err(), "{bad}");
        }
    }

    #[test]
    fn configuration_is_fail_closed() {
        assert!(EudiVerifierProvider::new("https://verifier.example/", Some("t"), 60).is_ok());
        assert!(EudiVerifierProvider::new("http://127.0.0.1:8080/", None, 60).is_ok());
        for (origin, window) in [
            ("http://verifier.example/", 60),
            ("https://u:p@verifier.example/", 60),
            ("https://verifier.example/path", 60),
            ("https://verifier.example/?q=1", 60),
            ("not a url", 60),
            ("https://verifier.example/", 0),
            ("https://verifier.example/", MAX_WINDOW_SECONDS + 1),
        ] {
            assert!(
                EudiVerifierProvider::new(origin, None, window).is_err(),
                "{origin}"
            );
        }
        assert!(EudiVerifierProvider::new("https://verifier.example/", Some(""), 60).is_err());
        let provider =
            EudiVerifierProvider::new("https://verifier.example/", Some("secret"), 60).unwrap();
        assert!(!format!("{provider:?}").contains("secret"));
        let descriptor = provider.descriptor();
        assert_eq!(descriptor.integration_id, INTEGRATION_ID);
        assert_eq!(descriptor.policy_version, POLICY_VERSION);
        assert_eq!(descriptor.evidence_class, EvidenceClass::DevelopmentOnly);
        // Allowing unbound mdoc is a different policy: the database refuses a silent flip.
        let mdoc = provider.allow_unbound_mdoc(true).descriptor();
        assert_eq!(mdoc.policy_version, POLICY_VERSION_UNBOUND_MDOC);
    }
}
