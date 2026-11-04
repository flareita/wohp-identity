//! Versioned, SDK-independent internal identity verification contract.
//!
//! This is a Rust source API, not a stable binary ABI or a public HTTP API.
//! Provider implementations are trusted security adapters, not user plugins.
#![forbid(unsafe_code)]

use std::fmt;

pub const API_VERSION: u16 = 1;
pub const MAX_PRESENTATION_BYTES: usize = 65_536;
pub const LOGIN_TTL_SECONDS: u64 = 300;

/// Seconds since the Unix epoch. Supplied by WOHP's trusted clock, not a client.
pub type Timestamp = u64;

/// Finite inclusive age thresholds. No birth date is part of this contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AgeThreshold {
    Thirteen = 13,
    /// Age of digital consent in Italy (GDPR art. 8, d.lgs. 101/2018).
    Fourteen = 14,
    Sixteen = 16,
    Eighteen = 18,
}

impl AgeThreshold {
    pub const fn years(self) -> u8 {
        self as u8
    }

    pub const fn from_years(years: u8) -> Option<Self> {
        match years {
            13 => Some(Self::Thirteen),
            14 => Some(Self::Fourteen),
            16 => Some(Self::Sixteen),
            18 => Some(Self::Eighteen),
            _ => None,
        }
    }
}

/// Positive, same-person age assertion from a trusted evidence adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgeEvidence {
    pub at_least: AgeThreshold,
    pub valid_until: Timestamp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvidenceClass {
    DevelopmentOnly,
    Production,
}

/// Identifies one configured verification + matching integration, not a SDK version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderDescriptor {
    pub integration_id: String,
    pub policy_version: String,
    pub evidence_class: EvidenceClass,
}

/// Private identifiers intentionally redact their Debug representation.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalPerson {
    namespace: String,
    reference: String,
}

impl CanonicalPerson {
    /// The adapter must establish person-level semantics and canonicalize
    /// equivalent national/wallet references BEFORE constructing this value.
    pub fn new(namespace: &str, reference: &str) -> Result<Self, InvalidInput> {
        if !valid_text(namespace, 128) || !valid_text(reference, 1024) {
            return Err(InvalidInput);
        }
        Ok(Self {
            namespace: namespace.into(),
            reference: reference.into(),
        })
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    pub fn reference(&self) -> &str {
        &self.reference
    }
}

impl fmt::Debug for CanonicalPerson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CanonicalPerson([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Presentation(Vec<u8>);

impl Presentation {
    pub fn new(bytes: Vec<u8>) -> Result<Self, InvalidInput> {
        if bytes.is_empty() || bytes.len() > MAX_PRESENTATION_BYTES {
            return Err(InvalidInput);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Presentation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Presentation([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Purpose {
    Enrollment,
    Recovery,
}

#[derive(Clone, PartialEq, Eq)]
pub struct VerificationContext {
    pub challenge_id: String,
    pub nonce: String,
    pub audience: String,
    pub purpose: Purpose,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
}

impl fmt::Debug for VerificationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerificationContext")
            .field("purpose", &self.purpose)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Construct ONLY after validating issuer, signature, holder binding, audience,
/// nonce, validity/status, and unambiguous person matching under the policy.
/// A serial number or simply "no match found" is not an established person.
#[derive(Clone)]
pub struct VerifiedPerson {
    pub person: CanonicalPerson,
    pub context: VerificationContext,
    pub policy_version: String,
    pub evidence_class: EvidenceClass,
    pub verified_at: Timestamp,
    pub valid_until: Timestamp,
    /// Highest established threshold; `None` when the evidence proves none
    /// (younger than 13, or no birth date).
    pub age: Option<AgeEvidence>,
}

impl fmt::Debug for VerifiedPerson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedPerson([REDACTED])")
    }
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum VerificationOutcome {
    Established(Box<VerifiedPerson>),
    Ambiguous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderError {
    InvalidEvidence,
    Unavailable,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidEvidence => "identity evidence could not be verified",
            Self::Unavailable => "identity provider unavailable",
        })
    }
}
impl std::error::Error for ProviderError {}

/// Synchronous port: no runtime, transport, EUDI, JSON or database types escape.
/// SDK errors must be mapped to these bounded categories without raw payloads.
pub trait IdentityProvider: Send + Sync {
    fn descriptor(&self) -> ProviderDescriptor;
    fn verify(
        &self,
        context: &VerificationContext,
        presentation: &Presentation,
        now: Timestamp,
    ) -> Result<VerificationOutcome, ProviderError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidInput;
impl fmt::Display for InvalidInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid or oversized input")
    }
}
impl std::error::Error for InvalidInput {}

pub fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

/// Registered relying-party identifier. This is not an OIDC library type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientId(String);

impl ClientId {
    pub fn parse(value: &str) -> Result<Self, InvalidInput> {
        if !valid_protocol_token(value, 128) {
            return Err(InvalidInput);
        }
        Ok(Self(value.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One closed-set relying party, its application scope and its own age
/// policy. WOHP deduplicates people for every client; the minimum age is the
/// client's: `None` means deduplication only, with no age requirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientRegistration {
    pub client_id: ClientId,
    pub application_scope: String,
    pub minimum_age: Option<AgeThreshold>,
}

impl ClientRegistration {
    pub fn new(
        client_id: ClientId,
        application_scope: &str,
        minimum_age: Option<AgeThreshold>,
    ) -> Result<Self, InvalidInput> {
        if !valid_protocol_token(application_scope, 128) {
            return Err(InvalidInput);
        }
        Ok(Self {
            client_id,
            application_scope: application_scope.into(),
            minimum_age,
        })
    }
}

/// What registering a client changed. The minimum age follows the operator's
/// configuration; a change is audited by the core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Registration {
    Created,
    Unchanged,
    MinimumAgeChanged {
        previous: Option<AgeThreshold>,
        current: Option<AgeThreshold>,
    },
}

fn valid_protocol_token(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Subject(String);

impl Subject {
    /// Canonical unpadded base64url encoding of exactly 32 bytes.
    pub fn parse(value: &str) -> Result<Self, InvalidInput> {
        if value.len() != 43
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || !b"AEIMQUYcgkosw048".contains(&value.as_bytes()[42])
        {
            return Err(InvalidInput);
        }
        Ok(Self(value.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Subject([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityStatus {
    Valid,
    RevalidationRequired,
    Revoked,
}

#[derive(Clone, Debug)]
pub enum IdentityFlow {
    Enrollment,
    Recovery { subject: Subject },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompletionKind {
    Created,
    ExistingRequiresAuthentication,
    Recovered,
}

#[derive(Clone, Debug)]
pub struct Completion {
    pub subject: Subject,
    pub kind: CompletionKind,
    pub authentication_epoch: u64,
    pub evidence_class: EvidenceClass,
}

/// Internal DTO, not an authentication grant, ID token or signed assertion.
#[derive(Clone, Debug)]
pub struct BindingStatus {
    pub status: IdentityStatus,
    pub policy_version: String,
    pub authentication_epoch: u64,
    /// Highest currently verified threshold, or unknown.
    pub age_at_least: Option<AgeThreshold>,
    pub age_valid_until: Option<Timestamp>,
    pub checked_at: Timestamp,
    pub valid_until: Timestamp,
    pub evidence_class: EvidenceClass,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    InvalidConfiguration,
    ConfigurationMismatch,
    MockInProduction,
    InvalidInput,
    InvalidEvidence,
    ProviderUnavailable,
    AmbiguousIdentity,
    ChallengeRejected,
    Expired,
    AgeRequired,
    SubjectNotFound,
    SubjectMismatch,
    Revoked,
    EpochMismatch,
    Capacity,
    Storage,
    Clock,
    Random,
    UnknownClient,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid service configuration",
            Self::ConfigurationMismatch => "database identity configuration mismatch",
            Self::MockInProduction => "development evidence is not permitted in production",
            Self::InvalidInput => "invalid or oversized input",
            Self::InvalidEvidence => "identity evidence could not be verified",
            Self::ProviderUnavailable => "identity provider unavailable",
            Self::AmbiguousIdentity => "identity matching is ambiguous",
            Self::ChallengeRejected => "unknown or already consumed verification challenge",
            Self::Expired => "verification or identity evidence expired",
            Self::AgeRequired => "required age threshold not established",
            Self::SubjectNotFound => "binding not available",
            Self::SubjectMismatch => "recovery evidence does not match the intended binding",
            Self::Revoked => "identity binding revoked",
            Self::EpochMismatch => "authentication epoch is no longer current",
            Self::Capacity => "pending verification limit reached",
            Self::Storage => "identity storage unavailable or invalid",
            Self::Clock => "trusted clock unavailable or invalid",
            Self::Random => "secure randomness unavailable",
            Self::UnknownClient => "client is not registered",
        })
    }
}
impl std::error::Error for Error {}

/// Trusted IN-PROCESS application interface. Implementing a network adapter
/// requires client/operator authentication, authorization, CSRF and rate limits.
/// In particular, `status` and `revoke` must never become unauthenticated routes.
pub trait IdentityService {
    fn begin(&mut self, flow: IdentityFlow) -> Result<VerificationContext, Error>;
    fn complete(
        &mut self,
        challenge_id: &str,
        evidence: &Presentation,
    ) -> Result<Completion, Error>;
    fn status(&self, subject: &Subject) -> Result<BindingStatus, Error>;
    fn revoke(&mut self, subject: &Subject) -> Result<(), Error>;
    /// Checks freshness/epoch AFTER a trusted authentication adapter has
    /// authenticated the user. Knowledge of the subject/epoch is not authentication.
    fn validate_epoch(&self, subject: &Subject, epoch: u64) -> Result<BindingStatus, Error>;
}
