//! Persistent WOHP identity application core (specification v1.0.1).
//!
//! No EUDI SDK, HTTP, OIDC or WebAuthn types are part of this API. The library
//! accepts a trusted `IdentityProvider` adapter and implements `IdentityService`.
//! Network/user authentication must be performed by separate protocol adapters.
#![forbid(unsafe_code)]

pub mod backup;
mod crypto;
pub mod policy;
mod store;

pub use crypto::LookupKey;
pub use wohp_api as api;

use std::{
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use wohp_api::{
    AgeThreshold, BindingStatus, ClientId, ClientRegistration, Completion, Error, EvidenceClass,
    IdentityFlow, IdentityProvider, IdentityService, IdentityStatus, Presentation,
    ProviderDescriptor, ProviderError, Purpose, Registration, Subject, Timestamp,
    VerificationContext, VerificationOutcome, VerifiedPerson, valid_text,
};

/// Trusted infrastructure clock. Tests can substitute an explicit deterministic clock.
pub trait Clock: Send + Sync {
    fn now(&self) -> Result<Timestamp, Error>;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Result<Timestamp, Error> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| Error::Clock)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Environment {
    Development,
    Production,
}

/// Deployment settings fixed for the life of a database. There is no
/// deployment-wide age floor: each registered client has its own minimum age.
#[derive(Clone, Debug)]
pub struct Config {
    pub environment: Environment,
    /// Identity presentation recipient, NOT a relying party's account identifier.
    pub provider_audience: String,
}

impl Config {
    pub fn development() -> Self {
        Self {
            environment: Environment::Development,
            provider_audience: "wohp-local-verifier".into(),
        }
    }
}

pub struct Service<P: IdentityProvider, C: Clock = SystemClock> {
    provider: Arc<P>,
    clock: C,
    config: Config,
    descriptor: ProviderDescriptor,
    key: LookupKey,
    store: store::Store,
}

/// A consumed challenge waiting for its provider verification. It holds no
/// reference to the service, so the (possibly slow, networked) verification
/// runs without blocking other service calls.
pub struct PendingCompletion<P: IdentityProvider> {
    provider: Arc<P>,
    context: VerificationContext,
    target: Option<store::RecoveryTarget>,
    minimum_age: Option<AgeThreshold>,
    reserved_at: Timestamp,
}

impl<P: IdentityProvider> PendingCompletion<P> {
    pub fn verify(&self, evidence: &Presentation) -> Result<VerificationOutcome, ProviderError> {
        self.provider
            .verify(&self.context, evidence, self.reserved_at)
    }
}

impl<P: IdentityProvider, C: Clock> Service<P, C> {
    /// Evidence class of the configured provider; fixed for the database.
    pub fn evidence_class(&self) -> EvidenceClass {
        self.descriptor.evidence_class
    }

    /// First half of `complete`: consumes the challenge. A failure later on
    /// still burns this attempt.
    pub fn reserve_completion(
        &mut self,
        challenge_id: &str,
    ) -> Result<PendingCompletion<P>, Error> {
        Subject::parse(challenge_id).map_err(|_| Error::InvalidInput)?;
        if self.provider.descriptor() != self.descriptor {
            return Err(Error::ConfigurationMismatch);
        }
        let now = self.now()?;
        let consumed = self.store.consume(challenge_id, now)?;
        Ok(PendingCompletion {
            provider: Arc::clone(&self.provider),
            context: consumed.context,
            target: consumed.target,
            minimum_age: consumed.minimum_age,
            reserved_at: now,
        })
    }

    /// Second half of `complete`: validates the provider outcome and applies it.
    pub fn finish_completion(
        &mut self,
        pending: PendingCompletion<P>,
        outcome: Result<VerificationOutcome, ProviderError>,
    ) -> Result<Completion, Error> {
        let PendingCompletion {
            context,
            target,
            minimum_age,
            ..
        } = pending;
        let outcome = outcome.map_err(|e| match e {
            ProviderError::Unavailable => Error::ProviderUnavailable,
            _ => Error::InvalidEvidence,
        })?;
        let proof = match outcome {
            VerificationOutcome::Established(proof) => proof,
            VerificationOutcome::Ambiguous => return Err(Error::AmbiguousIdentity),
            _ => return Err(Error::InvalidEvidence),
        };
        let now = self.now()?;
        // Below the client's minimum age nothing about the person is stored.
        self.validate_evidence(&proof, &context, minimum_age, now)?;
        let lookup = self.key.person_lookup(&proof.person);
        let mut result = self.store.apply(&lookup, target.as_ref(), &proof, now)?;
        result.evidence_class = self.descriptor.evidence_class;
        Ok(result)
    }

    pub fn open(
        path: impl AsRef<Path>,
        config: Config,
        provider: Arc<P>,
        key: LookupKey,
        clock: C,
    ) -> Result<Self, Error> {
        let descriptor = provider.descriptor();
        if !valid_text(&config.provider_audience, 256)
            || !valid_text(&descriptor.integration_id, 128)
            || !valid_text(&descriptor.policy_version, 128)
        {
            return Err(Error::InvalidConfiguration);
        }
        if config.environment == Environment::Production
            && descriptor.evidence_class != EvidenceClass::Production
        {
            return Err(Error::MockInProduction);
        }
        let store = store::Store::open(path.as_ref(), &config, &descriptor, &key)?;
        Ok(Self {
            provider,
            clock,
            config,
            descriptor,
            key,
            store,
        })
    }

    fn now(&self) -> Result<Timestamp, Error> {
        let now = self.clock.now()?;
        if now > i64::MAX as u64 - wohp_api::LOGIN_TTL_SECONDS {
            return Err(Error::Clock);
        }
        Ok(now)
    }

    fn validate_evidence(
        &self,
        proof: &VerifiedPerson,
        context: &VerificationContext,
        minimum_age: Option<AgeThreshold>,
        now: Timestamp,
    ) -> Result<(), Error> {
        if self.config.environment == Environment::Production
            && proof.evidence_class != EvidenceClass::Production
        {
            return Err(Error::MockInProduction);
        }
        if proof.context != *context
            || proof.policy_version != self.descriptor.policy_version
            || proof.evidence_class != self.descriptor.evidence_class
            || proof.verified_at < context.issued_at
            || proof.verified_at > now
            || proof.valid_until > i64::MAX as u64
        {
            return Err(Error::InvalidEvidence);
        }
        if now < context.issued_at || now >= context.expires_at || now >= proof.valid_until {
            return Err(Error::Expired);
        }
        if proof.age.is_some_and(|age| {
            age.valid_until > i64::MAX as u64
                || age.valid_until > proof.valid_until
                || age.valid_until <= proof.verified_at
        }) {
            return Err(Error::InvalidEvidence);
        }
        if minimum_age.is_some_and(|floor| {
            !proof.age.is_some_and(|age| {
                age.at_least >= floor
                    && age.valid_until > now
                    && age.valid_until <= proof.valid_until
            })
        }) {
            return Err(Error::AgeRequired);
        }
        Ok(())
    }

    /// Privileged operator registration, from the operator's configuration.
    /// The client's minimum age follows the configuration; registrations and
    /// changes are audited. Protocol adapters must separately verify redirect
    /// URIs, credentials and consent before issuing anything to a client.
    pub fn register_client(
        &mut self,
        registration: ClientRegistration,
    ) -> Result<Registration, Error> {
        let now = self.now()?;
        self.store.register_client(&registration, now)
    }

    /// Starts a verification for a registered client: the challenge carries
    /// the client's minimum age, and evidence below it is refused before
    /// anything about the person is stored.
    pub fn begin_for_client(
        &mut self,
        client_id: &ClientId,
        flow: IdentityFlow,
    ) -> Result<VerificationContext, Error> {
        let minimum_age = self.store.client_minimum_age(client_id)?;
        self.begin_with(flow, minimum_age)
    }

    fn begin_with(
        &mut self,
        flow: IdentityFlow,
        minimum_age: Option<AgeThreshold>,
    ) -> Result<VerificationContext, Error> {
        let now = self.now()?;
        let purpose = match flow {
            IdentityFlow::Enrollment => Purpose::Enrollment,
            _ => Purpose::Recovery,
        };
        let context = VerificationContext {
            challenge_id: crypto::random_token()?,
            nonce: crypto::random_token()?,
            audience: self.config.provider_audience.clone(),
            purpose,
            issued_at: now,
            expires_at: now + wohp_api::LOGIN_TTL_SECONDS,
        };
        self.store.begin(&context, flow, minimum_age)?;
        Ok(context)
    }

    fn status_with(
        &self,
        subject: &Subject,
        minimum_age: Option<AgeThreshold>,
    ) -> Result<BindingStatus, Error> {
        let now = self.now()?;
        let mut status = self.store.status(subject, now, minimum_age)?;
        status
            .policy_version
            .clone_from(&self.descriptor.policy_version);
        status.evidence_class = self.descriptor.evidence_class;
        Ok(status)
    }

    /// Returns the persisted closed-set registration for a protocol adapter.
    pub fn client_registration(&self, client_id: &ClientId) -> Result<ClientRegistration, Error> {
        self.store.client_registration(client_id)
    }

    /// Returns a stable pairwise identifier after the adapter authenticated the
    /// human and authorized disclosure to this registered client.
    pub fn client_subject(
        &mut self,
        client_id: &ClientId,
        profile_subject: &Subject,
    ) -> Result<Subject, Error> {
        self.store.client_subject(client_id, profile_subject)
    }

    /// Resolves the private profile behind a pairwise client subject. The result
    /// is for in-process use by the identity adapter (for example to start a
    /// recovery) and must never be shown to a relying party.
    pub fn profile_for_client_subject(
        &self,
        client_id: &ClientId,
        client_subject: &Subject,
    ) -> Result<Subject, Error> {
        self.store
            .profile_for_client_subject(client_id, client_subject)
    }

    /// Status of the profile behind a client subject, under that client's
    /// minimum age. An unknown client, an unknown subject and a subject issued
    /// to another client are indistinguishable to the caller.
    pub fn status_for_client(
        &self,
        client_id: &ClientId,
        client_subject: &Subject,
    ) -> Result<BindingStatus, Error> {
        let profile = self.profile_for_client_subject(client_id, client_subject)?;
        let minimum_age = self.store.client_minimum_age(client_id)?;
        self.status_with(&profile, minimum_age)
    }

    /// Compromise reset requested by a registered client after it revoked the
    /// person's authenticators. Advances the per-human authentication epoch so
    /// every relying party ends sessions bound to the old one; the identity
    /// status is unchanged and pending recoveries are cancelled. Returns the
    /// new epoch. Unknown and foreign subjects are indistinguishable.
    pub fn reset_authenticators_for_client(
        &mut self,
        client_id: &ClientId,
        client_subject: &Subject,
    ) -> Result<u64, Error> {
        let profile = self.profile_for_client_subject(client_id, client_subject)?;
        let now = self.now()?;
        self.store.reset_authenticators(&profile, now)
    }
}

impl<P: IdentityProvider, C: Clock> IdentityService for Service<P, C> {
    /// Without a client there is no age requirement: deduplication only.
    fn begin(&mut self, flow: IdentityFlow) -> Result<VerificationContext, Error> {
        self.begin_with(flow, None)
    }

    fn complete(
        &mut self,
        challenge_id: &str,
        evidence: &Presentation,
    ) -> Result<Completion, Error> {
        // Reserve/consume before external work. Failures burn this attempt; there
        // is no custom replay/idempotency protocol and no network I/O under a DB lock.
        let pending = self.reserve_completion(challenge_id)?;
        let outcome = pending.verify(evidence);
        self.finish_completion(pending, outcome)
    }

    /// The person's status with no age requirement; see `status_for_client`.
    fn status(&self, subject: &Subject) -> Result<BindingStatus, Error> {
        self.status_with(subject, None)
    }

    fn revoke(&mut self, subject: &Subject) -> Result<(), Error> {
        let now = self.now()?;
        self.store.revoke(subject, now)
    }

    fn validate_epoch(&self, subject: &Subject, epoch: u64) -> Result<BindingStatus, Error> {
        let status = self.status(subject)?;
        if epoch != status.authentication_epoch {
            return Err(Error::EpochMismatch);
        }
        match status.status {
            IdentityStatus::Valid => Ok(status),
            IdentityStatus::Revoked => Err(Error::Revoked),
            _ => Err(Error::Expired),
        }
    }
}
