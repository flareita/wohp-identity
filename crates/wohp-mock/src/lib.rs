//! In-process development fixture provider. Never certified identity evidence.
#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use wohp_api::{
    AgeEvidence, AgeThreshold, CanonicalPerson, EvidenceClass, IdentityProvider, Presentation,
    ProviderDescriptor, ProviderError, Timestamp, VerificationContext, VerificationOutcome,
    VerifiedPerson,
};

/// Long enough for age evidence to survive rounding to the UTC day.
const EVIDENCE_WINDOW_SECONDS: u64 = 2 * 86_400;

#[derive(Clone, Debug)]
pub enum Scenario {
    Person {
        reference: String,
        adult: Option<bool>,
    },
    Aged {
        reference: String,
        at_least: Option<AgeThreshold>,
    },
    Ambiguous,
    Unavailable,
    Invalid,
}

impl Scenario {
    pub fn person(reference: &str, adult: Option<bool>) -> Self {
        Self::Person {
            reference: reference.into(),
            adult,
        }
    }

    pub fn aged(reference: &str, at_least: Option<AgeThreshold>) -> Self {
        Self::Aged {
            reference: reference.into(),
            at_least,
        }
    }
}

struct Ticket {
    context: VerificationContext,
    scenario: Scenario,
}

/// Tickets are intentionally local simulator capabilities, not signed proofs.
/// An EUDI adapter replaces this implementation without changing `wohp-api`.
pub struct MockIdentityProvider {
    tickets: Mutex<HashMap<Vec<u8>, Ticket>>,
    counter: AtomicU64,
}

impl Default for MockIdentityProvider {
    fn default() -> Self {
        Self {
            tickets: Mutex::new(HashMap::new()),
            counter: AtomicU64::new(1),
        }
    }
}

impl MockIdentityProvider {
    /// Explicit simulator operation. Not an enrollment endpoint for production.
    pub fn issue(
        &self,
        context: &VerificationContext,
        scenario: Scenario,
    ) -> Result<Presentation, ProviderError> {
        let sequence = self.counter.fetch_add(1, Ordering::Relaxed);
        let bytes = format!("mock-only:{}:{sequence}", context.nonce).into_bytes();
        let mut tickets = self
            .tickets
            .lock()
            .map_err(|_| ProviderError::Unavailable)?;
        tickets.retain(|_, ticket| ticket.context.expires_at > context.issued_at);
        if tickets.len() >= 1024 {
            return Err(ProviderError::Unavailable);
        }
        tickets.insert(
            bytes.clone(),
            Ticket {
                context: context.clone(),
                scenario,
            },
        );
        Presentation::new(bytes).map_err(|_| ProviderError::InvalidEvidence)
    }
}

impl IdentityProvider for MockIdentityProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            integration_id: "mock-local-v1".into(),
            policy_version: "mock-only-1".into(),
            evidence_class: EvidenceClass::DevelopmentOnly,
        }
    }

    fn verify(
        &self,
        context: &VerificationContext,
        presentation: &Presentation,
        now: Timestamp,
    ) -> Result<VerificationOutcome, ProviderError> {
        let ticket = self
            .tickets
            .lock()
            .map_err(|_| ProviderError::Unavailable)?
            .remove(presentation.as_bytes())
            .ok_or(ProviderError::InvalidEvidence)?;
        if ticket.context != *context || now < context.issued_at || now >= context.expires_at {
            return Err(ProviderError::InvalidEvidence);
        }
        let (reference, threshold) = match ticket.scenario {
            Scenario::Ambiguous => return Ok(VerificationOutcome::Ambiguous),
            Scenario::Unavailable => return Err(ProviderError::Unavailable),
            Scenario::Invalid => return Err(ProviderError::InvalidEvidence),
            Scenario::Person { reference, adult } => (
                reference,
                adult.and_then(|positive| positive.then_some(AgeThreshold::Eighteen)),
            ),
            Scenario::Aged {
                reference,
                at_least,
            } => (reference, at_least),
        };
        let person = CanonicalPerson::new("mock.canonical-person.v1", &reference)
            .map_err(|_| ProviderError::InvalidEvidence)?;
        let valid_until = now
            .checked_add(EVIDENCE_WINDOW_SECONDS)
            .ok_or(ProviderError::InvalidEvidence)?;
        Ok(VerificationOutcome::Established(Box::new(VerifiedPerson {
            person,
            context: context.clone(),
            policy_version: self.descriptor().policy_version,
            evidence_class: EvidenceClass::DevelopmentOnly,
            verified_at: now,
            valid_until,
            age: threshold.map(|at_least| AgeEvidence {
                at_least,
                valid_until,
            }),
        })))
    }
}
