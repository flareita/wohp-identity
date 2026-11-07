//! The WOHP core behind the server: lookup key, opening and the completion step.
use super::*;
use wohp::policy::{Mismatch, diagnose};
use wohp_api::{IdentityProvider, ProviderDescriptor, Registration};

/// The decision point: the WOHP core, behind the EUDI verifier adapter.
/// The provider is blocking, so every call goes through `spawn_blocking`.
pub type Core = Arc<Mutex<Service<EudiVerifierProvider>>>;

pub fn read_key(path: &FsPath) -> Result<LookupKey, CoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)
            .map_err(|_| CoreError::Storage)?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err(CoreError::InvalidConfiguration);
        }
    }
    let bytes: [u8; 32] = fs::read(path)
        .map_err(|_| CoreError::Storage)?
        .try_into()
        .map_err(|_| CoreError::InvalidConfiguration)?;
    LookupKey::from_bytes(&bytes)
}

/// The lookup key is created only together with a brand new database. A lost
/// key next to an existing database must fail, never silently reset deduplication.
pub fn load_or_create_key(key_file: &FsPath, database: &FsPath) -> Result<LookupKey, CoreError> {
    use std::io::Write;
    if !key_file.exists() {
        if database.exists() {
            return Err(CoreError::ConfigurationMismatch);
        }
        let bytes = LookupKey::generate_bytes()?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(key_file).map_err(|_| CoreError::Storage)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| CoreError::Storage)?;
    }
    read_key(key_file)
}

/// Must run outside the async runtime: the provider owns a blocking HTTP client.
pub fn open_core(
    config: &Config,
    settings: &CoreSettings,
) -> Result<Core, Box<dyn std::error::Error>> {
    let key = load_or_create_key(&settings.key_file, &settings.database)?;
    // Unbound mdoc is a different policy version, so the database refuses a silent flip.
    let provider = EudiVerifierProvider::new(
        config.base.as_str(),
        config.token.as_deref(),
        settings.window_seconds,
    )?
    .allow_unbound_mdoc(config.credential_format == "mdoc");
    let mut core_config = wohp::Config::development();
    core_config
        .provider_audience
        .clone_from(&settings.verifier_client_id);
    let descriptor = provider.descriptor();
    let mut service = match Service::open(
        &settings.database,
        core_config.clone(),
        Arc::new(provider),
        key,
        SystemClock,
    ) {
        Ok(service) => service,
        Err(CoreError::ConfigurationMismatch) => {
            return Err(mismatch_report(settings, &core_config, &descriptor).into());
        }
        Err(error) => return Err(error.into()),
    };
    // Idempotent; a client already registered with another scope is refused.
    for client in &settings.clients {
        let id = client.registration.client_id.as_str();
        match service.register_client(client.registration.clone())? {
            Registration::Created => eprintln!(
                "wohp: client {id} registered, minimum age {}",
                age_text(client.registration.minimum_age)
            ),
            Registration::MinimumAgeChanged { previous, current } => eprintln!(
                "wohp: client {id} minimum age changed from {} to {} (audited)",
                age_text(previous),
                age_text(current)
            ),
            _ => {}
        }
    }
    Ok(Arc::new(Mutex::new(service)))
}

/// Names what differs between WOHP_SERVER_CORE_DB and this configuration, with
/// the setting that fixes it. One line: `main` prints errors with `Debug`.
fn mismatch_report(
    settings: &CoreSettings,
    config: &wohp::Config,
    descriptor: &ProviderDescriptor,
) -> String {
    let found = read_key(&settings.key_file)
        .and_then(|key| diagnose(&settings.database, config, descriptor, &key))
        .unwrap_or_default();
    if found.is_empty() {
        return CoreError::ConfigurationMismatch.to_string();
    }
    let details: Vec<String> = found
        .iter()
        .map(|mismatch| match mismatch {
            Mismatch::Schema => format!(
                "{mismatch}: move WOHP_SERVER_CORE_DB, WOHP_SERVER_CORE_KEY and WOHP_SERVER_DB \
                 aside and start again"
            ),
            Mismatch::Audience => format!("{mismatch}: check WOHP_VERIFIER_CLIENT_ID"),
            Mismatch::Provider => format!("{mismatch}: check WOHP_VERIFIER_CREDENTIAL_FORMAT"),
            Mismatch::LookupKey => format!("{mismatch}: check WOHP_SERVER_CORE_KEY"),
            other => other.to_string(),
        })
        .collect();
    format!(
        "WOHP_SERVER_CORE_DB does not match this configuration: {}",
        details.join("; ")
    )
}

/// A challenge the core refused is final; the client starts a new verification.
pub fn rejection(error: CoreError) -> &'static str {
    match error {
        CoreError::AmbiguousIdentity => "ambiguous",
        CoreError::AgeRequired => "underage",
        CoreError::ProviderUnavailable => "unavailable",
        CoreError::Expired | CoreError::ChallengeRejected => "expired",
        _ => "invalid",
    }
}

/// A minimum age as the operator writes it.
pub fn age_text(age: Option<AgeThreshold>) -> String {
    age.map_or_else(|| "none".into(), |age| age.years().to_string())
}

/// What the core decided; stored as the grant behind a one-time code. The age
/// is absent when the evidence proves no threshold; the client's own minimum
/// age, if any, was already enforced by the core.
pub struct Accepted {
    pub kind: &'static str,
    pub client_subject: String,
    pub authentication_epoch: u64,
    pub age_at_least: Option<u8>,
    pub age_valid_until: Option<u64>,
}

/// Consumes the challenge, verifies with the core lock released (the verifier
/// is a network call), then deduplicates and derives the client's subject.
/// The completion kind must match the flow the client started.
pub fn accept_in_core(
    core: &Core,
    challenge_id: &str,
    presentation: &Presentation,
    flow: WalletFlow,
    client: &ClientId,
) -> Result<Accepted, CoreError> {
    let pending = core
        .lock()
        .map_err(|_| CoreError::Storage)?
        .reserve_completion(challenge_id)?;
    let outcome = pending.verify(presentation);
    let mut service = core.lock().map_err(|_| CoreError::Storage)?;
    let completion = service.finish_completion(pending, outcome)?;
    let enrollment = match completion.kind {
        CompletionKind::Created | CompletionKind::ExistingRequiresAuthentication
            if flow == WalletFlow::Enrollment =>
        {
            true
        }
        CompletionKind::Recovered if flow == WalletFlow::Recovery => false,
        _ => return Err(CoreError::InvalidEvidence),
    };
    let (client_subject, issued) = service.issue_client_subject(client, &completion.subject)?;
    // `existing` is relative to this client: enrollment through another client
    // must not be visible here.
    let kind = match (enrollment, issued) {
        (false, _) => "recovered",
        (true, true) => "created",
        (true, false) => "existing",
    };
    let status = service.status(&completion.subject)?;
    let age = status.age_at_least.zip(status.age_valid_until);
    Ok(Accepted {
        kind,
        client_subject: client_subject.as_str().to_owned(),
        authentication_epoch: completion.authentication_epoch,
        age_at_least: age.map(|(age, _)| age.years()),
        age_valid_until: age.map(|(_, until)| until),
    })
}
