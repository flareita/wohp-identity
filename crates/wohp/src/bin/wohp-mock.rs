//! Privileged local development harness; never an authentication server.
#![forbid(unsafe_code)]

use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    process::ExitCode,
    sync::Arc,
};
use wohp::{
    Config, LookupKey, Service, SystemClock,
    policy::{Mismatch, diagnose},
};
use wohp_api::{
    AgeThreshold, ClientId, ClientRegistration, Error, IdentityFlow, IdentityProvider,
    IdentityService, Registration, Subject,
};
use wohp_mock::{MockIdentityProvider, Scenario};

const USAGE: &str = "Development mock only (no EUDI, OIDC or WebAuthn authentication).\n\
Usage:\n  wohp-mock keygen KEY_FILE\n  wohp-mock DB_FILE KEY_FILE demo\n  \
wohp-mock DB_FILE KEY_FILE client CLIENT_ID SCOPE 13|14|16|18|none\n  \
wohp-mock DB_FILE KEY_FILE enroll FIXTURE [AGE] [CLIENT_ID]\n  \
wohp-mock DB_FILE KEY_FILE recover SUBJECT FIXTURE [AGE]\n  \
wohp-mock DB_FILE KEY_FILE status SUBJECT\n  \
wohp-mock DB_FILE KEY_FILE client-status CLIENT_ID CLIENT_SUBJECT\n  \
wohp-mock DB_FILE KEY_FILE revoke SUBJECT\n\
AGE: 13|14|16|18|adult (default)|underage|unknown. With CLIENT_ID, enrollment\n\
is refused below that client's minimum age and nothing is stored.";

/// A core error, or one already explained in full.
enum Failure {
    Core(Error),
    Explained(String),
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Core(error)
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args == ["--help"] {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Core(error)) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
        Err(Failure::Explained(message)) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

/// A client minimum age: a threshold, or `none` for deduplication only.
fn parse_minimum_age(value: &str) -> Result<Option<AgeThreshold>, Error> {
    if value == "none" {
        return Ok(None);
    }
    value
        .parse::<u8>()
        .ok()
        .and_then(AgeThreshold::from_years)
        .map(Some)
        .ok_or(Error::InvalidInput)
}

fn age_text(age: Option<AgeThreshold>) -> String {
    age.map_or_else(|| "none".into(), |age| age.years().to_string())
}

fn keygen(path: &Path) -> Result<(), Error> {
    let bytes = LookupKey::generate_bytes()?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| Error::Storage)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| Error::Storage)?;
    println!("Created lookup key. Keep it with this database; do not regenerate it.");
    Ok(())
}

fn read_key(path: &Path) -> Result<LookupKey, Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)
            .map_err(|_| Error::Storage)?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err(Error::InvalidConfiguration);
        }
    }
    let bytes: [u8; 32] = fs::read(path)
        .map_err(|_| Error::Storage)?
        .try_into()
        .map_err(|_| Error::InvalidConfiguration)?;
    LookupKey::from_bytes(&bytes)
}

fn fixture(reference: &str, value: Option<&String>) -> Result<Scenario, Error> {
    let at_least = match value.map(String::as_str).unwrap_or("adult") {
        "adult" | "18" => Some(AgeThreshold::Eighteen),
        "underage" | "unknown" => None,
        other => Some(
            other
                .parse::<u8>()
                .ok()
                .and_then(AgeThreshold::from_years)
                .ok_or(Error::InvalidInput)?,
        ),
    };
    Ok(Scenario::aged(reference, at_least))
}

fn client_id(value: &str) -> Result<ClientId, Error> {
    ClientId::parse(value).map_err(|_| Error::InvalidInput)
}

/// Spells out a refused reopen: which deployment setting differs.
fn explain_mismatch(
    database: &Path,
    key: &Path,
    config: &Config,
    provider: &MockIdentityProvider,
) -> Failure {
    let found = read_key(key)
        .and_then(|key| diagnose(database, config, &provider.descriptor(), &key))
        .unwrap_or_default();
    if found.is_empty() {
        return Failure::Core(Error::ConfigurationMismatch);
    }
    let mut message = String::from("database identity configuration mismatch:");
    for mismatch in found {
        let hint = match mismatch {
            Mismatch::Schema => "delete it and its key, then start again",
            Mismatch::LookupKey => "use the key file created with this database",
            _ => "this database was created by another configuration",
        };
        message.push_str(&format!("\n  {mismatch}: {hint}"));
    }
    Failure::Explained(message)
}

type Mock = Service<MockIdentityProvider>;

fn enroll(
    service: &mut Mock,
    provider: &MockIdentityProvider,
    scenario: Scenario,
    client: Option<&ClientId>,
) -> Result<wohp_api::Completion, Error> {
    let context = match client {
        Some(client) => service.begin_for_client(client, IdentityFlow::Enrollment)?,
        None => service.begin(IdentityFlow::Enrollment)?,
    };
    let evidence = provider
        .issue(&context, scenario)
        .map_err(|_| Error::ProviderUnavailable)?;
    service.complete(&context.challenge_id, &evidence)
}

fn register(
    service: &mut Mock,
    id: &str,
    scope: &str,
    age: Option<AgeThreshold>,
) -> Result<(), Error> {
    let registration =
        ClientRegistration::new(client_id(id)?, scope, age).map_err(|_| Error::InvalidInput)?;
    match service.register_client(registration)? {
        Registration::Created => println!("Client {id} registered; minimum age {}.", age_text(age)),
        Registration::MinimumAgeChanged { previous, current } => println!(
            "Client {id}: minimum age changed from {} to {} (audited).",
            age_text(previous),
            age_text(current)
        ),
        _ => println!("Client {id} unchanged; minimum age {}.", age_text(age)),
    }
    Ok(())
}

fn demo(service: &mut Mock, provider: &MockIdentityProvider) -> Result<(), Failure> {
    let first = enroll(
        service,
        provider,
        Scenario::person("fixture-alice", Some(true)),
        None,
    )?;
    println!(
        "DEVELOPMENT ONLY: {:?}; subject={}",
        first.kind,
        first.subject.as_str()
    );
    let again = enroll(
        service,
        provider,
        Scenario::person("fixture-alice", Some(true)),
        None,
    )?;
    if again.subject != first.subject {
        return Err(Error::Storage.into());
    }
    println!("Duplicate enrollment resolved to the same subject; authentication still required.");
    service.revoke(&first.subject)?;
    let context = service.begin(IdentityFlow::Recovery {
        subject: first.subject.clone(),
    })?;
    let evidence = provider
        .issue(&context, Scenario::person("fixture-alice", Some(true)))
        .map_err(|_| Error::ProviderUnavailable)?;
    let recovered = service.complete(&context.challenge_id, &evidence)?;
    println!(
        "Recovery retained subject={}; epoch={}",
        recovered.subject.as_str(),
        recovered.authentication_epoch
    );
    // Per-client minimum age: a school vote deduplicates a child, a social
    // network with a minimum age of 13 refuses the same child.
    register(service, "demo-school-vote", "school.example", None)?;
    register(
        service,
        "demo-social",
        "social.example",
        Some(AgeThreshold::Thirteen),
    )?;
    let vote = client_id("demo-school-vote")?;
    let social = client_id("demo-social")?;
    let child = enroll(
        service,
        provider,
        Scenario::aged("fixture-child", None),
        Some(&vote),
    )?;
    println!("School vote (no minimum age): child {:?}", child.kind);
    let twice = enroll(
        service,
        provider,
        Scenario::aged("fixture-child", None),
        Some(&vote),
    )?;
    println!(
        "Second vote attempt resolves to the same person: {:?}",
        twice.kind
    );
    match enroll(
        service,
        provider,
        Scenario::aged("fixture-child", None),
        Some(&social),
    ) {
        Err(Error::AgeRequired) => println!("Social network (minimum age 13): child refused."),
        other => return Err(other.err().unwrap_or(Error::Storage).into()),
    }
    println!("No signed ID token or authenticated network session was issued.");
    Ok(())
}

fn run(args: &[String]) -> Result<(), Failure> {
    if args.len() == 2 && args[0] == "keygen" {
        return Ok(keygen(Path::new(&args[1]))?);
    }
    if args.len() < 3 {
        return Err(Error::InvalidInput.into());
    }
    let (database, key) = (Path::new(&args[0]), Path::new(&args[1]));
    let config = Config::development();
    let provider = Arc::new(MockIdentityProvider::default());
    let mut service = match Service::open(
        database,
        config.clone(),
        Arc::clone(&provider),
        read_key(key)?,
        SystemClock,
    ) {
        Ok(service) => service,
        Err(Error::ConfigurationMismatch) => {
            return Err(explain_mismatch(database, key, &config, &provider));
        }
        Err(error) => return Err(error.into()),
    };
    match (args[2].as_str(), args.len()) {
        ("client", 6) => register(
            &mut service,
            &args[3],
            &args[4],
            parse_minimum_age(&args[5])?,
        )?,
        ("enroll", 4..=6) => {
            let client = args.get(5).map(|id| client_id(id)).transpose()?;
            let result = enroll(
                &mut service,
                &provider,
                fixture(&args[3], args.get(4))?,
                client.as_ref(),
            )?;
            println!(
                "DEVELOPMENT ONLY: {:?}; subject={}; epoch={}",
                result.kind,
                result.subject.as_str(),
                result.authentication_epoch
            );
            if let Some(client) = &client {
                let subject = service.client_subject(client, &result.subject)?;
                println!("client_subject={}", subject.as_str());
            }
        }
        ("recover", 5 | 6) => {
            let subject = Subject::parse(&args[3]).map_err(|_| Error::InvalidInput)?;
            let context = service.begin(IdentityFlow::Recovery { subject })?;
            let evidence = provider
                .issue(&context, fixture(&args[4], args.get(5))?)
                .map_err(|_| Error::ProviderUnavailable)?;
            let result = service.complete(&context.challenge_id, &evidence)?;
            println!(
                "DEVELOPMENT recovery: subject={}; epoch={}",
                result.subject.as_str(),
                result.authentication_epoch
            );
        }
        ("status", 4) => {
            let subject = Subject::parse(&args[3]).map_err(|_| Error::InvalidInput)?;
            let status = service.status(&subject)?;
            println!(
                "DEVELOPMENT status={:?}; epoch={}; age_at_least={}; policy={}",
                status.status,
                status.authentication_epoch,
                age_text(status.age_at_least),
                status.policy_version
            );
        }
        ("client-status", 5) => {
            let subject = Subject::parse(&args[4]).map_err(|_| Error::InvalidInput)?;
            let status = service.status_for_client(&client_id(&args[3])?, &subject)?;
            println!(
                "DEVELOPMENT status={:?}; epoch={}; age_at_least={}",
                status.status,
                status.authentication_epoch,
                age_text(status.age_at_least)
            );
        }
        ("revoke", 4) => {
            let subject = Subject::parse(&args[3]).map_err(|_| Error::InvalidInput)?;
            service.revoke(&subject)?;
            println!("Development binding revoked.");
        }
        ("demo", 3) => demo(&mut service, &provider)?,
        _ => return Err(Error::InvalidInput.into()),
    }
    Ok(())
}
