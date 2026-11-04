//! Configuration from the environment: verifier, clients, branding, core files.
use super::*;

/// Display names only; nothing here reaches the core or the client protocol.
#[derive(Clone)]
pub struct Brand {
    pub name: String,
    /// The page language's default when not configured.
    pub tagline: Option<String>,
    pub notice: Option<String>,
}

/// A relying party allowed to start verifications and redeem their results.
#[derive(Clone)]
pub struct ClientConfig {
    pub registration: ClientRegistration,
    /// Exact-match return URLs; no query, no fragment.
    pub redirect_uris: Vec<String>,
    /// Only the SHA-256 of the bearer token is kept.
    pub token_sha256: [u8; 32],
    /// Look of the pages of this client's verifications.
    pub theme: Theme,
    /// Names on those pages; the server brand when absent.
    pub brand: Option<Brand>,
}

/// Fixed page looks. A client picks one by name; no client-supplied markup
/// or style ever reaches the pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Theme {
    /// Black on white, the default.
    Plain,
    /// Warm colours and a dark header.
    Warm,
}

impl Theme {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "plain" => Some(Self::Plain),
            "warm" => Some(Self::Warm),
            _ => None,
        }
    }
}

pub struct Config {
    pub base: reqwest::Url,
    pub token: Option<String>,
    pub intended_use_id: String,
    pub public_origin: Option<reqwest::Url>,
    pub credential_format: String,
    pub profile: String,
    pub response_mode: String,
    /// Ask the wallet for `personal_administrative_number` as an optional claim.
    pub request_pan: bool,
    pub brand: Brand,
    pub core: CoreSettings,
}

pub struct CoreSettings {
    pub database: PathBuf,
    pub key_file: PathBuf,
    /// The server's own file for verification sessions and one-time codes.
    pub server_database: PathBuf,
    /// The verifier's `client_id`; it is the audience every presentation is bound to.
    pub verifier_client_id: String,
    pub window_seconds: u64,
    pub clients: Vec<ClientConfig>,
}

pub fn require_development(mode: &str) -> Result<(), &'static str> {
    if mode == "development" {
        Ok(())
    } else {
        Err("the WOHP server requires WOHP_SERVER_ENV=development (development evidence only)")
    }
}

pub fn hex_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks(2).enumerate() {
        out[index] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

pub fn redirect_uri(raw: &str) -> Result<reqwest::Url, &'static str> {
    let url = reqwest::Url::parse(raw).map_err(|_| "invalid client redirect URI")?;
    let loopback =
        url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "localhost"));
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || loopback)
    {
        return Err(
            "client redirect URIs must be HTTPS (or loopback HTTP) without credentials, query or fragment",
        );
    }
    Ok(url)
}

/// A client minimum age as configured: `13`, `14`, `16`, `18`, or `none` for
/// deduplication only. Always explicit: a missing value is an error, never
/// "no age requirement".
pub fn minimum_age(value: &str) -> Result<Option<AgeThreshold>, &'static str> {
    const MESSAGE: &str = "a client minimum age must be 13, 14, 16, 18 or none";
    if value == "none" {
        return Ok(None);
    }
    value
        .parse::<u8>()
        .ok()
        .and_then(AgeThreshold::from_years)
        .map(Some)
        .ok_or(MESSAGE)
}

pub fn client_config(
    client_id: &str,
    application_scope: &str,
    minimum_age: Option<AgeThreshold>,
    redirect_uris: Vec<String>,
    token_sha256: [u8; 32],
) -> Result<ClientConfig, &'static str> {
    let client_id = ClientId::parse(client_id).map_err(|_| "invalid client id")?;
    let registration = ClientRegistration::new(client_id, application_scope, minimum_age)
        .map_err(|_| "invalid client application scope")?;
    if redirect_uris.is_empty() || redirect_uris.len() > 8 {
        return Err("each client needs 1 to 8 redirect URIs");
    }
    for uri in &redirect_uris {
        redirect_uri(uri)?;
    }
    Ok(ClientConfig {
        registration,
        redirect_uris,
        token_sha256,
        theme: Theme::Plain,
        brand: None,
    })
}

/// The `WOHP_CLIENTS_FILE` document: `{"clients": [...]}`. `minimum_age` is
/// required (13, 14, 16, 18, or null for none); `theme` and `brand` are
/// optional per client.
pub fn clients_from_json(text: &str) -> Result<Vec<ClientConfig>, &'static str> {
    const ENTRY: &str = "client entries need client_id, application_scope, minimum_age, \
                         redirect_uris and token_sha256";
    const AGE: &str = "client minimum_age must be 13, 14, 16, 18 or null (none)";
    let value: Value =
        serde_json::from_str(text).map_err(|_| "WOHP_CLIENTS_FILE is not valid JSON")?;
    let entries = value
        .get("clients")
        .and_then(Value::as_array)
        .ok_or("WOHP_CLIENTS_FILE needs a clients array")?;
    entries
        .iter()
        .map(|entry| {
            let field = |name: &str| entry.get(name).and_then(Value::as_str).ok_or(ENTRY);
            let uris = entry
                .get("redirect_uris")
                .and_then(Value::as_array)
                .ok_or(ENTRY)?
                .iter()
                .map(|uri| uri.as_str().map(str::to_owned).ok_or(ENTRY))
                .collect::<Result<Vec<_>, _>>()?;
            let hash = hex_digest(field("token_sha256")?)
                .ok_or("token_sha256 must be 64 hexadecimal characters")?;
            let age = match entry.get("minimum_age").ok_or(ENTRY)? {
                Value::Null => None,
                value => Some(
                    value
                        .as_u64()
                        .and_then(|years| u8::try_from(years).ok())
                        .and_then(AgeThreshold::from_years)
                        .ok_or(AGE)?,
                ),
            };
            let mut client = client_config(
                field("client_id")?,
                field("application_scope")?,
                age,
                uris,
                hash,
            )?;
            if let Some(theme) = entry.get("theme") {
                client.theme = theme
                    .as_str()
                    .and_then(Theme::parse)
                    .ok_or("client theme must be plain or warm")?;
            }
            if let Some(brand) = entry.get("brand") {
                // `name` is required; without `tagline`/`notice` the page
                // shows the default text in the page language.
                const BRAND: &str = "client brand needs a name; tagline and notice are strings";
                let text = |name: &str| match brand.get(name) {
                    None => Ok(None),
                    Some(value) => value.as_str().ok_or(BRAND).and_then(brand_value).map(Some),
                };
                client.brand = Some(Brand {
                    name: text("name")?.ok_or(BRAND)?,
                    tagline: text("tagline")?,
                    notice: text("notice")?,
                });
            }
            Ok(client)
        })
        .collect()
}

/// Clients come from `WOHP_CLIENTS_FILE` (JSON, token hashes only) or, for a
/// single client, from `WOHP_CLIENT_*`. Nothing is implied.
pub fn clients() -> Result<Vec<ClientConfig>, &'static str> {
    let clients = if let Some(path) = env::var_os("WOHP_CLIENTS_FILE") {
        let text = fs::read_to_string(path).map_err(|_| "cannot read WOHP_CLIENTS_FILE")?;
        clients_from_json(&text)?
    } else if let Ok(client_id) = env::var("WOHP_CLIENT_ID") {
        let token = env::var("WOHP_CLIENT_TOKEN").map_err(|_| "missing WOHP_CLIENT_TOKEN")?;
        if token.len() < 32 || token.len() > 4096 || token.chars().any(char::is_control) {
            return Err("WOHP_CLIENT_TOKEN must be 32 to 4096 printable characters");
        }
        let scope = env::var("WOHP_CLIENT_SCOPE").map_err(|_| "missing WOHP_CLIENT_SCOPE")?;
        let uris = env::var("WOHP_CLIENT_REDIRECT_URIS")
            .map_err(|_| "missing WOHP_CLIENT_REDIRECT_URIS")?
            .split(',')
            .map(str::trim)
            .filter(|uri| !uri.is_empty())
            .map(str::to_owned)
            .collect();
        let age = env::var("WOHP_CLIENT_MIN_AGE")
            .map_err(|_| "missing WOHP_CLIENT_MIN_AGE (13, 14, 16, 18 or none)")?;
        let mut client = client_config(
            &client_id,
            &scope,
            minimum_age(&age)?,
            uris,
            sha256(token.as_bytes()),
        )?;
        // The single client shows the server brand (WOHP_BRAND_*).
        if let Ok(theme) = env::var("WOHP_CLIENT_THEME") {
            client.theme = Theme::parse(&theme).ok_or("WOHP_CLIENT_THEME must be plain or warm")?;
        }
        vec![client]
    } else {
        Vec::new()
    };
    if clients.is_empty() {
        return Err("account mode needs a client: WOHP_CLIENTS_FILE or WOHP_CLIENT_*");
    }
    unique_clients(&clients)?;
    Ok(clients)
}

pub fn unique_clients(clients: &[ClientConfig]) -> Result<(), &'static str> {
    for (index, client) in clients.iter().enumerate() {
        if clients[..index].iter().any(|other| {
            other.registration.client_id == client.registration.client_id
                || other.registration.application_scope == client.registration.application_scope
                || other.token_sha256 == client.token_sha256
        }) {
            return Err("client ids, application scopes and tokens must be unique");
        }
    }
    Ok(())
}

/// Reads `name`, falling back to its pre-rename `WOHP_SPIKE_*` spelling with a
/// warning, so existing environment files keep working for one release.
pub fn setting_os(name: &str, legacy: &str) -> Option<OsString> {
    setting_from(|key| env::var_os(key), name, legacy)
}

pub fn setting_from(
    lookup: impl Fn(&str) -> Option<OsString>,
    name: &str,
    legacy: &str,
) -> Option<OsString> {
    if let Some(value) = lookup(name) {
        return Some(value);
    }
    let value = lookup(legacy)?;
    eprintln!("wohp: {legacy} is deprecated, use {name}");
    Some(value)
}

pub fn setting(name: &str, legacy: &str) -> Option<String> {
    setting_os(name, legacy).and_then(|value| value.into_string().ok())
}

pub fn brand_value(value: &str) -> Result<String, &'static str> {
    if value.is_empty() || value.len() > 120 || value.chars().any(char::is_control) {
        return Err("brand values must be 1 to 120 printable characters");
    }
    Ok(value.to_owned())
}

pub fn brand_text(name: &str) -> Result<Option<String>, &'static str> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => brand_value(&value).map(Some),
        _ => Ok(None),
    }
}

pub fn brand() -> Result<Brand, &'static str> {
    Ok(Brand {
        name: brand_text("WOHP_BRAND_NAME")?.unwrap_or_else(|| "WOHP".into()),
        tagline: brand_text("WOHP_BRAND_TAGLINE")?,
        notice: brand_text("WOHP_BRAND_NOTICE")?,
    })
}

pub fn config() -> Result<Config, &'static str> {
    require_development(&setting("WOHP_SERVER_ENV", "WOHP_SPIKE_ENV").unwrap_or_default())?;
    let raw = setting("WOHP_VERIFIER_URL", "WOHP_SPIKE_VERIFIER_URL")
        .ok_or("missing WOHP_VERIFIER_URL")?;
    let base = reqwest::Url::parse(&raw).map_err(|_| "invalid verifier URL")?;
    if base.username() != ""
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
        || base.path() != "/"
        || !(base.scheme() == "https"
            || (base.scheme() == "http"
                && matches!(base.host_str(), Some("127.0.0.1" | "localhost"))))
    {
        return Err("WOHP_VERIFIER_URL must be an HTTPS origin or local HTTP origin");
    }
    let token = setting("WOHP_VERIFIER_TOKEN", "WOHP_SPIKE_VERIFIER_TOKEN");
    if token.as_deref().is_some_and(|token| {
        token.is_empty() || token.len() > 4096 || token.chars().any(char::is_control)
    }) {
        return Err("invalid WOHP_VERIFIER_TOKEN");
    }
    let intended_use_id = setting(
        "WOHP_VERIFIER_INTENDED_USE_ID",
        "WOHP_SPIKE_INTENDED_USE_ID",
    )
    .ok_or("missing WOHP_VERIFIER_INTENDED_USE_ID")?;
    if !opaque_id(&intended_use_id) {
        return Err("invalid WOHP_VERIFIER_INTENDED_USE_ID");
    }
    let public_origin = match setting("WOHP_SERVER_PUBLIC_ORIGIN", "WOHP_SPIKE_PUBLIC_ORIGIN") {
        Some(raw) if !raw.is_empty() => {
            let url = reqwest::Url::parse(&raw).map_err(|_| "invalid WOHP_SERVER_PUBLIC_ORIGIN")?;
            if url.username() != ""
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/"
                || !(url.scheme() == "https"
                    || (url.scheme() == "http"
                        && matches!(url.host_str(), Some("127.0.0.1" | "localhost"))))
            {
                return Err(
                    "WOHP_SERVER_PUBLIC_ORIGIN must be an HTTPS origin or local HTTP origin",
                );
            }
            Some(url)
        }
        _ => None,
    };
    let credential_format = setting(
        "WOHP_VERIFIER_CREDENTIAL_FORMAT",
        "WOHP_SPIKE_CREDENTIAL_FORMAT",
    )
    .unwrap_or_else(|| "sd-jwt".into());
    if !matches!(credential_format.as_str(), "sd-jwt" | "mdoc") {
        return Err("WOHP_VERIFIER_CREDENTIAL_FORMAT must be sd-jwt or mdoc");
    }
    let profile =
        setting("WOHP_VERIFIER_PROFILE", "WOHP_SPIKE_PROFILE").unwrap_or_else(|| "haip".into());
    if !matches!(profile.as_str(), "haip" | "openid4vp") {
        return Err("WOHP_VERIFIER_PROFILE must be haip or openid4vp");
    }
    let response_mode = setting("WOHP_VERIFIER_RESPONSE_MODE", "WOHP_SPIKE_RESPONSE_MODE")
        .unwrap_or_else(|| "direct_post.jwt".into());
    if !matches!(response_mode.as_str(), "direct_post" | "direct_post.jwt") {
        return Err("WOHP_VERIFIER_RESPONSE_MODE must be direct_post or direct_post.jwt");
    }
    if profile == "haip" && response_mode != "direct_post.jwt" {
        return Err("HAIP requires response_mode=direct_post.jwt");
    }
    let request_pan =
        match setting("WOHP_VERIFIER_REQUEST_PAN", "WOHP_SPIKE_REQUEST_PAN").as_deref() {
            Some("1") => true,
            Some("0") | None => false,
            _ => return Err("WOHP_VERIFIER_REQUEST_PAN must be 0 or 1"),
        };
    if env::var_os("WOHP_SERVER_MIN_AGE").is_some() || env::var_os("WOHP_SPIKE_MIN_AGE").is_some() {
        return Err(
            "WOHP_SERVER_MIN_AGE was removed: each client has its own minimum age \
             (WOHP_CLIENT_MIN_AGE, or minimum_age in WOHP_CLIENTS_FILE)",
        );
    }
    let window_seconds = match setting(
        "WOHP_SERVER_EVIDENCE_WINDOW_DAYS",
        "WOHP_SPIKE_EVIDENCE_WINDOW_DAYS",
    ) {
        Some(value) => value
            .parse::<u64>()
            .ok()
            .and_then(|days| days.checked_mul(86_400))
            .ok_or("invalid WOHP_SERVER_EVIDENCE_WINDOW_DAYS")?,
        None => DEFAULT_WINDOW_SECONDS,
    };
    let verifier_client_id = setting("WOHP_VERIFIER_CLIENT_ID", "WOHP_SPIKE_VERIFIER_CLIENT_ID")
        .ok_or("missing WOHP_VERIFIER_CLIENT_ID")?;
    if !verifier_client_id.starts_with("x509_hash:") || !safe_token(&verifier_client_id) {
        return Err("WOHP_VERIFIER_CLIENT_ID must be the verifier x509_hash client id");
    }
    let StoragePaths {
        database,
        key_file,
        server_database,
    } = storage_paths()?;
    Ok(Config {
        base,
        token,
        intended_use_id,
        public_origin,
        credential_format,
        profile,
        response_mode,
        request_pan,
        brand: brand()?,
        core: CoreSettings {
            database,
            key_file,
            server_database,
            verifier_client_id,
            window_seconds,
            clients: clients()?,
        },
    })
}

/// Where the server keeps its files; also all that `backup` and `restore` need.
pub struct StoragePaths {
    pub database: PathBuf,
    pub key_file: PathBuf,
    pub server_database: PathBuf,
}

pub fn storage_paths() -> Result<StoragePaths, &'static str> {
    let database = setting_os("WOHP_SERVER_CORE_DB", "WOHP_SPIKE_CORE_DB")
        .map(PathBuf::from)
        .ok_or("missing WOHP_SERVER_CORE_DB")?;
    let server_database = match env::var_os("WOHP_SERVER_DB") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => database.with_file_name("server.sqlite3"),
    };
    if server_database == database {
        return Err("WOHP_SERVER_DB must not be the core database");
    }
    let key_file = setting_os("WOHP_SERVER_CORE_KEY", "WOHP_SPIKE_CORE_KEY")
        .map(PathBuf::from)
        .ok_or("missing WOHP_SERVER_CORE_KEY")?;
    Ok(StoragePaths {
        database,
        key_file,
        server_database,
    })
}
