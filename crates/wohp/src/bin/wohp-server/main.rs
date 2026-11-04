//! WOHP identity server in front of an independently configured EUDI Verifier
//! Endpoint (development evidence only).
//!
//! It proves a person with the wallet, deduplicates people in the WOHP core and
//! hands a one-time code back to a registered client, which redeems it
//! server-to-server for a pairwise subject. It knows nothing about the client's
//! sessions, OIDC provider, login challenges or passkeys.
#![forbid(unsafe_code)]

mod admin;
mod client_api;
mod config;
mod identity;
mod lang;
mod pages;
mod store;
mod verifier;

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use client_api::*;
use config::*;
use identity::*;
use lang::*;
use pages::*;
use qrcode::QrCode;
use reqwest::Client;
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use serde_json::{Map, Value, json};
use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use store::{Claim, GrantRow, Store, VerificationRow};
use verifier::*;
use wohp::{LookupKey, Service, SystemClock};
use wohp_api::{
    AgeThreshold, BindingStatus, ClientId, ClientRegistration, CompletionKind, Error as CoreError,
    EvidenceClass, IdentityFlow, IdentityService, IdentityStatus, Presentation, Subject,
};
use wohp_eudi::{
    DEFAULT_WINDOW_SECONDS, EudiVerifierProvider, PID_DOCTYPE, PID_VCT, mdoc_presentation,
    sd_jwt_presentation,
};

/// The fixed content security policy: forms only post to this origin and the
/// status poll only talks to it.
const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; \
                   connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; \
                   form-action 'self'";

/// Bound on concurrent verification sessions and on unredeemed codes.
const MAX_PENDING: usize = 256;
/// Lifetime of a one-time code handed back to the client through the browser.
const CODE_TTL_SECONDS: u64 = 120;

struct App {
    client: Client,
    config: Config,
    core: Core,
    /// Verifications and codes, keyed by their SHA-256.
    store: Store,
    /// Fixed for the core database; reported with every result.
    evidence_class: EvidenceClass,
}

impl App {
    fn new(client: Client, config: Config, core: Core, store: Store) -> Self {
        let evidence_class = core
            .lock()
            .map_or(EvidenceClass::DevelopmentOnly, |service| {
                service.evidence_class()
            });
        Self {
            client,
            config,
            core,
            store,
            evidence_class,
        }
    }

    fn clients(&self) -> &[ClientConfig] {
        &self.config.core.clients
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WalletFlow {
    Enrollment,
    Recovery,
}

impl WalletFlow {
    fn as_str(self) -> &'static str {
        match self {
            Self::Enrollment => "enroll",
            Self::Recovery => "recover",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "enroll" => Some(Self::Enrollment),
            "recover" => Some(Self::Recovery),
            _ => None,
        }
    }
}

/// Inputs of one completion attempt, read from the verification row the caller
/// claimed. Nonce and audience come from the core challenge.
struct Attempt {
    id_hash: [u8; 32],
    presentation_id: String,
    challenge_id: String,
    flow: WalletFlow,
    client_id: ClientId,
    return_url: reqwest::Url,
    state: String,
}

impl Attempt {
    fn from_row(id_hash: [u8; 32], row: VerificationRow) -> Option<Self> {
        Some(Self {
            id_hash,
            presentation_id: row.presentation?.0,
            challenge_id: row.challenge_id,
            flow: WalletFlow::parse(&row.flow)?,
            client_id: ClientId::parse(&row.client_id).ok()?,
            return_url: reqwest::Url::parse(&row.return_url).ok()?,
            state: row.state,
        })
    }
}

enum Finish {
    Pending,
    Ready(String),
    Rejected(&'static str),
}

fn timestamp() -> Result<u64, StatusCode> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn safe_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.bytes().all(|byte| {
            byte.is_ascii_graphic() && !matches!(byte, b'\'' | b'"' | b'<' | b'>' | b'&')
        })
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&#39;")
}

fn local_request(
    headers: &HeaderMap,
    post: bool,
    public_origin: Option<&reqwest::Url>,
) -> Result<(), StatusCode> {
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::FORBIDDEN)?;
    let local = host == "127.0.0.1:8787" || host == "localhost:8787";
    let public_host = public_origin.and_then(|origin| {
        origin.host_str().map(|host| match origin.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        })
    });
    if !local && public_host.as_deref() != Some(host) {
        return Err(StatusCode::FORBIDDEN);
    }
    if post {
        let origin = headers
            .get("origin")
            .and_then(|h| h.to_str().ok())
            .ok_or(StatusCode::FORBIDDEN)?;
        let allowed = if local {
            origin == format!("http://{host}")
        } else {
            public_origin.is_some_and(|url| url.as_str().trim_end_matches('/') == origin)
        };
        if !allowed {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    Ok(())
}

fn random_token() -> Result<String, StatusCode> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn sha256(value: &[u8]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, value).as_ref());
    out
}

/// Constant-time comparison of two digests.
fn same_digest(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Appends the protocol parameters to a registered return URL.
fn return_with(url: &reqwest::Url, pairs: &[(&str, &str)]) -> String {
    let mut url = url.clone();
    url.query_pairs_mut().extend_pairs(pairs);
    url.into()
}

fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/verify/{id}", get(verify_page))
        .route("/verify/{id}/status", get(verify_status))
        .route("/static/verify.js", get(verify_script))
        .route("/v1/verifications", post(api_start))
        .route("/v1/verifications/redeem", post(api_redeem))
        .route("/v1/subjects/status", post(api_subject_status))
        .route(
            "/v1/subjects/revoke-authenticators",
            post(api_subject_reset),
        )
        .with_state(app)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Without arguments it serves; `backup` and `restore` are operator commands.
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    if !arguments.is_empty() {
        admin::run(&arguments);
    }
    let config = config()?;
    // Opened before the runtime: the provider owns a blocking HTTP client.
    let core = open_core(&config, &config.core)?;
    let now = timestamp().map_err(|_| "system clock before 1970")?;
    let store = Store::open(&config.core.server_database, now)
        .map_err(|_| "cannot open WOHP_SERVER_DB (it must be a private 0600 server database)")?;
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let app = Arc::new(App::new(client, config, core, store));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let listen_host = setting("WOHP_SERVER_LISTEN_HOST", "WOHP_SPIKE_LISTEN_HOST")
        .unwrap_or_else(|| "127.0.0.1".into());
    if !matches!(listen_host.as_str(), "127.0.0.1" | "localhost" | "0.0.0.0") {
        return Err("WOHP_SERVER_LISTEN_HOST must be 127.0.0.1, localhost or 0.0.0.0".into());
    }
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind((listen_host.as_str(), 8787)).await?;
        println!("WOHP identity server: http://127.0.0.1:8787/");
        axum::serve(listener, router(app)).await?;
        Ok(())
    })
}

#[cfg(test)]
mod tests;
