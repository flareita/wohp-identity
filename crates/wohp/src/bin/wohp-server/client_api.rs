//! The relying-party API (`/v1/...`), authenticated with client bearer tokens.
use super::*;

pub fn api_json(status: StatusCode, value: &Value) -> Response {
    (
        status,
        [
            ("cache-control", "no-store"),
            ("content-type", "application/json"),
        ],
        value.to_string(),
    )
        .into_response()
}

pub fn api_error(status: StatusCode, error: &str) -> Response {
    api_json(status, &json!({ "error": error }))
}

/// Bearer authentication of a registered client. Every client is compared, so
/// the time taken does not depend on which one matched.
pub fn authenticate<'a>(app: &'a App, headers: &HeaderMap) -> Option<&'a ClientConfig> {
    let token = headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;
    if token.is_empty() || token.len() > 4096 {
        return None;
    }
    let hash = sha256(token.as_bytes());
    let mut found = None;
    for client in app.clients() {
        if same_digest(&client.token_sha256, &hash) {
            found = Some(client);
        }
    }
    found
}

pub fn json_body(body: &str) -> Option<Map<String, Value>> {
    if body.len() > 8192 {
        return None;
    }
    serde_json::from_str::<Value>(body)
        .ok()?
        .as_object()
        .cloned()
}

pub fn public_base(app: &App) -> Result<reqwest::Url, StatusCode> {
    match &app.config.public_origin {
        Some(origin) => Ok(origin.clone()),
        None => reqwest::Url::parse("http://127.0.0.1:8787/")
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// `POST /v1/verifications` — a client starts an enrollment or a recovery.
pub async fn api_start(State(app): State<Arc<App>>, headers: HeaderMap, body: String) -> Response {
    let (core, store) = (Arc::clone(&app.core), &app.store);
    let Some(client) = authenticate(&app, &headers).cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };
    let Some(body) = json_body(&body) else {
        return api_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Some(flow) = body
        .get("flow")
        .and_then(Value::as_str)
        .and_then(WalletFlow::parse)
    else {
        return api_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Some(return_url) = body
        .get("return_url")
        .and_then(Value::as_str)
        .filter(|url| client.redirect_uris.iter().any(|allowed| allowed == url))
        .map(str::to_owned)
    else {
        return api_error(StatusCode::BAD_REQUEST, "invalid_return_url");
    };
    let Some(state) = body
        .get("state")
        .and_then(Value::as_str)
        .filter(|state| {
            !state.is_empty() && state.len() <= 512 && state.bytes().all(|b| b.is_ascii_graphic())
        })
        .map(str::to_owned)
    else {
        return api_error(StatusCode::BAD_REQUEST, "invalid_state");
    };
    let subject = match flow {
        WalletFlow::Enrollment => None,
        WalletFlow::Recovery => match body
            .get("client_subject")
            .and_then(Value::as_str)
            .and_then(|subject| Subject::parse(subject).ok())
        {
            Some(subject) => Some(subject),
            None => return api_error(StatusCode::BAD_REQUEST, "invalid_request"),
        },
    };
    let Ok(now) = timestamp() else {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    let pending = store.sweep(now).and_then(|()| store.pending(now));
    match pending {
        Ok(count) if count < MAX_PENDING as u64 => {}
        Ok(_) => return api_error(StatusCode::TOO_MANY_REQUESTS, "capacity"),
        Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    }
    let client_id = client.registration.client_id.clone();
    let lookup_client = client_id.clone();
    // The client's own pairwise subject is mapped back to the private profile here,
    // in-process; it never travels through the browser.
    let context = tokio::task::spawn_blocking(move || {
        let mut service = core.lock().map_err(|_| CoreError::Storage)?;
        let identity_flow = match subject {
            Some(subject) => IdentityFlow::Recovery {
                subject: service.profile_for_client_subject(&lookup_client, &subject)?,
            },
            None => IdentityFlow::Enrollment,
        };
        // The challenge carries this client's minimum age.
        service.begin_for_client(&lookup_client, identity_flow)
    })
    .await;
    let context = match context {
        Ok(Ok(context)) => context,
        Ok(Err(CoreError::SubjectNotFound)) => {
            return api_error(StatusCode::NOT_FOUND, "unknown_subject");
        }
        Ok(Err(error)) => {
            eprintln!("wohp: core begin failed: {error}");
            return api_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        }
        Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    let (Ok(id), Ok(base)) = (random_token(), public_base(&app)) else {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    let Ok(browser_url) = base.join(&format!("verify/{id}")) else {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    let expires_at = context.expires_at;
    let row = VerificationRow {
        client_id: client_id.as_str().to_owned(),
        flow: flow.as_str().to_owned(),
        return_url,
        state,
        challenge_id: context.challenge_id.clone(),
        nonce: context.nonce.clone(),
        audience: context.audience.clone(),
        expires_at,
        presentation: None,
        processing: false,
        redirect: None,
    };
    if store
        .insert_verification(&sha256(id.as_bytes()), &row)
        .is_err()
    {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    }
    eprintln!("wohp: {} started", flow.as_str());
    api_json(
        StatusCode::CREATED,
        &json!({
            "verification_id": id,
            "browser_url": browser_url.as_str(),
            "expires_at": expires_at,
        }),
    )
}

/// `POST /v1/verifications/redeem` — exchanges a one-time code for the result.
pub async fn api_redeem(State(app): State<Arc<App>>, headers: HeaderMap, body: String) -> Response {
    let store = &app.store;
    let Some(client) = authenticate(&app, &headers) else {
        return api_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };
    let Some(code) = json_body(&body).and_then(|body| {
        body.get("code")
            .and_then(Value::as_str)
            .filter(|code| opaque_id(code))
            .map(str::to_owned)
    }) else {
        return api_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Ok(now) = timestamp() else {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    // Single use: consumed whoever presents it.
    let grant = match store.redeem(&sha256(code.as_bytes()), now) {
        Ok(grant) => grant,
        Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    let Some(grant) =
        grant.filter(|grant| grant.client_id == client.registration.client_id.as_str())
    else {
        return api_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    api_json(
        StatusCode::OK,
        &json!({
            "flow": grant.flow,
            "kind": grant.kind,
            "client_subject": grant.client_subject,
            "authentication_epoch": grant.authentication_epoch,
            "age_at_least": grant.age_at_least,
            "age_valid_until": grant.age_valid_until,
            "evidence_class": evidence_class_name(app.evidence_class),
        }),
    )
}

/// Wire name of an evidence class: what a relying party may conclude about
/// the person behind a subject. Only `production` evidence is a verified human.
pub fn evidence_class_name(class: EvidenceClass) -> &'static str {
    match class {
        EvidenceClass::Production => "production",
        _ => "development",
    }
}

/// Most subjects in one batch status request (WOHP draft §10.1); 100
/// subjects stay well inside the 8 KiB body limit.
pub const MAX_STATUS_BATCH: usize = 100;

/// The fields of one status answer, shared by the single and batch forms.
pub fn status_fields(status: &BindingStatus) -> Map<String, Value> {
    let value = json!({
        "status": match status.status {
            IdentityStatus::Valid => "valid",
            IdentityStatus::RevalidationRequired => "revalidation_required",
            IdentityStatus::Revoked => "revoked",
            _ => "unknown",
        },
        "authentication_epoch": status.authentication_epoch,
        "age_at_least": status.age_at_least.map(AgeThreshold::years),
        "age_valid_until": status.age_valid_until,
        "valid_until": status.valid_until,
        "policy_version": status.policy_version,
        "evidence_class": evidence_class_name(status.evidence_class),
    });
    match value {
        Value::Object(fields) => fields,
        _ => Map::new(),
    }
}

/// The subjects of a status request: exactly one of `client_subject`
/// (single, the original form) and `client_subjects` (batch, 1 to 100).
pub fn status_request(body: &str) -> Option<(Vec<Subject>, bool)> {
    let body = json_body(body)?;
    match (body.get("client_subject"), body.get("client_subjects")) {
        (Some(single), None) => Some((vec![Subject::parse(single.as_str()?).ok()?], false)),
        (None, Some(Value::Array(list))) if (1..=MAX_STATUS_BATCH).contains(&list.len()) => {
            let subjects = list
                .iter()
                .map(|subject| Subject::parse(subject.as_str()?).ok())
                .collect::<Option<Vec<_>>>()?;
            Some((subjects, true))
        }
        _ => None,
    }
}

/// `POST /v1/subjects/status` — current status of subjects issued to the
/// caller: one (`client_subject`) or a batch (`client_subjects`, §10.1).
pub async fn api_subject_status(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let core = Arc::clone(&app.core);
    let Some(client) = authenticate(&app, &headers) else {
        return api_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };
    let Some((subjects, batch)) = status_request(&body) else {
        return api_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let client_id = client.registration.client_id.clone();
    let answers = tokio::task::spawn_blocking(move || {
        let core = core.lock().map_err(|_| CoreError::Storage)?;
        subjects
            .into_iter()
            .map(|subject| {
                match core.status_for_client(&client_id, &subject) {
                    Ok(status) => Ok((subject, Some(status))),
                    // Unknown, or issued to another client: indistinguishable.
                    Err(CoreError::SubjectNotFound) => Ok((subject, None)),
                    Err(error) => Err(error),
                }
            })
            .collect::<Result<Vec<_>, CoreError>>()
    })
    .await;
    let answers = match answers {
        Ok(Ok(answers)) => answers,
        Ok(Err(_)) => return api_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    if !batch {
        return match answers.into_iter().next() {
            Some((_, Some(status))) => {
                api_json(StatusCode::OK, &Value::Object(status_fields(&status)))
            }
            _ => api_error(StatusCode::NOT_FOUND, "unknown_subject"),
        };
    }
    let results: Vec<Value> = answers
        .into_iter()
        .map(|(subject, status)| {
            let mut entry = status.as_ref().map(status_fields).unwrap_or_else(|| {
                let mut unknown = Map::new();
                unknown.insert("error".into(), "unknown_subject".into());
                unknown
            });
            entry.insert("client_subject".into(), subject.as_str().into());
            Value::Object(entry)
        })
        .collect();
    api_json(StatusCode::OK, &json!({ "results": results }))
}

/// `POST /v1/subjects/revoke-authenticators` — the caller revoked this
/// person's authenticators: advance the authentication epoch (compromise
/// reset) so sessions bound to the old epoch end at every relying party.
pub async fn api_subject_reset(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let core = Arc::clone(&app.core);
    let Some(client) = authenticate(&app, &headers) else {
        return api_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };
    let Some(subject) = json_body(&body).and_then(|body| {
        body.get("client_subject")
            .and_then(Value::as_str)
            .and_then(|subject| Subject::parse(subject).ok())
    }) else {
        return api_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let client_id = client.registration.client_id.clone();
    let epoch = tokio::task::spawn_blocking(move || {
        core.lock()
            .map_err(|_| CoreError::Storage)?
            .reset_authenticators_for_client(&client_id, &subject)
    })
    .await;
    match epoch {
        Ok(Ok(epoch)) => {
            eprintln!("wohp: authenticators reset");
            api_json(StatusCode::OK, &json!({ "authentication_epoch": epoch }))
        }
        Ok(Err(CoreError::SubjectNotFound)) => api_error(StatusCode::NOT_FOUND, "unknown_subject"),
        Ok(Err(_)) => api_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    }
}
