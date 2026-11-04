//! Calls to the EUDI Verifier Endpoint: transactions, QR and results.
use super::*;

pub async fn api(
    app: &App,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<(reqwest::StatusCode, Value), StatusCode> {
    let url = app
        .config
        .base
        .join(path)
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let mut request = app
        .client
        .request(method, url)
        .header("accept", "application/json");
    if let Some(token) = &app.config.token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    bounded_response(response).await
}

pub async fn bounded_response(
    mut response: reqwest::Response,
) -> Result<(reqwest::StatusCode, Value), StatusCode> {
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?
    {
        if chunk.len() > 65_536 - bytes.len() {
            return Err(StatusCode::BAD_GATEWAY);
        }
        bytes.extend_from_slice(&chunk);
    }
    let json = serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok((status, json))
}

#[derive(Clone)]
pub struct PresentationRequest {
    pub id: String,
    pub url: String,
}

/// Starts the verifier transaction for an already-issued nonce and renders the
/// QR. The returned client ID must match the core audience.
pub async fn start_presentation(
    app: &App,
    nonce: &str,
    audience: &str,
) -> Result<PresentationRequest, StatusCode> {
    let mdoc = app.config.credential_format == "mdoc";
    let dcql_query = sandbox_dcql(mdoc, app.config.request_pan);
    let (status, transaction) = api(
        app,
        reqwest::Method::POST,
        "ui/presentations/v2",
        Some(json!({
            "dcql_query": dcql_query,
            "nonce": nonce,
            "profile": app.config.profile,
            "jar_mode": "by_reference",
            "request_uri_method": "get",
            "response_mode": app.config.response_mode,
            "authorization_request_scheme": "openid4vp",
            "intended_use_id": app.config.intended_use_id,
        })),
    )
    .await?;
    if !status.is_success() {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let id = transaction
        .get("transaction_id")
        .and_then(Value::as_str)
        .filter(|s| opaque_id(s))
        .ok_or(StatusCode::BAD_GATEWAY)?
        .to_owned();
    let client_id = transaction
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or(StatusCode::BAD_GATEWAY)?;
    let request_uri = transaction
        .get("request_uri")
        .and_then(Value::as_str)
        .ok_or(StatusCode::BAD_GATEWAY)?;
    if !client_id.starts_with("x509_hash:")
        || transaction
            .get("request_uri_method")
            .and_then(Value::as_str)
            != Some("get")
        || !request_uri.starts_with("https://")
    {
        return Err(StatusCode::BAD_GATEWAY);
    }
    if audience != client_id {
        // The configured audience is what the core binds every presentation to.
        eprintln!("wohp: verifier client_id {client_id} differs from WOHP_VERIFIER_CLIENT_ID");
        return Err(StatusCode::BAD_GATEWAY);
    }
    let url = transaction
        .get("authorization_request_uri")
        .and_then(Value::as_str)
        .ok_or(StatusCode::BAD_GATEWAY)?;
    if url.len() > 4096 || !url.starts_with("openid4vp://?") {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let parsed = reqwest::Url::parse(url).map_err(|_| StatusCode::BAD_GATEWAY)?;
    if !parsed
        .query_pairs()
        .any(|(k, v)| k == "client_id" && v == client_id)
        || !parsed
            .query_pairs()
            .any(|(k, v)| k == "request_uri" && v == request_uri)
    {
        return Err(StatusCode::BAD_GATEWAY);
    }
    Ok(PresentationRequest {
        id,
        url: url.to_owned(),
    })
}

pub fn qr_svg(url: &str, theme: Theme) -> Result<String, StatusCode> {
    let qr = QrCode::new(url.as_bytes()).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let (dark, light) = theme.qr_colors();
    Ok(qr
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(320, 320)
        .dark_color(qrcode::render::svg::Color(dark))
        .light_color(qrcode::render::svg::Color(light))
        .build())
}

/// What the wallet is asked for. Raw values are only used in memory by the core's
/// provider to derive a keyed hash and an age threshold; nothing is stored.
pub fn sandbox_dcql(mdoc: bool, request_pan: bool) -> Value {
    let (format, meta, path_prefix, names, pan) = if mdoc {
        (
            "mso_mdoc",
            json!({ "doctype_value": PID_DOCTYPE }),
            vec![PID_DOCTYPE],
            [
                "issuing_country",
                "family_name",
                "given_name",
                "birth_date",
                "place_of_birth",
            ],
            "administrative_number",
        )
    } else {
        (
            "dc+sd-jwt",
            json!({ "vct_values": [PID_VCT] }),
            Vec::new(),
            [
                "issuing_country",
                "family_name",
                "given_name",
                "birthdate",
                "place_of_birth",
            ],
            "personal_administrative_number",
        )
    };
    let claim = |id: &str, name: &str| {
        let mut path = path_prefix.clone();
        path.push(name);
        json!({ "id": id, "path": path })
    };
    let mut claims: Vec<Value> = names
        .iter()
        .enumerate()
        .map(|(index, name)| claim(&format!("c{index}"), name))
        .collect();
    let mut credential = json!({ "id": "pid", "format": format, "meta": meta });
    if request_pan {
        // Optional: preferred set first, the wallet may fall back to the attributes.
        let required: Vec<String> = (0..claims.len()).map(|index| format!("c{index}")).collect();
        let mut preferred = required.clone();
        preferred.push("pan".into());
        claims.push(claim("pan", pan));
        credential["claim_sets"] = json!([preferred, required]);
    }
    credential["claims"] = Value::Array(claims);
    json!({ "credentials": [credential] })
}

pub async fn finish_verification(
    app: &App,
    store: &Store,
    attempt: &Attempt,
) -> Result<Finish, StatusCode> {
    let (code, response) = api(
        app,
        reqwest::Method::GET,
        &format!("ui/presentations/{}", attempt.presentation_id),
        None,
    )
    .await?;
    if code == reqwest::StatusCode::BAD_REQUEST && response["error"] == "PresentationNotSubmitted" {
        return Ok(Finish::Pending);
    }
    if code != reqwest::StatusCode::OK {
        eprintln!("wohp: verifier result HTTP {}", code.as_u16());
        return Err(StatusCode::BAD_GATEWAY);
    }
    let token = response
        .get("vp_token")
        .and_then(|value| value.get("pid"))
        .and_then(|value| {
            value
                .as_array()
                .and_then(|tokens| tokens.first())
                .or(Some(value))
        })
        .and_then(Value::as_str)
        .ok_or_else(|| {
            eprintln!("wohp: verifier result without vp_token.pid");
            StatusCode::BAD_GATEWAY
        })?;
    let presentation = if app.config.credential_format == "mdoc" {
        mdoc_presentation(token)
    } else {
        sd_jwt_presentation(token)
    }
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let core = Arc::clone(&app.core);
    let (challenge_id, flow, client) = (
        attempt.challenge_id.clone(),
        attempt.flow,
        attempt.client_id.clone(),
    );
    let accepted = tokio::task::spawn_blocking(move || {
        accept_in_core(&core, &challenge_id, &presentation, flow, &client)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let accepted = match accepted {
        Ok(accepted) => accepted,
        Err(error) => {
            // Categorical outcome only: no subject, nonce, claim or token.
            eprintln!(
                "wohp: {} rejected: {}",
                attempt.flow.as_str(),
                rejection(error)
            );
            return Ok(Finish::Rejected(rejection(error)));
        }
    };
    let code = random_token()?;
    let now = timestamp()?;
    let redirect = return_with(
        &attempt.return_url,
        &[("code", &code), ("state", &attempt.state)],
    );
    let grant = GrantRow {
        client_id: attempt.client_id.as_str().to_owned(),
        flow: attempt.flow.as_str().to_owned(),
        kind: accepted.kind.to_owned(),
        client_subject: accepted.client_subject,
        authentication_epoch: accepted.authentication_epoch,
        age_at_least: accepted.age_at_least,
        age_valid_until: accepted.age_valid_until,
        expires_at: now + CODE_TTL_SECONDS,
    };
    let stored = store
        .complete(
            &attempt.id_hash,
            &sha256(code.as_bytes()),
            &grant,
            &redirect,
            MAX_PENDING as u64,
            now,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !stored {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    eprintln!(
        "wohp: {} completed: {}",
        attempt.flow.as_str(),
        accepted.kind
    );
    Ok(Finish::Ready(redirect))
}
