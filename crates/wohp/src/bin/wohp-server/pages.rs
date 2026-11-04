//! Browser pages: the QR page, its status poll and the error pages.
use super::*;

/// Default look: black on white, no decoration.
const PLAIN_CSS: &str = r##"
:root{color-scheme:light;--ink:#000;--muted:#555;--line:#000;--page:#fff}
*{box-sizing:border-box}
body{min-height:100vh;display:flex;flex-direction:column;margin:0;background:var(--page);color:var(--ink);font:1rem/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--ink);text-underline-offset:.16em}
:focus-visible{outline:2px solid var(--ink);outline-offset:3px}
.site-header{border-bottom:1px solid var(--line)}
.header-inner{width:min(100%,56rem);margin-inline:auto;padding:.9rem 1rem;display:flex;align-items:baseline;justify-content:space-between;gap:1rem}
.brand{font-weight:700;letter-spacing:.04em}
.brand small{margin-left:.6rem;color:var(--muted);font-weight:400;letter-spacing:0}
.brand-symbol{display:none}
.header-badge{color:var(--muted);font-size:.8rem}
.shell{flex:1;width:min(100%,56rem);margin-inline:auto;padding:clamp(1.2rem,4vw,3rem) 1rem}
.eyebrow{margin:0 0 .3rem;color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.08em}
h1{margin:0 0 .7rem;font-size:clamp(1.5rem,3.5vw,2rem);line-height:1.15;font-weight:700}
.lead{max-width:60ch;margin:0 0 1.2rem}
.actions{display:flex;flex-wrap:wrap;gap:.6rem;margin-top:1rem}
button,.button{display:inline-flex;align-items:center;justify-content:center;min-height:2.6rem;padding:.55rem 1rem;border:1px solid var(--ink);border-radius:0;background:var(--ink);color:var(--page);font:inherit;font-weight:600;text-decoration:none;cursor:pointer}
button:hover,.button:hover{background:var(--page);color:var(--ink)}
button:disabled{opacity:.5;cursor:not-allowed}
.status-card{display:flex;align-items:center;gap:.6rem;margin:1rem 0;padding:.7rem .8rem;border:1px solid var(--line)}
.status-dot{width:.5rem;height:.5rem;flex:none;border-radius:50%;background:var(--ink);animation:blink 1.4s infinite}
@keyframes blink{50%{opacity:.2}}
.security-note{margin:1rem 0 0;color:var(--muted);font-size:.85rem}
.qr-layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.05fr);gap:clamp(1rem,3vw,2rem);align-items:center}
.qr-stage{display:grid;place-items:center;padding:1rem;border:1px solid var(--line);background:#fff}
.qr-stage svg{display:block;width:100%;max-width:22rem;height:auto;image-rendering:pixelated}
.footer{width:min(100%,56rem);margin:0 auto;padding:1rem;border-top:1px solid var(--line);color:var(--muted);font-size:.8rem}
@media(max-width:46rem){.qr-layout{grid-template-columns:1fr}.qr-stage{order:-1}.header-badge{display:none}.actions>*{width:100%}}
@media(prefers-reduced-motion:reduce){.status-dot{animation:none}}
"##;

/// Warm look, chosen per client with `theme: warm`.
const WARM_CSS: &str = r##"
:root{color-scheme:light;--ink:#292929;--muted:#68635f;--accent:#b54e35;--accent-dark:#913a27;--sun:#e69a67;--line:#e3dacf;--page:#f8f3ea;--surface:#fffdf8;--warm:#f4e8d8;--soft:#fae8d8;--peach:#f8dfca;--outline:#c5b6aa;--header:#292929}
*{box-sizing:border-box}
html{background:var(--page)}
body{min-height:100vh;display:flex;flex-direction:column;margin:0;background:radial-gradient(circle at 12% 0%,#fffaf2 0,transparent 32%),radial-gradient(circle at 88% 8%,#f7dfcf 0,transparent 28%),var(--page);color:var(--ink);font:1rem/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
a{color:var(--accent-dark);text-underline-offset:.16em}a:hover{color:var(--accent)}
:focus-visible{outline:3px solid var(--sun);outline-offset:3px}
.site-header{background:var(--header);color:#fff9ef;border-bottom:1px solid #1b1b1b}
.header-inner{width:min(100%,72rem);margin-inline:auto;padding:1rem 1.25rem;display:flex;align-items:center;justify-content:space-between;gap:1rem}
.brand{display:inline-flex;align-items:center;gap:.6rem;color:#fff9ef;font-size:1.15rem;font-weight:800;letter-spacing:.12em;line-height:1}
.brand small{display:block;margin-top:.25rem;color:#eac9a8;font-size:.56rem;font-weight:600;letter-spacing:.04em}
.brand-symbol{width:1.3rem;height:1.3rem;flex:none;border:2px solid var(--sun);border-radius:.2rem;position:relative;transform:rotate(45deg)}
.brand-symbol::before{content:"";position:absolute;inset:.2rem;border:1px solid #fff9ef;border-radius:.05rem}
.header-badge{padding:.3rem .6rem;border:1px solid rgb(255 255 255 / .22);border-radius:999px;color:#f8eee2;font-size:.72rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase}
.shell{flex:1;width:min(100%,56rem);margin-inline:auto;padding:clamp(1.2rem,4vw,3.5rem) 1rem}
.card{position:relative;overflow:hidden;padding:clamp(1.25rem,4vw,2.25rem);border:1px solid var(--line);border-top:4px solid var(--accent);border-radius:1.2rem;background:var(--surface);box-shadow:0 18px 50px rgb(41 41 41 / .10)}
.card::after{content:"";position:absolute;width:9rem;height:9rem;right:-4rem;bottom:-5.5rem;border:1.1rem solid rgb(181 78 53 / .10);border-radius:50%;box-shadow:0 0 0 1.1rem rgb(31 80 87 / .05);pointer-events:none}
.card>*{position:relative;z-index:1}
.eyebrow{margin:0 0 .4rem;color:var(--accent-dark);font-size:.72rem;font-weight:800;letter-spacing:.12em;text-transform:uppercase}
h1{margin:0 0 .7rem;font-size:clamp(1.8rem,4vw,2.7rem);line-height:1.08;letter-spacing:-.04em}
.lead{max-width:60ch;margin:0 0 1.2rem;color:var(--muted);font-size:1.02rem}
.notice{margin:1rem 0;padding:.8rem .9rem;border-left:3px solid var(--accent);border-radius:.55rem;background:var(--warm);color:var(--ink);font-size:.9rem}
.notice strong{color:var(--accent-dark)}
.pill,.account-chip{display:inline-flex;align-items:center;gap:.4rem;padding:.25rem .6rem;border:1px solid #d5ad90;border-radius:999px;background:var(--soft);color:var(--accent-dark);font-size:.76rem;font-weight:750}
.account-chip code{color:var(--ink);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.78rem}
.form-stack{display:grid;gap:.9rem;margin-top:1rem}
.field{display:grid;gap:.35rem}
.field label{font-size:.9rem;font-weight:750}
.field input{width:100%;min-height:2.8rem;padding:.65rem .8rem;border:1px solid var(--outline);border-radius:.7rem;background:#fff;color:var(--ink);font:inherit}
.field input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgb(181 78 53 / .12);outline:none}
.actions{display:flex;flex-wrap:wrap;gap:.6rem;align-items:center;margin-top:1rem}
button,.button{display:inline-flex;align-items:center;justify-content:center;min-height:2.7rem;max-width:100%;padding:.6rem 1rem;border:1px solid var(--accent);border-radius:.7rem;background:var(--accent);color:#fff;font:750 .92rem/1.2 Inter,ui-sans-serif,system-ui,sans-serif;text-align:center;text-decoration:none;cursor:pointer;box-shadow:0 3px rgb(31 41 45 / .16);transition:background .16s ease,border-color .16s ease,box-shadow .16s ease,transform .08s ease}
button:hover,.button:hover{border-color:var(--accent-dark);background:var(--accent-dark);color:#fff}
button:active,.button:active{box-shadow:none;transform:translateY(1px)}
button:disabled{opacity:.6;cursor:not-allowed}
.button-secondary{border-color:var(--accent);background:var(--soft);color:var(--ink);box-shadow:none}
.button-secondary:hover{border-color:var(--accent);background:var(--peach);color:var(--ink)}
.divider{display:flex;align-items:center;gap:.75rem;margin:1.2rem 0;color:var(--muted);font-size:.8rem;letter-spacing:.08em;text-transform:uppercase}
.divider::before,.divider::after{content:"";height:1px;flex:1;background:var(--line)}
.security-note{margin:1.1rem 0 0;color:var(--muted);font-size:.82rem}
.status-card{display:flex;align-items:center;gap:.65rem;margin:1rem 0;padding:.8rem .9rem;border:1px solid var(--line);border-radius:.8rem;background:var(--warm);color:var(--ink);font-weight:650}
.status-dot{width:.55rem;height:.55rem;flex:none;border-radius:50%;background:var(--accent);box-shadow:0 0 0 4px rgb(181 78 53 / .14);animation:pulse 1.6s infinite}
@keyframes pulse{50%{box-shadow:0 0 0 7px rgb(181 78 53 / .04)}}
.claim-list{display:grid;gap:.5rem;margin:1rem 0;padding:0;list-style:none}
.claim-list li{padding:.65rem .8rem;border:1px solid var(--line);border-radius:.65rem;background:var(--warm);font-size:.9rem}
.claim-list li::before{content:"✓";margin-right:.5rem;color:var(--accent);font-weight:900}
.qr-layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.05fr);gap:clamp(1rem,3vw,1.8rem);align-items:center}
.qr-stage{display:grid;place-items:center;padding:1rem;border:1px solid var(--line);border-radius:1rem;background:#fff;box-shadow:inset 0 0 0 6px var(--warm)}
.qr-stage svg{display:block;width:100%;max-width:22rem;height:auto;image-rendering:pixelated}
.qr-copy h1{font-size:clamp(1.6rem,3.5vw,2.3rem)}
.footer{width:min(100%,56rem);margin:0 auto;padding:0 1rem 2rem;color:var(--muted);font-size:.78rem;text-align:center}
.footer strong{color:var(--accent-dark)}
@media(max-width:46rem){.qr-layout{grid-template-columns:1fr}.qr-stage{order:-1}.header-badge{display:none}.actions>*{width:100%}}
@media(prefers-reduced-motion:reduce){.status-dot{animation:none}}
"##;

impl Theme {
    fn css(self) -> &'static str {
        match self {
            Self::Plain => PLAIN_CSS,
            Self::Warm => WARM_CSS,
        }
    }

    fn chrome(self) -> &'static str {
        match self {
            Self::Plain => "#ffffff",
            Self::Warm => "#292929",
        }
    }

    /// QR module and background colours.
    pub fn qr_colors(self) -> (&'static str, &'static str) {
        match self {
            Self::Plain => ("#000000", "#ffffff"),
            Self::Warm => ("#292929", "#fffdf8"),
        }
    }
}

/// How a page looks: the theme and brand of the client whose verification it
/// shows, or the server defaults when there is none.
#[derive(Clone, Copy)]
pub struct Look<'a> {
    pub theme: Theme,
    pub brand: &'a Brand,
}

impl App {
    pub fn look(&self, client_id: Option<&str>) -> Look<'_> {
        let client = client_id.and_then(|id| {
            self.config
                .core
                .clients
                .iter()
                .find(|client| client.registration.client_id.as_str() == id)
        });
        Look {
            theme: client.map_or(Theme::Plain, |client| client.theme),
            brand: client
                .and_then(|client| client.brand.as_ref())
                .unwrap_or(&self.config.brand),
        }
    }
}

pub fn page(look: Look<'_>, lang: Lang, body: &str) -> Response {
    let (brand, text) = (look.brand, lang.texts());
    let (css, chrome, code) = (look.theme.css(), look.theme.chrome(), text.code);
    let name = html_escape(&brand.name);
    let tagline = html_escape(brand.tagline.as_deref().unwrap_or(text.default_tagline));
    let notice = html_escape(brand.notice.as_deref().unwrap_or(text.default_notice));
    let title = html_escape(text.title);
    let html = format!(
        "<!doctype html><html lang={code}><head><meta charset=utf-8>\
         <meta name=viewport content='width=device-width, initial-scale=1'>\
         <meta name=robots content='noindex,nofollow'>\
         <meta name=theme-color content='{chrome}'>\
         <title>{title} · {name}</title><style>{css}</style></head>\
         <body><header class=site-header><div class=header-inner>\
         <span class=brand><span class=brand-symbol aria-hidden=true></span>\
         <span>{name}<small>{tagline}</small></span></span>\
         <span class=header-badge>Wallet</span></div></header>\
         <main class=shell><section class=card>{body}</section></main>\
         <footer class=footer>{name} · {notice}</footer>\
         </body></html>"
    );
    (
        [
            ("content-security-policy", CSP),
            ("cache-control", "no-store"),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "no-referrer"),
            ("content-language", code),
            ("vary", "accept-language"),
        ],
        Html(html),
    )
        .into_response()
}

/// A verification always starts at a registered client; there is nothing to do here.
pub async fn index(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    local_request(&headers, false, app.config.public_origin.as_ref())?;
    let lang = language(&headers);
    let text = lang.texts();
    Ok(page(
        app.look(None),
        lang,
        &format!(
            "<p class=eyebrow>{}</p><h1>{}</h1><p class=lead>{}</p>",
            html_escape(text.index_eyebrow),
            html_escape(text.index_heading),
            html_escape(text.index_lead)
        ),
    ))
}

pub fn verification_page(
    look: Look<'_>,
    lang: Lang,
    presentation: &PresentationRequest,
    flow: WalletFlow,
    verification_id: &str,
) -> Result<Response, StatusCode> {
    let wallet_link = html_escape(&presentation.url);
    let svg = qr_svg(&presentation.url, look.theme)?;
    let status_path = format!("/verify/{verification_id}/status");
    let text = lang.texts();
    let (eyebrow, lead, ready) = match flow {
        WalletFlow::Enrollment => (text.enroll_eyebrow, text.enroll_lead, text.enroll_ready),
        WalletFlow::Recovery => (text.recover_eyebrow, text.recover_lead, text.recover_ready),
    };
    // Catalogue texts are constants, but escaped like any other value: an
    // apostrophe in a translation must not end the single-quoted attribute.
    let [eyebrow, lead, ready, heading, open, waiting, note] = [
        eyebrow,
        lead,
        ready,
        text.scan_heading,
        text.open_wallet,
        text.waiting,
        text.security_note,
    ]
    .map(html_escape);
    Ok(page(
        look,
        lang,
        &format!(
            "<div class=qr-layout><div class=qr-stage>{svg}</div>\
             <div class=qr-copy><p class=eyebrow>{eyebrow}</p>\
             <h1>{heading}</h1>\
             <p class=lead>{lead}</p>\
             <div class=actions><a class=button href='{wallet_link}'>{open}</a></div>\
             <div class=status-card role=status aria-live=polite>\
             <span class=status-dot></span><span id=status data-poll='{status_path}' data-ready='{ready}'>{waiting}</span></div>\
             <p class=security-note>{note}</p></div></div>\
             <script src=/static/verify.js></script>"
        ),
    ))
}

/// The status poll of the QR page, served from this origin so the page
/// needs no inline script.
pub async fn verify_script() -> Response {
    (
        [
            ("content-type", "text/javascript; charset=utf-8"),
            ("cache-control", "no-cache"),
            ("x-content-type-options", "nosniff"),
        ],
        include_str!("verify.js"),
    )
        .into_response()
}

pub fn expired_page(look: Look<'_>, lang: Lang, back: &str) -> Response {
    let back = html_escape(back);
    let text = lang.texts();
    let mut response = page(
        look,
        lang,
        &format!(
            "<p class=eyebrow>{}</p><h1>{}</h1><p class=lead>{}</p>\
             <div class=actions><a class=button href='{back}'>{}</a></div>",
            html_escape(text.title),
            html_escape(text.expired_heading),
            html_escape(text.expired_lead),
            html_escape(text.back)
        ),
    );
    *response.status_mut() = StatusCode::GONE;
    response
}

/// Browser entry point created by `POST /v1/verifications`.
pub async fn verify_page(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, StatusCode> {
    local_request(&headers, false, app.config.public_origin.as_ref())?;
    if !opaque_id(&id) {
        return Err(StatusCode::NOT_FOUND);
    }
    let store = &app.store;
    let id_hash = sha256(id.as_bytes());
    let now = timestamp()?;
    let verification = store
        .verification(&id_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let flow = WalletFlow::parse(&verification.flow).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    if verification.expires_at <= now {
        let return_url = reqwest::Url::parse(&verification.return_url)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let back = return_with(
            &return_url,
            &[("error", "expired"), ("state", &verification.state)],
        );
        store
            .delete_verification(&id_hash)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Ok(expired_page(
            app.look(Some(&verification.client_id)),
            language(&headers),
            &back,
        ));
    }
    store
        .sweep(now)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let presentation = if let Some((id, url)) = verification.presentation {
        PresentationRequest { id, url }
    } else {
        let created = start_presentation(&app, &verification.nonce, &verification.audience).await?;
        // A concurrent reload may already have one: keep the first.
        match store
            .set_presentation(&id_hash, &created.id, &created.url)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            Some((kept, _)) if kept == created.id => created,
            Some((id, url)) => PresentationRequest { id, url },
            None => return Err(StatusCode::NOT_FOUND),
        }
    };
    verification_page(
        app.look(Some(&verification.client_id)),
        language(&headers),
        &presentation,
        flow,
        &id,
    )
}

pub async fn verify_status(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, StatusCode> {
    local_request(&headers, false, app.config.public_origin.as_ref())?;
    if !opaque_id(&id) {
        return Err(StatusCode::NOT_FOUND);
    }
    let store = &app.store;
    let id_hash = sha256(id.as_bytes());
    let claim = store
        .claim(&id_hash, timestamp()?)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let attempt = match claim {
        Claim::Missing => return Err(StatusCode::NOT_FOUND),
        Claim::Expired => return Err(StatusCode::GONE),
        Claim::Ready(redirect) => {
            return Ok(sandbox_response(
                json!({"state":"READY", "redirect":redirect}),
            ));
        }
        Claim::Pending => return Ok(sandbox_response(json!({"state":"PENDING"}))),
        Claim::Busy => return Ok(sandbox_response(json!({"state":"VERIFYING"}))),
        Claim::Claimed(row) => {
            Attempt::from_row(id_hash, *row).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
        }
    };
    match finish_verification(&app, store, &attempt).await {
        Ok(Finish::Pending) => {
            store
                .release(&id_hash)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(sandbox_response(json!({"state":"PENDING"})))
        }
        Ok(Finish::Ready(redirect)) => Ok(sandbox_response(
            json!({"state":"READY", "redirect":redirect}),
        )),
        Ok(Finish::Rejected(reason)) => {
            // The core consumed the challenge: the client starts a new one.
            store
                .delete_verification(&id_hash)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let restart = return_with(
                &attempt.return_url,
                &[("error", reason), ("state", &attempt.state)],
            );
            Ok(sandbox_response(
                json!({"state":"REJECTED", "reason":reason, "restart":restart}),
            ))
        }
        Err(error) => {
            let _ = store.delete_verification(&id_hash);
            Err(error)
        }
    }
}

pub fn sandbox_response(value: Value) -> Response {
    (
        [
            ("cache-control", "no-store"),
            ("content-type", "application/json"),
        ],
        value.to_string(),
    )
        .into_response()
}
