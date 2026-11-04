use super::*;

use axum::body::to_bytes;
use std::{
    collections::HashMap,
    future::Future,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};
use wohp_eudi::fake::FakeVerifier;

const ID: &str = "test-transaction_123";
const AUDIENCE: &str = "x509_hash:test-verifier";
const IDP_TOKEN: &str = "first-party-idp-token-0123456789abcdef";
const OTHER_TOKEN: &str = "other-relying-party-token-0123456789ab";
const RETURN: &str = "http://localhost:5556/wallet/return";
const OTHER_RETURN: &str = "https://rp.example/return";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("host", "127.0.0.1:8787".parse().unwrap());
    headers.insert("origin", "http://127.0.0.1:8787".parse().unwrap());
    headers
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("host", "wohp:8787".parse().unwrap());
    headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
    headers
}

fn run<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

fn url(value: &str) -> reqwest::Url {
    reqwest::Url::parse(value).unwrap()
}

fn test_config(base: &str, core: CoreSettings) -> Config {
    Config {
        base: url(base),
        token: None,
        intended_use_id: "TEST-01".into(),
        public_origin: None,
        credential_format: "sd-jwt".into(),
        profile: "haip".into(),
        response_mode: "direct_post.jwt".into(),
        request_pan: false,
        brand: Brand {
            name: "TestBrand".into(),
            tagline: Some("Tagline".into()),
            notice: Some("Notice".into()),
        },
        core,
    }
}

fn app(config: Config, core: Core) -> App {
    let store = Store::open(&config.core.server_database, timestamp().unwrap()).unwrap();
    App::new(
        Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        config,
        core,
        store,
    )
}

fn test_clients() -> Vec<ClientConfig> {
    vec![
        client_config(
            "first-party-idp",
            "idp.network",
            Some(AgeThreshold::Sixteen),
            vec![RETURN.into()],
            sha256(IDP_TOKEN.as_bytes()),
        )
        .unwrap(),
        ClientConfig {
            theme: Theme::Warm,
            brand: Some(Brand {
                name: "OtherBrand".into(),
                tagline: Some("Other tagline".into()),
                notice: Some("other notice".into()),
            }),
            ..client_config(
                "other-rp",
                "other.network",
                Some(AgeThreshold::Eighteen),
                vec![OTHER_RETURN.into()],
                sha256(OTHER_TOKEN.as_bytes()),
            )
            .unwrap()
        },
    ]
}

/// A real core in a throwaway directory, validating against a fake verifier.
/// Built and dropped outside the async runtime, like in `main`.
struct TestCore {
    core: Core,
    verifier: FakeVerifier,
    directory: PathBuf,
    mdoc: bool,
}

fn core_settings(directory: &FsPath) -> CoreSettings {
    CoreSettings {
        database: directory.join("identity.sqlite3"),
        key_file: directory.join("lookup.key"),
        server_database: directory.join("server.sqlite3"),
        verifier_client_id: AUDIENCE.into(),
        window_seconds: DEFAULT_WINDOW_SECONDS,
        clients: test_clients(),
    }
}

impl TestCore {
    fn new(mdoc: bool) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "wohp-server-test-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let verifier = FakeVerifier::start();
        let mut config = test_config(verifier.origin(), core_settings(&directory));
        config.credential_format = if mdoc { "mdoc" } else { "sd-jwt" }.into();
        let core = open_core(&config, &config.core).unwrap();
        Self {
            core,
            verifier,
            directory,
            mdoc,
        }
    }

    fn settings(&self) -> CoreSettings {
        core_settings(&self.directory)
    }

    fn humans(&self) -> u64 {
        rusqlite::Connection::open(self.directory.join("identity.sqlite3"))
            .unwrap()
            .query_row("SELECT count(*) FROM humans", [], |row| row.get(0))
            .unwrap()
    }

    /// A second connection to the server file, as another process would see it.
    fn server_db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.directory.join("server.sqlite3")).unwrap()
    }

    fn rows(&self, table: &str) -> u64 {
        self.server_db()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }
}

impl Drop for TestCore {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

type Posted = Arc<Mutex<Vec<Value>>>;

/// The EUDI verifier management API: one transaction per request, and a
/// presentation token `token-<transaction>` once the wallet has answered.
async fn upstream(client_id: &'static str) -> (u16, Posted, tokio::task::JoinHandle<()>) {
    let posted = Posted::default();
    let recorder = posted.clone();
    let counter = Arc::new(AtomicUsize::new(0));
    let router = Router::new()
        .route(
            "/ui/presentations/v2",
            post(move |body: String| {
                let recorder = recorder.clone();
                let counter = counter.clone();
                async move {
                    recorder
                        .lock()
                        .unwrap()
                        .push(serde_json::from_str::<Value>(&body).unwrap());
                    let id = format!("tx-{}", counter.fetch_add(1, Ordering::SeqCst));
                    (
                        [("content-type", "application/json")],
                        json!({
                            "transaction_id": id,
                            "client_id": client_id,
                            "request_uri_method": "get",
                            "request_uri": "https://verifier.example/wallet/request.jwt/test",
                            "authorization_request_uri": format!(
                                "openid4vp://?client_id={}&request_uri=https%3A%2F%2Fverifier.example%2Fwallet%2Frequest.jwt%2Ftest&request_uri_method=get",
                                client_id.replace(':', "%3A")
                            ),
                        })
                        .to_string(),
                    )
                }
            }),
        )
        .route(
            "/ui/presentations/{id}",
            get(|Path(id): Path<String>| async move {
                (
                    [("content-type", "application/json")],
                    json!({"vp_token":{"pid":[format!("token-{id}")]}}).to_string(),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (port, posted, server)
}

fn server(port: u16, test: &TestCore) -> Arc<App> {
    let mut config = test_config(&format!("http://127.0.0.1:{port}/"), test.settings());
    config.credential_format = if test.mdoc { "mdoc" } else { "sd-jwt" }.into();
    Arc::new(app(config, test.core.clone()))
}

async fn read(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn start(app: &Arc<App>, token: &str, body: Value) -> (StatusCode, Value) {
    read(api_start(State(app.clone()), bearer(token), body.to_string()).await).await
}

async fn redeem(app: &Arc<App>, token: &str, code: &str) -> (StatusCode, Value) {
    let body = json!({ "code": code }).to_string();
    read(api_redeem(State(app.clone()), bearer(token), body).await).await
}

async fn status_of(app: &Arc<App>, token: &str, subject: &Value) -> (StatusCode, Value) {
    let body = json!({ "client_subject": subject }).to_string();
    read(api_subject_status(State(app.clone()), bearer(token), body).await).await
}

async fn reset_of(app: &Arc<App>, token: &str, subject: &Value) -> (StatusCode, Value) {
    let body = json!({ "client_subject": subject }).to_string();
    read(api_subject_reset(State(app.clone()), bearer(token), body).await).await
}

fn enroll(state: &str) -> Value {
    json!({"flow": "enroll", "return_url": RETURN, "state": state})
}

async fn open_page(app: &Arc<App>, id: &str) -> String {
    let response = verify_page(State(app.clone()), headers(), Path(id.into()))
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}

fn row(app: &App, id: &str) -> VerificationRow {
    app.store
        .verification(&sha256(id.as_bytes()))
        .unwrap()
        .unwrap()
}

fn transaction(app: &App, id: &str) -> String {
    row(app, id).presentation.unwrap().0
}

/// The wallet answers the QR of this verification with these claims.
fn present(test: &TestCore, app: &App, id: &str, claims: &Value) {
    let verification = row(app, id);
    test.verifier.issue(
        &format!("token-{}", verification.presentation.unwrap().0),
        claims,
        &verification.nonce,
        &verification.audience,
    );
}

async fn poll(app: &Arc<App>, id: &str) -> Value {
    let response = verify_status(State(app.clone()), headers(), Path(id.into()))
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 8192).await.unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        !text.contains("token-"),
        "presentation leaked to the browser"
    );
    serde_json::from_slice(&body).unwrap()
}

/// Start, open the QR, answer it with `claims`, poll once.
async fn journey(
    test: &TestCore,
    app: &Arc<App>,
    token: &str,
    body: Value,
    claims: &Value,
) -> (String, Value) {
    let (status, started) = start(app, token, body).await;
    assert_eq!(status, StatusCode::CREATED, "{started}");
    let id = started["verification_id"].as_str().unwrap().to_owned();
    assert_eq!(
        started["browser_url"],
        format!("http://127.0.0.1:8787/verify/{id}")
    );
    open_page(app, &id).await;
    present(test, app, &id, claims);
    (id.clone(), poll(app, &id).await)
}

fn query(redirect: &str) -> HashMap<String, String> {
    url(redirect).query_pairs().into_owned().collect()
}

fn born(age: u64) -> String {
    format!("{}-01-01", 1970 + timestamp().unwrap() / 31_556_952 - age)
}

fn pid(person: &str, age: u64) -> Value {
    json!({
        "vct": PID_VCT, "exp": timestamp().unwrap() + 86_400,
        "issuing_country": "IT", "family_name": format!("Family {person}"),
        "given_name": format!("Given {person}"), "birthdate": born(age),
        "place_of_birth": {"country": "IT", "locality": "Roma"},
    })
}

#[test]
fn clients_authenticate_and_may_only_return_to_registered_urls() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let body = enroll("state-1").to_string();
        let unauthenticated =
            read(api_start(State(app.clone()), headers(), body.clone()).await).await;
        assert_eq!(unauthenticated.0, StatusCode::UNAUTHORIZED);
        assert_eq!(
            start(&app, "not-a-registered-token-0123456789", enroll("s"))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        for (bad, error) in [
            (
                json!({"flow": "enroll", "return_url": OTHER_RETURN, "state": "s"}),
                "invalid_return_url",
            ),
            (
                json!({"flow": "enroll", "return_url": format!("{RETURN}?x=1"), "state": "s"}),
                "invalid_return_url",
            ),
            (
                json!({"flow": "enroll", "return_url": RETURN, "state": ""}),
                "invalid_state",
            ),
            (
                json!({"flow": "enroll", "return_url": RETURN, "state": "a b"}),
                "invalid_state",
            ),
            (
                json!({"flow": "login", "return_url": RETURN, "state": "s"}),
                "invalid_request",
            ),
            (
                json!({"flow": "recover", "return_url": RETURN, "state": "s"}),
                "invalid_request",
            ),
        ] {
            let (status, value) = start(&app, IDP_TOKEN, bad.clone()).await;
            assert_eq!(
                (status, value["error"].as_str()),
                (StatusCode::BAD_REQUEST, Some(error)),
                "{bad}"
            );
        }
        let unknown = json!({"flow": "recover", "return_url": RETURN, "state": "s",
                             "client_subject": "A".repeat(42) + "A"});
        assert_eq!(
            start(&app, IDP_TOKEN, unknown).await.0,
            StatusCode::NOT_FOUND
        );
        let (status, started) = start(&app, IDP_TOKEN, enroll("state-1")).await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(started["expires_at"].as_u64().unwrap() > timestamp().unwrap());
        upstream.abort();
    });
}

#[test]
fn enrollment_returns_a_single_use_code_redeemable_only_by_its_client() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let (id, value) = journey(
            &test,
            &app,
            IDP_TOKEN,
            enroll("opaque-state"),
            &pid("alice", 30),
        )
        .await;
        assert_eq!(value["state"], "READY");
        let redirect = value["redirect"].as_str().unwrap();
        assert!(redirect.starts_with(&format!("{RETURN}?code=")));
        let params = query(redirect);
        assert_eq!(params["state"], "opaque-state");
        // Polling again returns the same redirect; nothing is redone.
        assert_eq!(poll(&app, &id).await["redirect"], redirect);

        let (status, result) = redeem(&app, IDP_TOKEN, &params["code"]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(result["flow"], "enroll");
        assert_eq!(result["kind"], "created");
        assert_eq!(result["authentication_epoch"], 1);
        assert_eq!(result["age_at_least"], 18);
        assert!(result["age_valid_until"].as_u64().unwrap() > timestamp().unwrap());
        let subject = result["client_subject"].as_str().unwrap();
        assert!(Subject::parse(subject).is_ok());
        assert!(!redirect.contains(subject));
        let text = result.to_string();
        assert!(!text.contains("Family") && !text.contains("birthdate"));
        assert_eq!(result["evidence_class"], "development");
        assert_eq!(result.as_object().unwrap().len(), 7);

        // Single use, and never for another client.
        assert_eq!(
            redeem(&app, IDP_TOKEN, &params["code"]).await.0,
            StatusCode::BAD_REQUEST
        );
        let (_, second) = journey(&test, &app, IDP_TOKEN, enroll("s2"), &pid("bob", 30)).await;
        let stolen = query(second["redirect"].as_str().unwrap())["code"].clone();
        assert_eq!(
            redeem(&app, OTHER_TOKEN, &stolen).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            redeem(&app, IDP_TOKEN, &stolen).await.0,
            StatusCode::BAD_REQUEST
        );
        upstream.abort();
    });
    assert_eq!(test.humans(), 2);
}

#[test]
fn the_same_person_gets_one_profile_and_a_pairwise_subject_per_client() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let mut results = Vec::new();
        for (token, return_url) in [
            (IDP_TOKEN, RETURN),
            (IDP_TOKEN, RETURN),
            (OTHER_TOKEN, OTHER_RETURN),
        ] {
            let body = json!({"flow": "enroll", "return_url": return_url, "state": "s"});
            let (_, value) = journey(&test, &app, token, body, &pid("alice", 30)).await;
            let code = query(value["redirect"].as_str().unwrap())["code"].clone();
            results.push(redeem(&app, token, &code).await.1);
        }
        assert_eq!(results[0]["kind"], "created");
        assert_eq!(results[1]["kind"], "existing");
        assert_eq!(results[0]["client_subject"], results[1]["client_subject"]);
        assert_eq!(results[2]["kind"], "existing");
        assert_ne!(results[2]["client_subject"], results[0]["client_subject"]);
        upstream.abort();
    });
    assert_eq!(test.humans(), 1);
}

#[test]
fn recovery_is_started_by_the_client_with_its_own_subject() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let (_, value) = journey(&test, &app, IDP_TOKEN, enroll("s"), &pid("alice", 30)).await;
        let code = query(value["redirect"].as_str().unwrap())["code"].clone();
        let enrolled = redeem(&app, IDP_TOKEN, &code).await.1;
        let subject = enrolled["client_subject"].clone();

        // Another client cannot recover through a subject it was not issued.
        let foreign = json!({"flow": "recover", "return_url": OTHER_RETURN, "state": "s",
                             "client_subject": subject});
        assert_eq!(
            start(&app, OTHER_TOKEN, foreign).await.0,
            StatusCode::NOT_FOUND
        );

        let body = json!({"flow": "recover", "return_url": RETURN, "state": "r",
                          "client_subject": subject});
        let (_, value) = journey(&test, &app, IDP_TOKEN, body, &pid("alice", 30)).await;
        assert_eq!(value["state"], "READY");
        let code = query(value["redirect"].as_str().unwrap())["code"].clone();
        let (status, recovered) = redeem(&app, IDP_TOKEN, &code).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(recovered["flow"], "recover");
        assert_eq!(recovered["kind"], "recovered");
        assert_eq!(recovered["client_subject"], subject);
        assert_eq!(recovered["authentication_epoch"], 2);

        // Somebody else's wallet cannot recover this account.
        let body = json!({"flow": "recover", "return_url": RETURN, "state": "x",
                          "client_subject": subject});
        let (_, refused) = journey(&test, &app, IDP_TOKEN, body, &pid("mallory", 30)).await;
        assert_eq!(refused["state"], "REJECTED");
        upstream.abort();
    });
    assert_eq!(test.humans(), 1);
}

#[test]
fn refusals_send_the_browser_back_with_an_error_and_the_state() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let (id, value) = journey(&test, &app, IDP_TOKEN, enroll("young"), &pid("kid", 10)).await;
        assert_eq!(value["state"], "REJECTED");
        assert_eq!(value["reason"], "underage");
        assert_eq!(
            value["restart"],
            format!("{RETURN}?error=underage&state=young")
        );
        // The verification is over.
        assert_eq!(
            verify_status(State(app.clone()), headers(), Path(id))
                .await
                .unwrap_err(),
            StatusCode::NOT_FOUND
        );

        let mut ambiguous = pid("anon", 30);
        ambiguous.as_object_mut().unwrap().remove("family_name");
        assert_eq!(
            journey(&test, &app, IDP_TOKEN, enroll("a"), &ambiguous)
                .await
                .1["reason"],
            "ambiguous"
        );

        let mut expired = pid("old", 30);
        expired["exp"] = json!(timestamp().unwrap() - 10);
        assert_eq!(
            journey(&test, &app, IDP_TOKEN, enroll("e"), &expired)
                .await
                .1["reason"],
            "invalid"
        );

        // A token bound to another verification's nonce is refused.
        let (_, first) = start(&app, IDP_TOKEN, enroll("one")).await;
        let (_, second) = start(&app, IDP_TOKEN, enroll("two")).await;
        let (first, second) = (
            first["verification_id"].as_str().unwrap(),
            second["verification_id"].as_str().unwrap(),
        );
        open_page(&app, first).await;
        open_page(&app, second).await;
        let other = row(&app, second);
        test.verifier.issue(
            &format!("token-{}", transaction(&app, first)),
            &pid("alice", 30),
            &other.nonce,
            &other.audience,
        );
        assert_eq!(poll(&app, first).await["reason"], "invalid");

        test.verifier.force_status(Some(503));
        assert_eq!(
            journey(&test, &app, IDP_TOKEN, enroll("down"), &pid("bob", 30))
                .await
                .1["reason"],
            "unavailable"
        );
        test.verifier.force_status(None);
        assert_eq!(test.rows("grants"), 0);
        upstream.abort();
    });
    assert_eq!(test.humans(), 0);
}

#[test]
fn subject_status_is_visible_only_to_the_issuing_client() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let (_, value) = journey(&test, &app, IDP_TOKEN, enroll("s"), &pid("alice", 30)).await;
        let code = query(value["redirect"].as_str().unwrap())["code"].clone();
        let subject = redeem(&app, IDP_TOKEN, &code).await.1["client_subject"].clone();

        let (status, current) = status_of(&app, IDP_TOKEN, &subject).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(current["status"], "valid");
        assert_eq!(current["authentication_epoch"], 1);
        assert_eq!(current["age_at_least"], 18);
        assert_eq!(current["policy_version"], wohp_eudi::POLICY_VERSION);
        assert_eq!(current["evidence_class"], "development");
        assert_eq!(
            status_of(&app, OTHER_TOKEN, &subject).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status_of(&app, "nope-0123456789-0123456789-01234", &subject)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status_of(&app, IDP_TOKEN, &json!("not-a-subject")).await.0,
            StatusCode::BAD_REQUEST
        );
        upstream.abort();
    });
}

async fn status_batch(app: &Arc<App>, token: &str, body: Value) -> (StatusCode, Value) {
    read(api_subject_status(State(app.clone()), bearer(token), body.to_string()).await).await
}

#[test]
fn batch_status_answers_in_order_without_disclosing_and_keeps_the_single_form() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let (_, value) = journey(&test, &app, IDP_TOKEN, enroll("s"), &pid("alice", 30)).await;
        let code = query(value["redirect"].as_str().unwrap())["code"].clone();
        let alice = redeem(&app, IDP_TOKEN, &code).await.1["client_subject"].clone();
        let unknown = json!("A".repeat(43));

        let (_, single) = status_of(&app, IDP_TOKEN, &alice).await;
        assert!(
            single.get("client_subject").is_none(),
            "the single answer is unchanged"
        );
        let (status, batch) = status_batch(
            &app,
            IDP_TOKEN,
            json!({"client_subjects": [unknown, alice, alice]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let results = batch["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(
            results[0],
            json!({"client_subject": unknown, "error": "unknown_subject"})
        );
        let mut known = results[1].clone();
        assert_eq!(known["client_subject"], alice);
        known.as_object_mut().unwrap().remove("client_subject");
        assert_eq!(
            known, single,
            "a batch entry carries the single answer's fields"
        );
        assert_eq!(results[2], results[1]);

        // Another client sees the same answer as for a subject that does not exist.
        let (_, foreign) = status_batch(
            &app,
            OTHER_TOKEN,
            json!({"client_subjects": [alice, unknown]}),
        )
        .await;
        assert_eq!(foreign["results"][0]["error"], "unknown_subject");
        assert_eq!(
            foreign["results"][0].as_object().unwrap().len(),
            foreign["results"][1].as_object().unwrap().len()
        );

        let too_many: Vec<Value> = (0..=MAX_STATUS_BATCH).map(|_| alice.clone()).collect();
        let full: Vec<Value> = (0..MAX_STATUS_BATCH).map(|_| alice.clone()).collect();
        assert_eq!(
            status_batch(&app, IDP_TOKEN, json!({"client_subjects": full}))
                .await
                .0,
            StatusCode::OK
        );
        for bad in [
            json!({"client_subjects": []}),
            json!({"client_subjects": too_many}),
            json!({"client_subjects": [alice, "not-a-subject"]}),
            json!({"client_subjects": alice}),
            json!({"client_subject": alice, "client_subjects": [alice]}),
            json!({}),
        ] {
            assert_eq!(
                status_batch(&app, IDP_TOKEN, bad).await.0,
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            status_batch(
                &app,
                "nope-0123456789-0123456789-01234",
                json!({"client_subjects": [alice]})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        upstream.abort();
    });
}

/// Status throughput through the handler, the service lock and SQLite
/// (Bootstrap scale plan, phase 1). One hot subject: an upper bound.
///     cargo test --release -p wohp --bin wohp-server status_throughput -- --ignored --nocapture
#[test]
#[ignore = "measurement"]
fn status_throughput() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let (_, value) = journey(&test, &app, IDP_TOKEN, enroll("s"), &pid("alice", 30)).await;
        let code = query(value["redirect"].as_str().unwrap())["code"].clone();
        let subject = redeem(&app, IDP_TOKEN, &code).await.1["client_subject"].clone();
        for concurrency in [1_usize, 8] {
            let calls = 5_000;
            let started = std::time::Instant::now();
            let mut tasks = tokio::task::JoinSet::new();
            for worker in 0..concurrency {
                let (app, subject) = (app.clone(), subject.clone());
                tasks.spawn(async move {
                    for _ in (worker..calls).step_by(concurrency) {
                        assert_eq!(status_of(&app, IDP_TOKEN, &subject).await.0, StatusCode::OK);
                    }
                });
            }
            while let Some(done) = tasks.join_next().await {
                done.unwrap();
            }
            let seconds = started.elapsed().as_secs_f64();
            println!(
                "status concurrency {concurrency}: {calls} calls in {seconds:.2} s, {:.0}/s",
                calls as f64 / seconds
            );
        }
        let batch: Vec<Value> = (0..MAX_STATUS_BATCH).map(|_| subject.clone()).collect();
        let requests = 100;
        let started = std::time::Instant::now();
        for _ in 0..requests {
            let (status, _) =
                status_batch(&app, IDP_TOKEN, json!({"client_subjects": batch})).await;
            assert_eq!(status, StatusCode::OK);
        }
        let seconds = started.elapsed().as_secs_f64();
        println!(
            "batch of {MAX_STATUS_BATCH}: {requests} requests in {seconds:.2} s, {:.0} subjects/s",
            (requests * MAX_STATUS_BATCH) as f64 / seconds
        );
        upstream.abort();
    });
}

#[test]
fn revoking_authenticators_advances_the_epoch_for_the_issuing_client_only() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let (_, value) = journey(&test, &app, IDP_TOKEN, enroll("s"), &pid("alice", 30)).await;
        let code = query(value["redirect"].as_str().unwrap())["code"].clone();
        let subject = redeem(&app, IDP_TOKEN, &code).await.1["client_subject"].clone();

        assert_eq!(
            reset_of(&app, OTHER_TOKEN, &subject).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            reset_of(&app, "nope-0123456789-0123456789-01234", &subject)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            reset_of(&app, IDP_TOKEN, &json!("not-a-subject")).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_of(&app, IDP_TOKEN, &subject).await.1["authentication_epoch"],
            1
        );

        // A recovery started before the reset is cancelled by it.
        let body = json!({"flow": "recover", "return_url": RETURN, "state": "early",
                          "client_subject": subject});
        let (status, started) = start(&app, IDP_TOKEN, body).await;
        assert_eq!(status, StatusCode::CREATED);
        let early = started["verification_id"].as_str().unwrap().to_owned();
        open_page(&app, &early).await;

        let (status, reset) = reset_of(&app, IDP_TOKEN, &subject).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reset["authentication_epoch"], 2);
        let (_, current) = status_of(&app, IDP_TOKEN, &subject).await;
        assert_eq!(current["status"], "valid");
        assert_eq!(current["authentication_epoch"], 2);

        present(&test, &app, &early, &pid("alice", 30));
        assert_ne!(poll(&app, &early).await["state"], "READY");

        // A recovery started afterwards still works and advances again.
        let body = json!({"flow": "recover", "return_url": RETURN, "state": "late",
                          "client_subject": subject});
        let (_, value) = journey(&test, &app, IDP_TOKEN, body, &pid("alice", 30)).await;
        let code = query(value["redirect"].as_str().unwrap())["code"].clone();
        assert_eq!(
            redeem(&app, IDP_TOKEN, &code).await.1["authentication_epoch"],
            3
        );
        upstream.abort();
    });
    assert_eq!(test.humans(), 1);
}

#[test]
fn the_qr_uses_the_core_nonce_and_is_created_once_per_verification() {
    let test = TestCore::new(false);
    run(async {
        let (port, posted, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let (_, started) = start(&app, IDP_TOKEN, enroll("s")).await;
        let id = started["verification_id"].as_str().unwrap();
        assert!(
            posted.lock().unwrap().is_empty(),
            "the QR is created on the first page view"
        );
        let html = open_page(&app, id).await;
        assert!(html.contains("<svg"));
        assert!(html.contains(&format!("/verify/{id}/status")));
        assert!(html.contains("TestBrand"));
        assert!(!html.contains("Elite") && !html.contains("Genera QR"));
        open_page(&app, id).await;
        let posted = posted.lock().unwrap();
        assert_eq!(posted.len(), 1, "a reload reuses the verifier transaction");
        assert_eq!(posted[0]["nonce"], row(&app, id).nonce);
        assert_eq!(posted[0]["dcql_query"], sandbox_dcql(false, false));
        drop(posted);
        upstream.abort();
    });
}

#[test]
fn a_verifier_with_another_client_id_is_refused() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream("x509_hash:somebody-else").await;
        let app = server(port, &test);
        let (_, started) = start(&app, IDP_TOKEN, enroll("s")).await;
        let id = started["verification_id"].as_str().unwrap().to_owned();
        assert_eq!(
            verify_page(State(app.clone()), headers(), Path(id))
                .await
                .unwrap_err(),
            StatusCode::BAD_GATEWAY
        );
        upstream.abort();
    });
}

#[test]
fn an_expired_verification_sends_the_browser_back_to_the_client() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let (_, started) = start(&app, IDP_TOKEN, enroll("late")).await;
        let id = started["verification_id"].as_str().unwrap().to_owned();
        test.server_db()
            .execute("UPDATE verifications SET expires_at = 0", [])
            .unwrap();
        let response = verify_page(State(app.clone()), headers(), Path(id.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GONE);
        let body = to_bytes(response.into_body(), 65_536).await.unwrap();
        assert!(
            String::from_utf8_lossy(&body)
                .contains(&html_escape(&format!("{RETURN}?error=expired&state=late")))
        );
        assert_eq!(test.rows("verifications"), 0);
        upstream.abort();
    });
}

#[test]
fn a_verification_survives_a_server_restart_and_its_code_redeems_once() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let before = server(port, &test);
        let (_, started) = start(&before, IDP_TOKEN, enroll("restart")).await;
        let id = started["verification_id"].as_str().unwrap().to_owned();
        open_page(&before, &id).await;
        drop(before);

        let after = server(port, &test);
        let html = open_page(&after, &id).await;
        assert!(
            html.contains("<svg"),
            "the QR is rendered again after a restart"
        );
        present(&test, &after, &id, &pid("alice", 30));
        let value = poll(&after, &id).await;
        assert_eq!(value["state"], "READY");
        let code = query(value["redirect"].as_str().unwrap())["code"].clone();
        drop(after);

        let last = server(port, &test);
        assert_eq!(redeem(&last, IDP_TOKEN, &code).await.0, StatusCode::OK);
        assert_eq!(
            redeem(&last, IDP_TOKEN, &code).await,
            (StatusCode::BAD_REQUEST, json!({"error": "invalid_grant"}))
        );
        // The redirect carrying the code went with the redeem.
        assert_eq!(test.rows("verifications"), 0);
        upstream.abort();
    });
    assert_eq!(test.humans(), 1);
}

#[test]
fn simultaneous_redeems_of_one_code_succeed_exactly_once() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let (_, value) = journey(&test, &app, IDP_TOKEN, enroll("s"), &pid("alice", 30)).await;
        let code = query(value["redirect"].as_str().unwrap())["code"].clone();
        // Two server processes on the same file.
        let other = server(port, &test);
        let (first, second) = tokio::join!(
            redeem(&app, IDP_TOKEN, &code),
            redeem(&other, IDP_TOKEN, &code)
        );
        let mut statuses = [first.0, second.0];
        statuses.sort();
        assert_eq!(statuses, [StatusCode::OK, StatusCode::BAD_REQUEST]);
        upstream.abort();
    });
}

#[test]
fn expired_codes_and_unknown_ids_are_refused_and_rows_removed() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let (_, value) = journey(&test, &app, IDP_TOKEN, enroll("s"), &pid("alice", 30)).await;
        let code = query(value["redirect"].as_str().unwrap())["code"].clone();
        test.server_db()
            .execute("UPDATE grants SET expires_at = 1", [])
            .unwrap();
        assert_eq!(
            redeem(&app, IDP_TOKEN, &code).await,
            (StatusCode::BAD_REQUEST, json!({"error": "invalid_grant"}))
        );
        assert_eq!(test.rows("grants"), 0);
        assert_eq!(
            redeem(&app, IDP_TOKEN, "never-issued-code").await.0,
            StatusCode::BAD_REQUEST
        );
        for unknown in ["never-started", "../x"] {
            assert_eq!(
                verify_page(State(app.clone()), headers(), Path(unknown.into()))
                    .await
                    .unwrap_err(),
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                verify_status(State(app.clone()), headers(), Path(unknown.into()))
                    .await
                    .unwrap_err(),
                StatusCode::NOT_FOUND
            );
        }
        upstream.abort();
    });
}

#[test]
fn the_server_file_is_private_and_holds_no_identifiers_or_claims() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let (id, value) = journey(&test, &app, IDP_TOKEN, enroll("s"), &pid("alice", 30)).await;
        assert_eq!(value["state"], "READY");
        let (_, pending) = start(&app, IDP_TOKEN, enroll("p")).await;
        let pending = pending["verification_id"].as_str().unwrap().to_owned();
        drop(app);
        let path = test.directory.join("server.sqlite3");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // Fold the WAL in so the main file holds everything.
        test.server_db()
            .pragma_update(None, "wal_checkpoint", "TRUNCATE")
            .unwrap();
        let bytes = fs::read(&path).unwrap();
        let contains = |needle: &str| bytes.windows(needle.len()).any(|w| w == needle.as_bytes());
        for secret in [
            id.as_str(),
            pending.as_str(),
            "Family alice",
            "Given alice",
            "token-tx",
            IDP_TOKEN,
        ] {
            assert!(!contains(secret), "{secret} stored in the server file");
        }
        upstream.abort();
    });
}

#[test]
fn unbound_mdoc_is_accepted_only_under_its_own_policy() {
    let test = TestCore::new(true);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let (_, started) = start(&app, IDP_TOKEN, enroll("m")).await;
        let id = started["verification_id"].as_str().unwrap().to_owned();
        open_page(&app, &id).await;
        let transaction = transaction(&app, &id);
        test.verifier.issue_mdoc(
            &format!("token-{transaction}"),
            &json!([{"docType": PID_DOCTYPE, "attributes": {PID_DOCTYPE: {
                "family_name": "Rossi", "given_name": "Anna", "issuing_country": "IT",
                "birth_date": born(30), "place_of_birth": {"country": "IT", "locality": "Roma"}
            }}}]),
        );
        assert_eq!(poll(&app, &id).await["state"], "READY");
        upstream.abort();
    });
    // A strict (SD-JWT) core refuses the same kind of presentation.
    let strict = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let mut config = test_config(&format!("http://127.0.0.1:{port}/"), strict.settings());
        config.credential_format = "mdoc".into();
        let app = Arc::new(app(config, strict.core.clone()));
        let (_, started) = start(&app, IDP_TOKEN, enroll("m")).await;
        let id = started["verification_id"].as_str().unwrap().to_owned();
        open_page(&app, &id).await;
        let transaction = transaction(&app, &id);
        strict
            .verifier
            .issue_mdoc(&format!("token-{transaction}"), &json!([]));
        assert_eq!(poll(&app, &id).await["reason"], "invalid");
        upstream.abort();
    });
}

#[test]
fn accept_language_prefers_the_higher_quality_supported_language() {
    let pick = |value: &str| {
        let mut headers = headers();
        headers.insert("accept-language", value.parse().unwrap());
        language(&headers)
    };
    assert_eq!(pick("it-IT,it;q=0.9,en;q=0.8"), Lang::It);
    assert_eq!(pick("it;q=0.8,en;q=0.9"), Lang::En);
    assert_eq!(pick("it;q=0.9,en;q=0.9"), Lang::It);
    assert_eq!(pick("fr-FR,de;q=0.9"), Lang::En);
    assert_eq!(pick("it;q=0"), Lang::En);
    assert_eq!(pick("it;q=2,en;q=0.5"), Lang::En);
    assert_eq!(pick("en-US,en;q=0.9,it;q=0.8"), Lang::En);
}

#[test]
fn an_unset_tagline_and_notice_follow_the_page_language() {
    run(async {
        let brand = Brand {
            name: "N".into(),
            tagline: None,
            notice: None,
        };
        let look = Look {
            theme: Theme::Plain,
            brand: &brand,
        };
        let html = |lang| async move {
            let response = page(look, lang, "");
            let language = response.headers()["content-language"].clone();
            let body = to_bytes(response.into_body(), 65_536).await.unwrap();
            (language, String::from_utf8(body.to_vec()).unwrap())
        };
        let (language, english) = html(Lang::En).await;
        assert_eq!(language, "en");
        assert!(english.contains("EUDI wallet identity"));
        assert!(english.contains("no verification of unique identity"));
        let (language, italian) = html(Lang::It).await;
        assert_eq!(language, "it");
        assert!(italian.contains("Identità con wallet EUDI"));
        assert!(italian.contains("nessuna verifica di identità unica"));
    });
}

#[test]
fn qr_and_expired_pages_are_translated_and_escaped() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let mut italian = headers();
        italian.insert("accept-language", "it".parse().unwrap());
        let (_, started) = start(&app, IDP_TOKEN, enroll("it")).await;
        let id = started["verification_id"].as_str().unwrap().to_owned();
        let response = verify_page(State(app.clone()), italian.clone(), Path(id.clone()))
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), 65_536).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("<html lang=it>") && body.contains("Scansiona con il wallet"));
        // The apostrophe of a translation is escaped, never a bare quote.
        assert!(body.contains("un&#39;identità") && !body.contains("un'identità"));
        let english = open_page(&app, &id).await;
        assert!(english.contains("Scan with your wallet"));
        test.server_db()
            .execute("UPDATE verifications SET expires_at = 0", [])
            .unwrap();
        let response = verify_page(State(app.clone()), italian, Path(id))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GONE);
        let body = to_bytes(response.into_body(), 65_536).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("Richiesta scaduta"));
        upstream.abort();
    });
}

#[test]
fn the_landing_page_is_neutral_and_the_probe_routes_are_gone() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let response = index(State(app.clone()), headers()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-security-policy"], CSP);
        let body = to_bytes(response.into_body(), 65_536).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("Start from the service"));
        let mut italian = headers();
        italian.insert(
            "accept-language",
            "it-IT,it;q=0.9,en;q=0.8".parse().unwrap(),
        );
        let response = index(State(app.clone()), italian).await.unwrap();
        assert_eq!(response.headers()["vary"], "accept-language");
        let body = to_bytes(response.into_body(), 65_536).await.unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("Inizia dal servizio") && body.contains("<html lang=it>"));
        assert!(!body.contains("Start from the service"));
        assert!(CSP.ends_with("form-action 'self'") && !CSP.contains("5556"));
        // Legacy probe paths no longer exist.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let served = tokio::spawn(async move {
            axum::serve(listener, router(app)).await.unwrap();
        });
        let client = Client::new();
        for (method, path) in [
            (reqwest::Method::GET, "/login?login_challenge=x"),
            (reqwest::Method::POST, "/presentations?login_challenge=x"),
            (reqwest::Method::GET, "/status/abc"),
        ] {
            let response = client
                .request(method, format!("http://{address}{path}"))
                .header("host", "127.0.0.1:8787")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND, "{path}");
        }
        served.abort();
        upstream.abort();
    });
}

#[test]
fn renamed_settings_fall_back_to_the_legacy_names() {
    let lookup = |key: &str| match key {
        "WOHP_SPIKE_CORE_DB" => Some(OsString::from("/legacy/identity.sqlite3")),
        "WOHP_VERIFIER_PROFILE" => Some(OsString::from("haip")),
        "WOHP_SPIKE_PROFILE" => Some(OsString::from("openid4vp")),
        _ => None,
    };
    assert_eq!(
        setting_from(lookup, "WOHP_SERVER_CORE_DB", "WOHP_SPIKE_CORE_DB"),
        Some(OsString::from("/legacy/identity.sqlite3"))
    );
    // The new name wins over the legacy one.
    assert_eq!(
        setting_from(lookup, "WOHP_VERIFIER_PROFILE", "WOHP_SPIKE_PROFILE"),
        Some(OsString::from("haip"))
    );
    assert_eq!(
        setting_from(
            lookup,
            "WOHP_VERIFIER_CLIENT_ID",
            "WOHP_SPIKE_VERIFIER_CLIENT_ID"
        ),
        None
    );
}

#[test]
fn a_client_minimum_age_is_required_and_limited_to_the_supported_thresholds() {
    for (text, expected) in [
        ("13", Some(AgeThreshold::Thirteen)),
        ("14", Some(AgeThreshold::Fourteen)),
        ("16", Some(AgeThreshold::Sixteen)),
        ("18", Some(AgeThreshold::Eighteen)),
        ("none", None),
    ] {
        assert_eq!(minimum_age(text), Ok(expected), "{text}");
    }
    for bad in ["", "12", "15", "17", "19", "adult", "None"] {
        assert!(minimum_age(bad).is_err(), "{bad}");
    }
}

#[test]
fn clients_file_sets_theme_and_brand() {
    let entry = |extra: Value| {
        let mut entry = json!({"client_id": "rp", "application_scope": "rp.network",
            "minimum_age": 16,
            "redirect_uris": [OTHER_RETURN], "token_sha256": "ab".repeat(32)});
        entry
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        json!({ "clients": [entry] }).to_string()
    };
    let plain = clients_from_json(&entry(json!({}))).unwrap();
    assert_eq!(plain[0].theme, Theme::Plain);
    assert_eq!(
        plain[0].registration.minimum_age,
        Some(AgeThreshold::Sixteen)
    );
    assert!(plain[0].brand.is_none());
    let child = clients_from_json(&entry(json!({"minimum_age": null}))).unwrap();
    assert_eq!(child[0].registration.minimum_age, None);
    let warm = clients_from_json(&entry(json!({"theme": "warm",
        "brand": {"name": "N", "tagline": "T", "notice": "X"}})))
    .unwrap();
    assert_eq!(warm[0].theme, Theme::Warm);
    assert_eq!(warm[0].brand.as_ref().unwrap().name, "N");
    // Tagline and notice may be left to the page language.
    let named = clients_from_json(&entry(json!({"brand": {"name": "N"}}))).unwrap();
    let brand = named[0].brand.as_ref().unwrap();
    assert!(brand.tagline.is_none() && brand.notice.is_none());
    for bad in [
        json!({"theme": "elite"}),
        json!({"theme": 1}),
        json!({"brand": {"tagline": "T"}}),
        json!({"brand": "N"}),
        json!({"brand": {"name": "", "tagline": "T", "notice": "X"}}),
        json!({"brand": {"name": "N", "tagline": ""}}),
        json!({"brand": {"name": "N", "notice": 1}}),
        json!({"minimum_age": 15}),
        json!({"minimum_age": "16"}),
        json!({"minimum_age": 16.5}),
    ] {
        assert!(clients_from_json(&entry(bad.clone())).is_err(), "{bad}");
    }
}

#[test]
fn pages_use_the_theme_and_brand_of_their_client() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let (_, started) = start(&app, IDP_TOKEN, enroll("s")).await;
        let plain = open_page(&app, started["verification_id"].as_str().unwrap()).await;
        assert!(plain.contains("TestBrand") && plain.contains("#000000"));
        assert!(!plain.contains("#b54e35") && !plain.contains("OtherBrand"));
        let other = json!({"flow": "enroll", "return_url": OTHER_RETURN, "state": "s"});
        let (_, started) = start(&app, OTHER_TOKEN, other).await;
        let warm = open_page(&app, started["verification_id"].as_str().unwrap()).await;
        assert!(warm.contains("OtherBrand") && warm.contains("other notice"));
        assert!(warm.contains("#b54e35") && warm.contains("#fffdf8"));
        assert!(!warm.contains("TestBrand"));
        upstream.abort();
    });
}

#[test]
fn client_configuration_is_validated() {
    let hash = sha256(b"token");
    assert!(
        client_config(
            "idp",
            "idp.network",
            Some(AgeThreshold::Fourteen),
            vec![RETURN.into()],
            hash
        )
        .is_ok()
    );
    for uri in [
        "http://example.org/return",
        "https://rp.example/return?x=1",
        "https://rp.example/r#f",
        "https://user@rp.example/r",
        "not a url",
    ] {
        assert!(
            client_config("idp", "idp.network", None, vec![uri.into()], hash).is_err(),
            "{uri}"
        );
    }
    assert!(client_config("idp", "idp.network", None, Vec::new(), hash).is_err());
    assert!(client_config("bad id", "idp.network", None, vec![RETURN.into()], hash).is_err());
    let clients = test_clients();
    assert!(unique_clients(&clients).is_ok());
    let mut duplicate = clients.clone();
    duplicate.push(clients[0].clone());
    assert!(unique_clients(&duplicate).is_err());
    assert_eq!(hex_digest(&"ab".repeat(32)), Some([0xab; 32]));
    assert_eq!(hex_digest(&"+b".repeat(32)), None);
    assert_eq!(hex_digest("ab"), None);
    assert!(same_digest(&hash, &sha256(b"token")) && !same_digest(&hash, &sha256(b"other")));
}

#[test]
fn dcql_requests_the_matching_claims_and_the_pan_only_as_an_alternative() {
    let sd_jwt = sandbox_dcql(false, false);
    let credential = &sd_jwt["credentials"][0];
    assert_eq!(credential["format"], "dc+sd-jwt");
    assert_eq!(credential["meta"]["vct_values"], json!([PID_VCT]));
    assert!(credential.get("claim_sets").is_none());
    let paths: Vec<_> = credential["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|claim| claim["path"][0].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        [
            "issuing_country",
            "family_name",
            "given_name",
            "birthdate",
            "place_of_birth"
        ]
    );

    let with_pan = sandbox_dcql(false, true);
    let credential = &with_pan["credentials"][0];
    assert_eq!(
        credential["claims"][5]["path"],
        json!(["personal_administrative_number"])
    );
    assert_eq!(
        credential["claim_sets"][0],
        json!(["c0", "c1", "c2", "c3", "c4", "pan"])
    );
    assert_eq!(
        credential["claim_sets"][1],
        json!(["c0", "c1", "c2", "c3", "c4"])
    );

    let mdoc = sandbox_dcql(true, true);
    let credential = &mdoc["credentials"][0];
    assert_eq!(credential["format"], "mso_mdoc");
    assert_eq!(credential["meta"]["doctype_value"], PID_DOCTYPE);
    assert_eq!(
        credential["claims"][3]["path"],
        json!([PID_DOCTYPE, "birth_date"])
    );
    assert_eq!(
        credential["claims"][4]["path"],
        json!([PID_DOCTYPE, "place_of_birth"])
    );
    assert_eq!(
        credential["claims"][5]["path"],
        json!([PID_DOCTYPE, "administrative_number"])
    );
}

#[test]
fn the_lookup_key_is_never_recreated_next_to_an_existing_database() {
    let directory = std::env::temp_dir().join(format!(
        "wohp-spike-key-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&directory).unwrap();
    let (database, key) = (
        directory.join("identity.sqlite3"),
        directory.join("lookup.key"),
    );
    assert!(load_or_create_key(&key, &database).is_ok());
    assert!(load_or_create_key(&key, &database).is_ok());
    fs::write(&database, b"x").unwrap();
    fs::remove_file(&key).unwrap();
    assert_eq!(
        load_or_create_key(&key, &database).err(),
        Some(CoreError::ConfigurationMismatch)
    );
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn rejects_invalid_paths_and_cross_origin_requests() {
    assert!(opaque_id(ID));
    assert!(!opaque_id(
        "../admin/../../00000000-0000-0000-0000-000000000000"
    ));
    let mut headers = HeaderMap::new();
    headers.insert("host", "127.0.0.1:8787".parse().unwrap());
    headers.insert("origin", "https://attacker.invalid".parse().unwrap());
    assert_eq!(
        local_request(&headers, true, None),
        Err(StatusCode::FORBIDDEN)
    );
}

#[test]
fn public_origin_allows_cloudflare_host_and_origin() {
    let public = reqwest::Url::parse("https://qr.example.org").unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("host", "qr.example.org".parse().unwrap());
    headers.insert("origin", "https://qr.example.org".parse().unwrap());
    assert_eq!(local_request(&headers, true, Some(&public)), Ok(()));

    headers.insert("host", "attacker.invalid".parse().unwrap());
    assert_eq!(
        local_request(&headers, true, Some(&public)),
        Err(StatusCode::FORBIDDEN)
    );

    headers.insert("host", "qr.example.org".parse().unwrap());
    headers.insert("origin", "https://attacker.invalid".parse().unwrap());
    assert_eq!(
        local_request(&headers, true, Some(&public)),
        Err(StatusCode::FORBIDDEN)
    );
}

#[test]
fn a_slow_verifier_does_not_hold_the_core_lock() {
    let test = TestCore::new(false);
    let (alice, challenge, token) = run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let (_, value) = journey(&test, &app, IDP_TOKEN, enroll("a"), &pid("alice", 30)).await;
        let code = query(value["redirect"].as_str().unwrap())["code"].clone();
        let alice = redeem(&app, IDP_TOKEN, &code).await.1["client_subject"]
            .as_str()
            .unwrap()
            .to_owned();
        let (_, started) = start(&app, IDP_TOKEN, enroll("b")).await;
        let id = started["verification_id"].as_str().unwrap().to_owned();
        open_page(&app, &id).await;
        present(&test, &app, &id, &pid("bob", 30));
        let verification = row(&app, &id);
        upstream.abort();
        (
            alice,
            verification.challenge_id,
            format!("token-{}", verification.presentation.unwrap().0),
        )
    });
    let client = ClientId::parse("first-party-idp").unwrap();
    test.verifier.delay(Some(Duration::from_millis(1500)));
    let worker = {
        let (core, client) = (test.core.clone(), client.clone());
        let presentation = sd_jwt_presentation(&token).unwrap();
        std::thread::spawn(move || {
            accept_in_core(
                &core,
                &challenge,
                &presentation,
                WalletFlow::Enrollment,
                &client,
            )
        })
    };
    std::thread::sleep(Duration::from_millis(300));
    let waited = std::time::Instant::now();
    let status = test
        .core
        .lock()
        .unwrap()
        .status_for_client(&client, &Subject::parse(&alice).unwrap())
        .unwrap();
    assert!(waited.elapsed() < Duration::from_millis(1000));
    assert_eq!(status.status, IdentityStatus::Valid);
    let accepted = worker.join().unwrap().unwrap();
    assert_eq!(accepted.kind, "created");
    assert_eq!(test.humans(), 2);
}

#[test]
fn the_qr_page_needs_no_inline_script() {
    let test = TestCore::new(false);
    run(async {
        let (port, _, upstream) = upstream(AUDIENCE).await;
        let app = server(port, &test);
        let (_, started) = start(&app, IDP_TOKEN, enroll("s")).await;
        let id = started["verification_id"].as_str().unwrap().to_owned();
        let response = verify_page(State(app.clone()), headers(), Path(id.clone()))
            .await
            .unwrap();
        let csp = response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(csp.contains("script-src 'self';") && !csp.contains("script-src 'unsafe-inline'"));
        let body = to_bytes(response.into_body(), 65_536).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("<script src=/static/verify.js></script>"));
        assert!(!html.contains("<script>"));
        assert!(html.contains(&format!("data-poll='/verify/{id}/status'")));
        let script = verify_script().await;
        assert_eq!(
            script.headers()["content-type"],
            "text/javascript; charset=utf-8"
        );
        upstream.abort();
    });
}

#[test]
fn spike_requires_explicit_development_environment() {
    assert!(require_development("development").is_ok());
    assert!(require_development("").is_err());
    assert!(require_development("production").is_err());
}
