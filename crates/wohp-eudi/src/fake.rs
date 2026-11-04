//! Loopback fake of the verifier's validation endpoints, for tests only.
//!
//! An SD-JWT token is bound to the nonce and audience it was issued for, like the
//! real endpoint: any other nonce or audience is answered with 400. The mdoc
//! endpoint takes no nonce, exactly like the real one. Never enable this feature
//! in a deployable binary.

use reqwest::Url;
use serde_json::Value;
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

struct Bound {
    claims: String,
    nonce: String,
    audience: String,
}

#[derive(Default)]
struct State {
    tokens: HashMap<String, Bound>,
    mdoc: HashMap<String, String>,
    requests: Vec<ValidationRequest>,
    forced_status: Option<u16>,
    delay: Option<Duration>,
}

/// What the provider actually sent to the validation endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationRequest {
    pub path: String,
    pub token: String,
    pub nonce: String,
    pub audience: String,
    pub authorization: Option<String>,
}

pub struct FakeVerifier {
    origin: String,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    address: std::net::SocketAddr,
    worker: Option<JoinHandle<()>>,
}

impl FakeVerifier {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let address = listener.local_addr().expect("local address");
        let state = Arc::new(Mutex::new(State::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let (state, stop) = (Arc::clone(&state), Arc::clone(&stop));
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        let _ = serve(stream, &state);
                    }
                }
            })
        };
        Self {
            origin: format!("http://{address}/"),
            state,
            stop,
            address,
            worker: Some(worker),
        }
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The verifier validates `token` only for this nonce and audience.
    pub fn issue(&self, token: &str, claims: &Value, nonce: &str, audience: &str) {
        self.state.lock().unwrap().tokens.insert(
            token.into(),
            Bound {
                claims: claims.to_string(),
                nonce: nonce.into(),
                audience: audience.into(),
            },
        );
    }

    /// An mdoc device response the endpoint will decode (no nonce binding).
    pub fn issue_mdoc(&self, token: &str, documents: &Value) {
        self.state
            .lock()
            .unwrap()
            .mdoc
            .insert(token.into(), documents.to_string());
    }

    /// Answers every request with this status (for example 503), or none.
    pub fn force_status(&self, status: Option<u16>) {
        self.state.lock().unwrap().forced_status = status;
    }

    /// Waits this long before every answer, like a slow verifier.
    pub fn delay(&self, delay: Option<Duration>) {
        self.state.lock().unwrap().delay = delay;
    }

    pub fn requests(&self) -> Vec<ValidationRequest> {
        self.state.lock().unwrap().requests.clone()
    }
}

impl Drop for FakeVerifier {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn serve(mut stream: TcpStream, state: &Mutex<State>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let header = |name: &str| {
        head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    };
    let length: usize = header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buffer.len() < head_end + length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let body = String::from_utf8_lossy(&buffer[head_end..]).into_owned();
    let form: HashMap<String, String> = Url::parse(&format!("http://localhost/?{body}"))
        .map(|url| {
            url.query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        })
        .unwrap_or_default();
    let field = |name: &str| form.get(name).cloned().unwrap_or_default();
    let path = head
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let request = ValidationRequest {
        token: if path.ends_with("/deviceResponse") {
            field("device_response")
        } else {
            field("sd_jwt_vc")
        },
        path: path.clone(),
        nonce: field("nonce"),
        audience: field("audience"),
        authorization: header("authorization"),
    };

    let (status, payload, delay) = {
        let mut state = state.lock().unwrap();
        state.requests.push(request.clone());
        let delay = state.delay;
        let (status, payload) = if let Some(status) = state.forced_status {
            (status, "{}".to_owned())
        } else if head.starts_with("POST /utilities/validations/msoMdoc/deviceResponse ") {
            match state.mdoc.get(&request.token) {
                Some(documents) => (200, documents.clone()),
                None => (400, r#"{"error":"InvalidDeviceResponse"}"#.to_owned()),
            }
        } else if !head.starts_with("POST /utilities/validations/sdJwtVc ") {
            (404, "{}".to_owned())
        } else {
            match state.tokens.get(&request.token) {
                Some(bound)
                    if bound.nonce == request.nonce && bound.audience == request.audience =>
                {
                    (200, bound.claims.clone())
                }
                _ => (400, r#"{"error":"InvalidSdJwtVc"}"#.to_owned()),
            }
        };
        (status, payload, delay)
    };
    if let Some(delay) = delay {
        thread::sleep(delay);
    }
    let response = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    stream.shutdown(Shutdown::Both)
}
