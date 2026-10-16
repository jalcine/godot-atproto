use std::net::TcpListener;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use atproto_identity::key::{KeyData, KeyType, generate_key};
use atproto_identity::plc;
use atproto_identity::resolve::resolve_handle_http;
use atproto_oauth::dpop::{auth_dpop, request_dpop};
use atproto_oauth::jwt::mint;
use atproto_oauth::pkce;
use atproto_oauth::resources::pds_resources;
use atproto_oauth::workflow::{ParResponse, TokenResponse};
use rand::distr::{Alphanumeric, SampleString};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::oneshot;

use godot::prelude::*;

const PLC_HOSTNAME: &str = "plc.directory";
const REDIRECT_PATH: &str = "/callback";
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

struct GodotAtproto;

#[gdextension]
unsafe impl ExtensionLibrary for GodotAtproto {}

/// A completed sign-in. The DPoP key stays in Rust: the access token is
/// DPoP-bound and cannot be used without it.
struct Session {
    did: String,
    pds: String,
    access_token: String,
    dpop_key: KeyData,
}

enum SignInEvent {
    AuthorizeUrl(String),
    Completed(Session),
    Cancelled,
    Failed(String),
}

/// Entry point for ATProto functionality exposed to GDScript.
///
/// `sign_in` runs the public-client OAuth flow on a background thread. Progress
/// reaches GDScript through the `authorize_url_ready`, `sign_in_completed`,
/// `sign_in_cancelled`, and `sign_in_failed` signals, which are emitted from
/// `process` on the main thread.
#[derive(GodotClass)]
#[class(init, base = Node)]
pub struct AtprotoClient {
    base: Base<Node>,
    events: Option<Receiver<SignInEvent>>,
    cancel: Option<oneshot::Sender<()>>,
    session: Option<Session>,
}

#[godot_api]
impl INode for AtprotoClient {
    fn ready(&mut self) {
        self.base_mut().set_process(true);
    }

    fn process(&mut self, _delta: f64) {
        let Some(rx) = self.events.take() else {
            return;
        };
        loop {
            match rx.try_recv() {
                Ok(SignInEvent::AuthorizeUrl(url)) => {
                    self.signals().authorize_url_ready().emit(&GString::from(url.as_str()));
                }
                Ok(SignInEvent::Completed(session)) => {
                    let did = GString::from(session.did.as_str());
                    self.session = Some(session);
                    self.cancel = None;
                    self.signals().sign_in_completed().emit(&did);
                    return;
                }
                Ok(SignInEvent::Cancelled) => {
                    self.cancel = None;
                    self.signals().sign_in_cancelled().emit();
                    return;
                }
                Ok(SignInEvent::Failed(message)) => {
                    self.cancel = None;
                    self.signals().sign_in_failed().emit(&GString::from(message.as_str()));
                    return;
                }
                Err(TryRecvError::Empty) => {
                    self.events = Some(rx);
                    return;
                }
                Err(TryRecvError::Disconnected) => {
                    self.cancel = None;
                    return;
                }
            }
        }
    }
}

#[godot_api]
impl AtprotoClient {
    #[signal]
    fn authorize_url_ready(url: GString);

    #[signal]
    fn sign_in_completed(did: GString);

    #[signal]
    fn sign_in_cancelled();

    #[signal]
    fn sign_in_failed(message: GString);

    /// Returns the crate version, to verify the extension is loaded.
    #[func]
    fn version(&self) -> GString {
        env!("CARGO_PKG_VERSION").into()
    }

    /// Starts sign-in for a handle. Returns false if a sign-in is already running.
    #[func]
    fn sign_in(&mut self, handle: GString, scope: GString) -> bool {
        if self.events.is_some() {
            return false;
        }
        let (tx, rx) = mpsc::channel();
        let (cancel_tx, cancel_rx) = oneshot::channel();
        self.events = Some(rx);
        self.cancel = Some(cancel_tx);
        let handle = handle.to_string();
        let scope = scope.to_string();
        std::thread::spawn(move || run_sign_in_thread(handle, scope, tx, cancel_rx));
        true
    }

    /// Cancels the pending sign-in. Emits `sign_in_cancelled` once it stops.
    /// Returns false if no sign-in is pending.
    #[func]
    fn cancel(&mut self) -> bool {
        match self.cancel.take() {
            Some(tx) => {
                let _ = tx.send(());
                true
            }
            None => false,
        }
    }

    /// Forgets the current session and cancels any pending sign-in. Local only:
    /// no revocation request is sent to the authorization server.
    #[func]
    fn sign_out(&mut self) {
        self.session = None;
        self.cancel();
    }

    /// The DID of the signed-in account, or an empty string.
    #[func]
    fn get_did(&self) -> GString {
        GString::from(self.session.as_ref().map_or("", |s| s.did.as_str()))
    }

    /// The PDS base URL of the signed-in account, or an empty string.
    #[func]
    fn get_pds_url(&self) -> GString {
        GString::from(self.session.as_ref().map_or("", |s| s.pds.as_str()))
    }

    /// The access token of the signed-in account, or an empty string.
    /// It is DPoP-bound and is only usable together with the DPoP key, which is not exposed.
    #[func]
    fn get_access_token(&self) -> GString {
        GString::from(self.session.as_ref().map_or("", |s| s.access_token.as_str()))
    }

    /// Creates an `app.bsky.feed.post` with `text` in the signed-in repo.
    /// Returns the record URI, or an empty string on failure or when signed out.
    /// Blocks the main thread for the network round trip.
    #[func]
    fn create_post(&self, text: GString) -> GString {
        let Some(session) = self.session.as_ref() else {
            return GString::new();
        };
        let record = json!({
            "$type": "app.bsky.feed.post",
            "text": text.to_string(),
            "createdAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        });
        match run_blocking(create_record(session, "app.bsky.feed.post", record)) {
            Ok(uri) => GString::from(uri.as_str()),
            Err(error) => {
                godot_error!("create_post failed: {error:#}");
                GString::new()
            }
        }
    }

    /// Reads a record from the signed-in repo. Returns its JSON value, or an
    /// empty string on failure or when signed out.
    /// Blocks the main thread for the network round trip.
    #[func]
    fn get_record(&self, collection: GString, rkey: GString) -> GString {
        let Some(session) = self.session.as_ref() else {
            return GString::new();
        };
        match run_blocking(get_record_json(session, &collection.to_string(), &rkey.to_string())) {
            Ok(value) => GString::from(value.to_string().as_str()),
            Err(error) => {
                godot_error!("get_record failed: {error:#}");
                GString::new()
            }
        }
    }
}

fn run_blocking<T>(future: impl Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)?
        .block_on(future)
}

/// Sends a DPoP-bound request to the PDS and decodes the JSON response.
async fn xrpc(
    session: &Session,
    method: reqwest::Method,
    url: &str,
    body: Option<&Value>,
) -> anyhow::Result<Value> {
    let http = reqwest::Client::builder().timeout(Duration::from_secs(15)).build()?;
    let mut nonce: Option<String> = None;
    for attempt in 0..2 {
        let proof = request_proof(&session.dpop_key, method.as_str(), url, &session.access_token, nonce.as_deref())?;
        let mut request = http
            .request(method.clone(), url)
            .header("Authorization", format!("DPoP {}", session.access_token))
            .header("DPoP", proof);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await?;
        let status = response.status();
        let server_nonce = response
            .headers()
            .get("DPoP-Nonce")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);

        if status.is_success() {
            return Ok(response.json::<Value>().await?);
        }
        if attempt == 0 && status == StatusCode::UNAUTHORIZED {
            if let Some(server_nonce) = server_nonce {
                nonce = Some(server_nonce);
                continue;
            }
        }
        let text = response.text().await.unwrap_or_default();
        bail!("{method} {url} failed with {status}: {text}");
    }
    bail!("{method} {url} did not succeed after a DPoP nonce retry")
}

/// Builds a resource-request DPoP proof, with the server nonce when one was issued.
fn request_proof(
    key: &KeyData,
    method: &str,
    url: &str,
    access_token: &str,
    nonce: Option<&str>,
) -> anyhow::Result<String> {
    let (proof, header, mut claims) = request_dpop(key, method, url, access_token)?;
    match nonce {
        None => Ok(proof),
        Some(nonce) => {
            claims.private.insert("nonce".to_string(), nonce.into());
            mint(key, &header, &claims)
        }
    }
}

/// `com.atproto.repo.createRecord`: returns the new record's `at://` URI.
async fn create_record(session: &Session, collection: &str, record: Value) -> anyhow::Result<String> {
    let url = format!("{}/xrpc/com.atproto.repo.createRecord", session.pds.trim_end_matches('/'));
    let body = json!({
        "repo": session.did,
        "collection": collection,
        "record": record,
    });
    let response = xrpc(session, reqwest::Method::POST, &url, Some(&body)).await?;
    response["uri"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("createRecord response has no uri: {response}"))
}

/// `com.atproto.repo.getRecord`: returns the record's `value` object.
async fn get_record_json(session: &Session, collection: &str, rkey: &str) -> anyhow::Result<Value> {
    let url = url::Url::parse_with_params(
        &format!("{}/xrpc/com.atproto.repo.getRecord", session.pds.trim_end_matches('/')),
        &[("repo", session.did.as_str()), ("collection", collection), ("rkey", rkey)],
    )?;
    let response = xrpc(session, reqwest::Method::GET, url.as_str(), None).await?;
    response
        .get("value")
        .cloned()
        .ok_or_else(|| anyhow!("getRecord response has no value: {response}"))
}

fn run_sign_in_thread(handle: String, scope: String, tx: Sender<SignInEvent>, cancel_rx: oneshot::Receiver<()>) {
    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)
        .and_then(|runtime| {
            runtime.block_on(async {
                tokio::select! {
                    result = sign_in(&handle, &scope, &tx) => result.map(Some),
                    _ = cancel_rx => Ok(None),
                }
            })
        });
    let event = match outcome {
        Ok(Some(session)) => SignInEvent::Completed(session),
        Ok(None) => SignInEvent::Cancelled,
        Err(error) => SignInEvent::Failed(format!("{error:#}")),
    };
    let _ = tx.send(event);
}

/// Public-client OAuth: loopback redirect, PAR, PKCE, DPoP, token exchange.
///
/// The `client_id` is the atproto localhost development client, so no hosted
/// metadata is needed. The authorization server must support that exception.
async fn sign_in(handle: &str, scope: &str, tx: &Sender<SignInEvent>) -> anyhow::Result<Session> {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()?;

    let did = resolve_handle_http(&http, handle).await?;
    if !did.starts_with("did:plc:") {
        bail!("only did:plc identities are supported, got {did}");
    }
    let document = plc::query(&http, PLC_HOSTNAME, &did).await?;
    let pds = document
        .pds_endpoints()
        .first()
        .map(|pds| pds.to_string())
        .ok_or_else(|| anyhow!("DID document for {did} names no PDS"))?;
    let (_, server) = pds_resources(&http, &pds).await.map_err(|e| anyhow!("{e:?}"))?;

    // Bind the loopback listener first: its port goes into the redirect_uri.
    let std_listener = TcpListener::bind("127.0.0.1:0").context("binding loopback listener")?;
    std_listener.set_nonblocking(true)?;
    let port = std_listener.local_addr()?.port();
    let listener = tokio::net::TcpListener::from_std(std_listener)?;
    let redirect_uri = format!("http://127.0.0.1:{port}{REDIRECT_PATH}");

    // Localhost dev client: redirect_uri and scope go in the client_id query,
    // and the port is ignored when matching the loopback redirect.
    let client_id = format!(
        "http://localhost?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("redirect_uri", &format!("http://127.0.0.1{REDIRECT_PATH}"))
            .append_pair("scope", scope)
            .finish()
    );

    let dpop_key = generate_key(KeyType::P256Private)?;
    let (verifier, challenge) = pkce::generate();
    let state = Alphanumeric.sample_string(&mut rand::rng(), 32);

    let par: ParResponse = post_form(
        &http,
        &dpop_key,
        &server.pushed_authorization_request_endpoint,
        &[
            ("response_type", "code"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("client_id", &client_id),
            ("state", &state),
            ("redirect_uri", &redirect_uri),
            ("scope", scope),
            ("login_hint", handle),
        ],
    )
    .await?;

    let authorize_url = url::Url::parse_with_params(
        &server.authorization_endpoint,
        &[
            ("client_id", client_id.as_str()),
            ("request_uri", par.request_uri.as_str()),
        ],
    )?
    .to_string();
    let _ = tx.send(SignInEvent::AuthorizeUrl(authorize_url));

    let callback = tokio::time::timeout(CALLBACK_TIMEOUT, accept_callback(&listener))
        .await
        .context("timed out waiting for the browser redirect")??;

    if callback.state.as_deref() != Some(state.as_str()) {
        bail!("callback state does not match the request");
    }
    // RFC 9207 mix-up defence: a returned iss must match the authorization server.
    match callback.issuer.as_deref() {
        Some(iss) if iss != server.issuer => {
            bail!("callback iss {iss} does not match authorization server {}", server.issuer)
        }
        None if server.authorization_response_iss_parameter_supported => {
            bail!("callback is missing the required iss parameter")
        }
        _ => {}
    }
    let code = callback.code.context("callback carried no authorization code")?;

    let token: TokenResponse = post_form(
        &http,
        &dpop_key,
        &server.token_endpoint,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &client_id),
            ("code_verifier", &verifier),
        ],
    )
    .await?;

    match token.sub.as_deref() {
        Some(sub) if sub == did => Ok(Session {
            did,
            pds,
            access_token: token.access_token,
            dpop_key,
        }),
        other => bail!("token subject {other:?} does not match handle DID {did}"),
    }
}

/// Builds a DPoP proof for a POST, optionally carrying a server-issued nonce.
fn dpop_proof(key: &KeyData, url: &str, nonce: Option<&str>) -> anyhow::Result<String> {
    let (proof, header, mut claims) = auth_dpop(key, "POST", url)?;
    match nonce {
        None => Ok(proof),
        Some(nonce) => {
            claims.private.insert("nonce".to_string(), nonce.into());
            mint(key, &header, &claims)
        }
    }
}

/// POSTs a form with a DPoP proof, retrying once with the server's nonce on a
/// `use_dpop_nonce` challenge.
async fn post_form<T: DeserializeOwned>(
    http: &reqwest::Client,
    key: &KeyData,
    url: &str,
    form: &[(&str, &str)],
) -> anyhow::Result<T> {
    let mut nonce: Option<String> = None;
    for attempt in 0..2 {
        let proof = dpop_proof(key, url, nonce.as_deref())?;
        let response = http
            .post(url)
            .header("DPoP", proof)
            .form(form)
            .send()
            .await?;

        let status = response.status();
        let server_nonce = response
            .headers()
            .get("DPoP-Nonce")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);

        if status.is_success() {
            return Ok(response.json::<T>().await?);
        }
        if attempt == 0 && status == StatusCode::BAD_REQUEST {
            if let Some(server_nonce) = server_nonce {
                nonce = Some(server_nonce);
                continue;
            }
        }
        let body = response.text().await.unwrap_or_default();
        bail!("POST {url} failed with {status}: {body}");
    }
    bail!("POST {url} did not succeed after a DPoP nonce retry")
}

struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    issuer: Option<String>,
}

/// Accepts connections until one hits the redirect path, answers it, and returns its query.
async fn accept_callback(listener: &tokio::net::TcpListener) -> anyhow::Result<CallbackParams> {
    loop {
        let (stream, _) = listener.accept().await?;
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await?;

        let target = request_line.split_whitespace().nth(1).unwrap_or("/");
        if !target.starts_with(REDIRECT_PATH) {
            let mut stream = reader.into_inner();
            stream
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
            continue;
        }

        let url = url::Url::parse(&format!("http://127.0.0.1{target}"))?;
        let mut params = CallbackParams {
            code: None,
            state: None,
            issuer: None,
        };
        let mut error = None;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "code" => params.code = Some(value.into_owned()),
                "state" => params.state = Some(value.into_owned()),
                "iss" => params.issuer = Some(value.into_owned()),
                "error" => error = Some(value.into_owned()),
                _ => {}
            }
        }

        let body = "<html><body><p>Sign-in finished. You can close this tab.</p></body></html>";
        let mut stream = reader.into_inner();
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await?;

        if let Some(error) = error {
            bail!("authorization server returned error: {error}");
        }
        return Ok(params);
    }
}
