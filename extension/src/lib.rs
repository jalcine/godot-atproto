use std::{
    net::TcpListener,
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
    time::Duration,
};

use anyhow::{Context, anyhow, bail};
use atproto_identity::{
    key::{KeyData, KeyType, generate_key},
    plc,
    resolve::resolve_handle_http,
};
use atproto_oauth::{
    dpop::{auth_dpop, request_dpop},
    jwt::mint,
    pkce,
    resources::pds_resources,
    workflow::{ParResponse, TokenResponse},
};
use rand::distr::{Alphanumeric, SampleString};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::oneshot,
};

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
                    self.signals()
                        .authorize_url_ready()
                        .emit(&GString::from(url.as_str()));
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
                    self.signals()
                        .sign_in_failed()
                        .emit(&GString::from(message.as_str()));
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
        GString::from(
            self.session
                .as_ref()
                .map_or("", |s| s.access_token.as_str()),
        )
    }

    /// Reads a record from the signed-in repo. Returns its JSON value, or an
    /// empty string on failure or when signed out.
    /// Blocks the main thread for the network round trip.
    #[func]
    fn get_record(&self, collection: GString, rkey: GString) -> GString {
        let Some(session) = self.session.as_ref() else {
            return GString::new();
        };
        let params = [
            ("repo".to_string(), session.did.clone()),
            ("collection".to_string(), collection.to_string()),
            ("rkey".to_string(), rkey.to_string()),
        ];
        match run_blocking(xrpc_call(
            session,
            reqwest::Method::GET,
            "com.atproto.repo.getRecord",
            &params,
            None,
        )) {
            Ok(response) => GString::from(response["value"].to_string().as_str()),
            Err(error) => {
                godot_error!("get_record failed: {error:#}");
                GString::new()
            }
        }
    }

    /// Calls any XRPC query (GET). `params` become the query string. Returns the
    /// JSON response, or an empty string on failure or when signed out.
    /// Blocks the main thread for the network round trip.
    #[func]
    fn xrpc_query(&self, nsid: GString, params: Dictionary<GString, GString>) -> GString {
        let Some(session) = self.session.as_ref() else {
            return GString::new();
        };
        let params: Vec<(String, String)> = params
            .iter_shared()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        match run_blocking(xrpc_call(
            session,
            reqwest::Method::GET,
            &nsid.to_string(),
            &params,
            None,
        )) {
            Ok(value) => GString::from(value.to_string().as_str()),
            Err(error) => {
                godot_error!("xrpc_query failed: {error:#}");
                GString::new()
            }
        }
    }

    /// Calls any XRPC procedure (POST). `body_json` is the JSON request body, or
    /// empty for none. Returns the JSON response, or an empty string on failure
    /// or when signed out. Blocks the main thread for the network round trip.
    #[func]
    fn xrpc_procedure(&self, nsid: GString, body_json: GString) -> GString {
        let Some(session) = self.session.as_ref() else {
            return GString::new();
        };
        let body = if body_json.is_empty() {
            None
        } else {
            match serde_json::from_str::<Value>(&body_json.to_string()) {
                Ok(body) => Some(body),
                Err(error) => {
                    godot_error!("xrpc_procedure body is not JSON: {error}");
                    return GString::new();
                }
            }
        };
        match run_blocking(xrpc_call(
            session,
            reqwest::Method::POST,
            &nsid.to_string(),
            &[],
            body.as_ref(),
        )) {
            Ok(value) => GString::from(value.to_string().as_str()),
            Err(error) => {
                godot_error!("xrpc_procedure failed: {error:#}");
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
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let mut nonce: Option<String> = None;
    for attempt in 0..2 {
        let proof = request_proof(
            &session.dpop_key,
            method.as_str(),
            url,
            &session.access_token,
            nonce.as_deref(),
        )?;
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
            let text = response.text().await?;
            return Ok(if text.is_empty() {
                Value::Null
            } else {
                serde_json::from_str(&text)?
            });
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

/// Calls any XRPC method on the signed-in PDS. `nsid` must be a dotted NSID
/// with at least three segments; the shape is checked, not resolved.
async fn xrpc_call(
    session: &Session,
    method: reqwest::Method,
    nsid: &str,
    params: &[(String, String)],
    body: Option<&Value>,
) -> anyhow::Result<Value> {
    let segments: Vec<&str> = nsid.split('.').collect();
    let well_formed = segments.len() >= 3
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if !well_formed {
        bail!("invalid NSID: {nsid:?}");
    }
    let mut url = url::Url::parse(&format!(
        "{}/xrpc/{nsid}",
        session.pds.trim_end_matches('/')
    ))?;
    if !params.is_empty() {
        url.query_pairs_mut().extend_pairs(params);
    }
    xrpc(session, method, url.as_str(), body).await
}

fn run_sign_in_thread(
    handle: String,
    scope: String,
    tx: Sender<SignInEvent>,
    cancel_rx: oneshot::Receiver<()>,
) {
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
    let (_, server) = pds_resources(&http, &pds)
        .await
        .map_err(|e| anyhow!("{e:?}"))?;

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
            bail!(
                "callback iss {iss} does not match authorization server {}",
                server.issuer
            )
        }
        None if server.authorization_response_iss_parameter_supported => {
            bail!("callback is missing the required iss parameter")
        }
        _ => {}
    }
    let code = callback
        .code
        .context("callback carried no authorization code")?;

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
        if attempt == 0
            && status == StatusCode::BAD_REQUEST
            && let Some(server_nonce) = server_nonce
        {
            nonce = Some(server_nonce);
            continue;
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
                .write_all(
                    // FIXME: Let's allow for this body to be used as the default but allow for
                    // an asset to be streamed or a string value to be used.
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
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

        // FIXME: Let's allow for this body to be used as the default but allow for
        // an asset to be streamed or a string value to be used.
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

#[cfg(test)]
mod tests;
