use std::net::TcpListener;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use atproto_identity::key::{KeyData, KeyType, generate_key};
use atproto_identity::resolve::{resolve_did_document, resolve_handle_http};
use atproto_oauth::dpop::{auth_dpop, dpop_with_nonce};
use atproto_oauth::pkce;
use atproto_oauth::resources::pds_resources;
use atproto_oauth::workflow::{ParResponse, TokenResponse, bind_response_issuer, generate_state};
use godot::prelude::*;
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const PLC_DIRECTORY: &str = "https://plc.directory";
const REDIRECT_PATH: &str = "/callback";
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

struct GodotAtproto;

#[gdextension]
unsafe impl ExtensionLibrary for GodotAtproto {}

enum SignInEvent {
    AuthorizeUrl(String),
    Completed(String),
    Failed(String),
}

/// Entry point for ATProto functionality exposed to GDScript.
///
/// `sign_in` runs the public-client OAuth flow on a background thread. Progress
/// reaches GDScript through the `authorize_url_ready`, `sign_in_completed`, and
/// `sign_in_failed` signals, which are emitted from `process` on the main thread.
#[derive(GodotClass)]
#[class(init, base = Node)]
pub struct AtprotoClient {
    base: Base<Node>,
    events: Option<Receiver<SignInEvent>>,
    did: Option<String>,
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
                    self.signals().authorize_url_ready().emit(&GString::from(url));
                }
                Ok(SignInEvent::Completed(did)) => {
                    self.did = Some(did.clone());
                    self.signals().sign_in_completed().emit(&GString::from(did));
                    return;
                }
                Ok(SignInEvent::Failed(message)) => {
                    self.signals().sign_in_failed().emit(&GString::from(message));
                    return;
                }
                Err(TryRecvError::Empty) => {
                    self.events = Some(rx);
                    return;
                }
                Err(TryRecvError::Disconnected) => return,
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
    fn sign_in_failed(message: GString);

    /// Returns the crate version, to verify the extension is loaded.
    #[func]
    fn version(&self) -> GString {
        env!("CARGO_PKG_VERSION").into()
    }

    /// Starts sign-in for a handle. Returns false if a sign-in is already running.
    #[func]
    fn sign_in(&mut self, handle: GString) -> bool {
        if self.events.is_some() {
            return false;
        }
        let (tx, rx) = mpsc::channel();
        self.events = Some(rx);
        let handle = handle.to_string();
        std::thread::spawn(move || run_sign_in_thread(handle, tx));
        true
    }

    /// The DID of the last completed sign-in, or an empty string.
    #[func]
    fn get_did(&self) -> GString {
        self.did.clone().unwrap_or_default().into()
    }
}

fn run_sign_in_thread(handle: String, tx: Sender<SignInEvent>) {
    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)
        .and_then(|runtime| runtime.block_on(sign_in(&handle, &tx)));
    let event = match outcome {
        Ok(did) => SignInEvent::Completed(did),
        Err(error) => SignInEvent::Failed(format!("{error:#}")),
    };
    let _ = tx.send(event);
}

/// Public-client OAuth: loopback redirect, PAR, PKCE, DPoP, token exchange.
///
/// The `client_id` is the atproto localhost development client, so no hosted
/// metadata is needed. The authorization server must support that exception.
async fn sign_in(handle: &str, tx: &Sender<SignInEvent>) -> anyhow::Result<String> {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()?;

    let did = resolve_handle_http(&http, handle).await?;
    let document = resolve_did_document(&http, PLC_DIRECTORY, &did).await?;
    let pds = document
        .pds_endpoints()
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("DID document for {did} names no PDS"))?;
    let (_, server) = pds_resources(&http, &pds).await?;

    // Bind the loopback listener first: its port goes into the redirect_uri.
    let std_listener = TcpListener::bind("127.0.0.1:0").context("binding loopback listener")?;
    std_listener.set_nonblocking(true)?;
    let port = std_listener.local_addr()?.port();
    let listener = tokio::net::TcpListener::from_std(std_listener)?;
    let redirect_uri = format!("http://127.0.0.1:{port}{REDIRECT_PATH}");

    // Localhost dev client: the localhost exception declares redirect_uri and
    // scope in the query, and the port is ignored when matching.
    let client_id = url::Url::parse_with_params(
        "http://localhost/",
        &[
            ("redirect_uri", format!("http://127.0.0.1{REDIRECT_PATH}")),
            ("scope", "atproto".to_string()),
        ],
    )?
    .to_string();

    let dpop_key = generate_key(KeyType::P256Private)?;
    let (verifier, challenge) = pkce::generate();
    let state = generate_state();

    let par: ParResponse = post_with_dpop(
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
            ("scope", "atproto"),
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
    bind_response_issuer(&server.issuer, callback.issuer.as_deref())?;
    let code = callback.code.context("callback carried no authorization code")?;

    let token: TokenResponse = post_with_dpop(
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
        Some(sub) if sub == did => Ok(did),
        other => bail!("token subject {other:?} does not match handle DID {did}"),
    }
}

/// POSTs a form with a DPoP proof, retrying once with the server's nonce when it asks for one.
async fn post_with_dpop<T: DeserializeOwned>(
    http: &reqwest::Client,
    key: &KeyData,
    url: &str,
    form: &[(&str, &str)],
) -> anyhow::Result<T> {
    let (proof, _, _) = auth_dpop(key, "POST", url)?;
    let mut response = http
        .post(url)
        .header("DPoP", proof)
        .form(form)
        .send()
        .await?;

    if response.status() == StatusCode::BAD_REQUEST {
        let nonce = response
            .headers()
            .get("DPoP-Nonce")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if let Some(nonce) = nonce {
            let (proof, _, _) = dpop_with_nonce(key, "POST", url, None, &nonce)?;
            response = http
                .post(url)
                .header("DPoP", proof)
                .form(form)
                .send()
                .await?;
        }
    }

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("POST {url} failed with {status}: {body}");
    }
    Ok(response.json::<T>().await?)
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
