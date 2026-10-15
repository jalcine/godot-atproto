use std::{
    net::TcpListener,
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
    time::Duration,
};

use anyhow::{Context, anyhow, bail};
use atproto_identity::resolve::resolve_handle_http;
use atproto_identity::{
    key::{KeyData, KeyType, generate_key},
    plc,
};
use atproto_oauth::{
    dpop::auth_dpop,
    jwt::mint,
    pkce,
    resources::pds_resources,
    workflow::{ParResponse, TokenResponse},
};
use rand::distr::{Alphanumeric, SampleString};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use godot::prelude::*;

const PLC_HOSTNAME: &str = "plc.directory";
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
                    self.signals()
                        .authorize_url_ready()
                        .emit(&GString::from(url.as_str()));
                }
                Ok(SignInEvent::Completed(did)) => {
                    self.did = Some(did.clone());
                    self.signals()
                        .sign_in_completed()
                        .emit(&GString::from(did.as_str()));
                    return;
                }
                Ok(SignInEvent::Failed(message)) => {
                    self.signals()
                        .sign_in_failed()
                        .emit(&GString::from(message.as_str()));
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
    /// TODO: Can we return an error instead if self.did == None?
    #[func]
    fn get_did(&self) -> GString {
        GString::from(self.did.as_deref().unwrap_or(""))
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
    if !did.starts_with("did:plc:") {
        // FIXME: Is this true? What is the constraint?
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
            .append_pair("scope", "atproto")
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
        Some(sub) if sub == did => Ok(did),
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

        // FIXME: Allow for customizing this body.
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
