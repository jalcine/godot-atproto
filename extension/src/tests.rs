use super::*;
use serde_json::json;
use tokio::io::AsyncReadExt;

async fn bind_pds() -> anyhow::Result<(tokio::net::TcpListener, String)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    Ok((listener, url))
}

/// Reads one HTTP/1.1 request (head plus Content-Length body) as text.
async fn read_request(stream: &mut tokio::net::TcpStream) -> anyhow::Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("client closed before sending headers");
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    let content_length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .map_or(Ok(0), |v| v.trim().parse::<usize>())?;
    while buf.len() < head_end + content_length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("client closed before sending body");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Answers one scripted response per accepted connection and returns the requests seen.
async fn serve(
    listener: tokio::net::TcpListener,
    responses: Vec<String>,
) -> anyhow::Result<Vec<String>> {
    let mut requests = Vec::new();
    for response in responses {
        let (mut stream, _) = listener.accept().await?;
        requests.push(read_request(&mut stream).await?);
        stream.write_all(response.as_bytes()).await?;
        stream.shutdown().await?;
    }
    Ok(requests)
}

fn respond(status: &str, extra_headers: &[(&str, &str)], body: &str) -> String {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in extra_headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    response.push_str(body);
    response
}

fn test_session(pds: &str) -> Session {
    Session {
        did: "did:plc:test".to_string(),
        pds: pds.to_string(),
        access_token: "token".to_string(),
        dpop_key: generate_key(KeyType::P256Private).expect("generating DPoP key"),
    }
}

#[test]
fn xrpc_call_rejects_malformed_nsid_before_any_request() {
    // The shape check bails first, so this unreachable PDS is never contacted.
    let session = test_session("http://127.0.0.1:1");
    for nsid in ["", "com", "com..example", "com.example.bad!"] {
        let result = run_blocking(xrpc_call(&session, reqwest::Method::GET, nsid, &[], None, None));
        assert!(result.is_err(), "{nsid:?} should be rejected");
    }
}

#[test]
fn get_sends_percent_encoded_params_auth_and_dpop_then_parses_json() {
    run_blocking(async {
        let (listener, url) = bind_pds().await?;
        let server = tokio::spawn(serve(
            listener,
            vec![respond("200 OK", &[], r#"{"ok":true}"#)],
        ));
        let params = [("repo".to_string(), "did:plc:x".to_string())];
        let value = xrpc_call(
            &test_session(&url),
            reqwest::Method::GET,
            "com.example.thing",
            &params,
            None,
            None,
        )
        .await?;
        let requests = server.await??;

        assert_eq!(value, json!({"ok": true}));
        let request = requests[0].to_ascii_lowercase();
        assert!(
            request.starts_with("get /xrpc/com.example.thing?repo=did%3aplc%3ax http/1.1"),
            "{request}"
        );
        assert!(request.contains("authorization: dpop token"), "{request}");
        assert!(request.contains("\r\ndpop: "), "{request}");
        Ok(())
    })
    .expect("GET round trip");
}

#[test]
fn post_sends_json_body() {
    run_blocking(async {
        let (listener, url) = bind_pds().await?;
        let server = tokio::spawn(serve(listener, vec![respond("200 OK", &[], "{}")]));
        let body = json!({"repo": "did:plc:x", "collection": "app.bsky.feed.post"});
        xrpc_call(
            &test_session(&url),
            reqwest::Method::POST,
            "com.example.thing",
            &[],
            Some(&body),
            None,
        )
        .await?;
        let requests = server.await??;

        assert!(
            requests[0].starts_with("POST /xrpc/com.example.thing HTTP/1.1\r\n"),
            "{}",
            requests[0]
        );
        assert!(requests[0].ends_with(&body.to_string()), "{}", requests[0]);
        Ok(())
    })
    .expect("POST round trip");
}

#[test]
fn empty_success_body_maps_to_null() {
    run_blocking(async {
        let (listener, url) = bind_pds().await?;
        let server = tokio::spawn(serve(listener, vec![respond("200 OK", &[], "")]));
        let value = xrpc_call(
            &test_session(&url),
            reqwest::Method::POST,
            "com.example.thing",
            &[],
            None,
            None,
        )
        .await?;
        server.await??;
        assert_eq!(value, Value::Null);
        Ok(())
    })
    .expect("empty body round trip");
}

#[test]
fn retries_once_with_server_nonce_on_401() {
    run_blocking(async {
        let (listener, url) = bind_pds().await?;
        let server = tokio::spawn(serve(
            listener,
            vec![
                respond(
                    "401 Unauthorized",
                    &[("DPoP-Nonce", "server-nonce")],
                    r#"{"error":"use_dpop_nonce"}"#,
                ),
                respond("200 OK", &[], r#"{"ok":true}"#),
            ],
        ));
        let value = xrpc_call(
            &test_session(&url),
            reqwest::Method::GET,
            "com.example.thing",
            &[],
            None,
            None,
        )
        .await?;
        let requests = server.await??;

        assert_eq!(value, json!({"ok": true}));
        assert_eq!(requests.len(), 2);
        Ok(())
    })
    .expect("nonce retry round trip");
}

#[test]
fn unauthorized_without_nonce_fails_without_retry() {
    run_blocking(async {
        let (listener, url) = bind_pds().await?;
        let server = tokio::spawn(serve(listener, vec![respond("401 Unauthorized", &[], "")]));
        let error = xrpc_call(
            &test_session(&url),
            reqwest::Method::GET,
            "com.example.thing",
            &[],
            None,
            None,
        )
        .await
        .expect_err("401 without a nonce must fail");
        let requests = server.await??;

        assert_eq!(requests.len(), 1);
        assert!(format!("{error:#}").contains("401"), "{error:#}");
        Ok(())
    })
    .expect("no-nonce failure");
}

#[test]
fn error_status_and_body_are_reported() {
    run_blocking(async {
        let (listener, url) = bind_pds().await?;
        let body = r#"{"error":"InvalidRequest","message":"bad record"}"#;
        let server = tokio::spawn(serve(listener, vec![respond("400 Bad Request", &[], body)]));
        let error = xrpc_call(
            &test_session(&url),
            reqwest::Method::POST,
            "com.example.thing",
            &[],
            Some(&json!({})),
            None,
        )
        .await
        .expect_err("400 must fail");
        server.await??;

        let message = format!("{error:#}");
        assert!(message.contains("400"), "{message}");
        assert!(message.contains("InvalidRequest"), "{message}");
        Ok(())
    })
    .expect("error reporting");
}
