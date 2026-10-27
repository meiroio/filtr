use crate::{
    AppState, block,
    encoding::{self, DecodeError, Encoding},
    error,
};
use axum::{
    body::{Body, Bytes, to_bytes},
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderName, Method, StatusCode, Uri, header},
    response::Response,
};
use futures_util::StreamExt;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_TARGET_BYTES: usize = 8 * 1024;
static HOP_HEADERS: [HeaderName; 10] = [
    HeaderName::from_static("connection"),
    HeaderName::from_static("proxy-connection"),
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("proxy-authenticate"),
    HeaderName::from_static("proxy-authorization"),
    HeaderName::from_static("te"),
    HeaderName::from_static("trailer"),
    HeaderName::from_static("transfer-encoding"),
    HeaderName::from_static("upgrade"),
    HeaderName::from_static("http2-settings"),
];

fn strip_hop_headers(headers: &mut HeaderMap) {
    let nominated: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| name.trim().parse().ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in &HOP_HEADERS {
        headers.remove(name);
    }
}

fn unsafe_envelope(request: &Request) -> Option<(StatusCode, &'static str)> {
    let uri = request.uri();
    let target = uri.path_and_query().map_or("/", |value| value.as_str());
    let headers = request.headers();
    if uri.scheme().is_some()
        || uri.authority().is_some()
        || !uri.path().starts_with('/')
        || target.contains(['#', '\\'])
    {
        return Some((StatusCode::BAD_REQUEST, "invalid-request-target"));
    }
    if target.len() > MAX_TARGET_BYTES {
        return Some((StatusCode::URI_TOO_LONG, "target-too-large"));
    }
    if headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        > MAX_HEADER_BYTES
    {
        return Some((
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "headers-too-large",
        ));
    }
    if !matches!(
        *request.method(),
        Method::GET
            | Method::HEAD
            | Method::POST
            | Method::PUT
            | Method::PATCH
            | Method::DELETE
            | Method::OPTIONS
    ) {
        return Some((StatusCode::METHOD_NOT_ALLOWED, "unsupported-method"));
    }
    if headers.contains_key(header::UPGRADE) || headers.contains_key("http2-settings") {
        return Some((StatusCode::BAD_REQUEST, "protocol-upgrade-not-supported"));
    }
    if headers.contains_key("x-http-method-override")
        || headers.contains_key("x-method-override")
        || headers.contains_key("x-http-method")
    {
        return Some((StatusCode::BAD_REQUEST, "method-override-not-supported"));
    }
    if headers.get_all(header::CONNECTION).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value.split(',').any(|name| {
                name.trim().eq_ignore_ascii_case("content-encoding")
                    || name.trim().eq_ignore_ascii_case("content-type")
            })
        })
    }) {
        // Hop-header stripping must not change how upstream interprets inspected bytes.
        return Some((
            StatusCode::BAD_REQUEST,
            "connection-nominates-content-metadata",
        ));
    }
    if headers.get_all(header::CONTENT_TYPE).iter().any(|v| {
        let content_type = String::from_utf8_lossy(v.as_bytes()).to_ascii_lowercase();
        content_type.split(';').skip(1).any(|parameter| {
            parameter.split_once('=').is_some_and(|(key, value)| {
                key.trim() == "charset" && value.trim().trim_matches('"') != "utf-8"
            })
        })
    }) {
        return Some((StatusCode::UNSUPPORTED_MEDIA_TYPE, "charset-not-supported"));
    }
    if headers.contains_key(header::CONTENT_LENGTH)
        && headers.contains_key(header::TRANSFER_ENCODING)
    {
        return Some((StatusCode::BAD_REQUEST, "ambiguous-body-framing"));
    }
    // Trailers are not part of the inspected request representation in this MVP.
    if headers.contains_key(header::TRAILER) || headers.contains_key(header::TRANSFER_ENCODING) {
        return Some((StatusCode::BAD_REQUEST, "chunked-request-not-supported"));
    }
    None
}

fn upstream_url(origin: &reqwest::Url, uri: &Uri) -> reqwest::Url {
    // Path/query setters cannot replace the configured authority, even for //host paths.
    let mut url = origin.clone();
    url.set_path(uri.path());
    url.set_query(uri.query());
    url
}

struct CancelDecode(Arc<AtomicBool>);

impl Drop for CancelDecode {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

async fn inspectable_body(
    state: &AppState,
    encoding: Encoding,
    bytes: Bytes,
) -> Result<Bytes, DecodeError> {
    if encoding == Encoding::Identity {
        return Ok(bytes);
    }
    let permit = state
        .decoders
        .clone()
        .try_acquire_owned()
        .map_err(|_| DecodeError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            reason: "body-decode-capacity-exceeded",
        })?;
    let cancellation = CancelDecode(Arc::new(AtomicBool::new(false)));
    let flag = cancellation.0.clone();
    let timeout = Duration::from_secs(state.config.timeout_secs);
    let deadline = Instant::now() + timeout;
    let limit = state.config.max_body_bytes;
    let task = tokio::task::spawn_blocking(move || {
        // A dropped/expired async request cannot release capacity while CPU work runs.
        let _permit = permit;
        encoding::decode(encoding, &bytes, limit, deadline, &flag).map(Bytes::from)
    });
    match tokio::time::timeout(timeout, task).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(DecodeError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            reason: "body-decode-failed",
        }),
        Err(_) => Err(DecodeError {
            status: StatusCode::REQUEST_TIMEOUT,
            reason: "body-decode-timeout",
        }),
    }
}

pub(crate) async fn forward(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    if let Some(reason) = state.traffic.block_reason() {
        return block(&state, StatusCode::FORBIDDEN, reason);
    }
    {
        let Some(policy) = state.policy.load_full() else {
            return block(&state, StatusCode::SERVICE_UNAVAILABLE, "sbom-required");
        };
        if let Some(rule) = policy.inspect_request(
            request.method(),
            request.uri().path(),
            request.headers(),
            &[],
        ) {
            return block(&state, StatusCode::FORBIDDEN, rule);
        }
    }
    if let Some((status, code)) = unsafe_envelope(&request) {
        return block(&state, status, code);
    }
    let encoding = match Encoding::parse(request.headers()) {
        Ok(encoding) => encoding,
        Err(error) => return block(&state, error.status, error.reason),
    };
    let metadata = match crate::forwarding::Metadata::read(
        &state.config.forwarding,
        request.headers(),
        peer.ip(),
    ) {
        Ok(metadata) => metadata,
        Err(_) => {
            return block(
                &state,
                StatusCode::BAD_REQUEST,
                "invalid-forwarding-metadata",
            );
        }
    };
    let (parts, body) = request.into_parts();
    let bytes = match tokio::time::timeout(
        Duration::from_secs(state.config.timeout_secs),
        to_bytes(body, state.config.max_body_bytes),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            return block(
                &state,
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid-or-oversized-body",
            );
        }
        Err(_) => return block(&state, StatusCode::REQUEST_TIMEOUT, "request-body-timeout"),
    };
    if (parts.method == Method::GET || parts.method == Method::HEAD) && !bytes.is_empty() {
        return block(
            &state,
            StatusCode::BAD_REQUEST,
            "read-method-body-not-supported",
        );
    }
    let inspected = match inspectable_body(&state, encoding, bytes.clone()).await {
        Ok(body) => body,
        Err(error) => return block(&state, error.status, error.reason),
    };
    let Some(policy) = state.policy.load_full() else {
        return block(&state, StatusCode::SERVICE_UNAVAILABLE, "sbom-required");
    };
    if let Some(reason) = state.traffic.block_reason() {
        return block(&state, StatusCode::FORBIDDEN, reason);
    }
    if let Some(rule) =
        policy.inspect_request(&parts.method, parts.uri.path(), &parts.headers, &inspected)
    {
        return block(&state, StatusCode::FORBIDDEN, rule);
    }
    let target = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    if let Some(rule) = policy.inspect_bytes(target.as_bytes(), true) {
        return block(&state, StatusCode::FORBIDDEN, rule);
    }
    for (name, value) in &parts.headers {
        if let Some(rule) = policy
            .inspect_bytes(name.as_str().as_bytes(), false)
            .or_else(|| policy.inspect_bytes(value.as_bytes(), false))
        {
            return block(&state, StatusCode::FORBIDDEN, rule);
        }
    }
    if let Some(rule) = policy.inspect_bytes(&inspected, false) {
        return block(&state, StatusCode::FORBIDDEN, rule);
    }
    drop(inspected);
    let url = upstream_url(&state.config.upstream, &parts.uri);
    let mut headers = parts.headers;
    strip_hop_headers(&mut headers);
    headers.remove(header::CONTENT_LENGTH);
    metadata.apply(&mut headers);
    state.counters.proxied.fetch_add(1, Ordering::Relaxed);
    let mut request = reqwest::Request::new(parts.method, url);
    *request.headers_mut() = headers;
    *request.body_mut() = Some(bytes.into());
    let mut upstream = match state.client.execute(request).await {
        Ok(response) => response,
        Err(upstream_error) => {
            state
                .counters
                .upstream_errors
                .fetch_add(1, Ordering::Relaxed);
            let status = if upstream_error.is_timeout() {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            };
            tracing::warn!(status = status.as_u16(), "upstream request failed");
            return error(status, "upstream-unavailable");
        }
    };
    if upstream.status().is_informational() {
        state
            .counters
            .upstream_errors
            .fetch_add(1, Ordering::Relaxed);
        return error(StatusCode::BAD_GATEWAY, "unexpected-upstream-upgrade");
    }
    let status = upstream.status();
    let mut headers = std::mem::take(upstream.headers_mut());
    strip_hop_headers(&mut headers);
    let stream = upstream.bytes_stream().map(move |result| {
        if result.is_err() {
            state
                .counters
                .upstream_errors
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!("upstream response stream failed");
        }
        result
    });
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abandoned_decode_requests_keep_capacity_until_workers_exit() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let state = AppState::new(crate::Config {
                listen: "127.0.0.1:8080".parse().unwrap(),
                admin_listen: "127.0.0.1:9090".parse().unwrap(),
                upstream: "http://127.0.0.1:3000".parse().unwrap(),
                admin_token: "a".repeat(128),
                sbom: directory.path().join("missing-sbom.json"),
                rules: None,
                forwarding: Default::default(),
                ai: crate::ai::AiConfig {
                    cache_ttl_secs: 0,
                    ..Default::default()
                },
                webhook: Default::default(),
                auto_block_critical: false,
                max_body_bytes: 1024,
                timeout_secs: 1,
                max_in_flight: 1,
            })
            .await
            .unwrap();
            for abort_request in [true, false] {
                let (release, waiting) = std::sync::mpsc::channel();
                let (started, start) = tokio::sync::oneshot::channel();
                let occupied = tokio::task::spawn_blocking(move || {
                    let _ = started.send(());
                    // A failed assertion cannot leave runtime shutdown waiting forever.
                    let _ = waiting.recv_timeout(Duration::from_secs(5));
                });
                tokio::time::timeout(Duration::from_secs(2), start)
                    .await
                    .unwrap()
                    .unwrap();
                let worker_state = state.clone();
                let request = tokio::spawn(async move {
                    inspectable_body(
                        &worker_state,
                        Encoding::Gzip,
                        Bytes::from_static(&[
                            31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ]),
                    )
                    .await
                });
                tokio::time::timeout(Duration::from_secs(2), async {
                    while state.decoders.available_permits() != 0 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                if abort_request {
                    request.abort();
                    assert!(request.await.unwrap_err().is_cancelled());
                } else {
                    let error = request.await.unwrap().unwrap_err();
                    assert_eq!(error.status, StatusCode::REQUEST_TIMEOUT);
                    assert_eq!(error.reason, "body-decode-timeout");
                }
                assert_eq!(state.decoders.available_permits(), 0);
                let error = inspectable_body(&state, Encoding::Gzip, Bytes::new())
                    .await
                    .unwrap_err();
                assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(error.reason, "body-decode-capacity-exceeded");
                assert_eq!(
                    inspectable_body(&state, Encoding::Identity, Bytes::from_static(b"plain"))
                        .await
                        .unwrap(),
                    "plain"
                );
                release.send(()).unwrap();
                occupied.await.unwrap();
                let permit = tokio::time::timeout(
                    Duration::from_secs(2),
                    state.decoders.clone().acquire_owned(),
                )
                .await
                .unwrap()
                .unwrap();
                drop(permit);
                assert_eq!(state.decoders.available_permits(), 1);
            }
        });
    }

    #[test]
    fn upstream_setters_preserve_serialization_and_fixed_authority() {
        let mut targets = vec![
            "/".to_owned(),
            "//elsewhere.invalid:81/path?x=1".to_owned(),
            "///elsewhere.invalid/path".to_owned(),
            "/https://elsewhere.invalid/path".to_owned(),
            "/a%2Fb/%25/%E2%82%AC?x=a%2Fb&y=+%25".to_owned(),
            "/empty?".to_owned(),
            "/a/./b/../c?x=../value".to_owned(),
        ];
        targets.extend(
            (b'!'..=b'~')
                .filter(|byte| !b"#\\".contains(byte))
                .map(|byte| format!("/segment{}tail?x=%2F&y=+%25", char::from(byte))),
        );
        for origin in [
            "http://127.0.0.1:3000",
            "https://example.com",
            "http://[::1]:8081",
        ] {
            let origin = reqwest::Url::parse(origin).unwrap();
            for target in &targets {
                let Ok(uri) = target.parse::<Uri>() else {
                    continue;
                };
                let expected = reqwest::Url::parse(&format!(
                    "{}{}",
                    origin.origin().ascii_serialization(),
                    uri
                ))
                .unwrap();
                let actual = upstream_url(&origin, &uri);
                assert_eq!(actual.origin(), origin.origin(), "{target}");
                assert_eq!(actual, expected, "{target}");
            }
        }
    }
}
