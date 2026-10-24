use crate::{AppState, block, error};
use axum::{
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderName, Method, StatusCode, header},
    response::Response,
};
use futures_util::StreamExt;
use std::{
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_TARGET_BYTES: usize = 8 * 1024;
const HOP_HEADERS: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "http2-settings",
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
    for name in HOP_HEADERS {
        headers.remove(*name);
    }
}

fn unsafe_envelope(request: &Request) -> Option<(StatusCode, &'static str)> {
    let uri = request.uri();
    let headers = request.headers();
    if uri.scheme().is_some()
        || uri.authority().is_some()
        || !uri.path().starts_with('/')
        || uri.to_string().contains(['#', '\\'])
    {
        return Some((StatusCode::BAD_REQUEST, "invalid-request-target"));
    }
    if uri.to_string().len() > MAX_TARGET_BYTES {
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
    if headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return Some((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "encoded-body-not-supported",
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

pub(crate) async fn forward(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    if let Some((status, code)) = unsafe_envelope(&request) {
        return block(&state, status, code);
    }
    {
        let Some(policy) = state.policy.load_full() else {
            return block(&state, StatusCode::SERVICE_UNAVAILABLE, "sbom-required");
        };
        if let Some(rule) = policy.inspect_method(request.method()) {
            return block(&state, StatusCode::FORBIDDEN, rule);
        }
    }
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
    let policy = state
        .policy
        .load_full()
        .expect("policy cannot be removed after activation");
    if let Some(rule) = policy.inspect_method(&parts.method) {
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
    if let Some(rule) = policy.inspect_bytes(&bytes, false) {
        return block(&state, StatusCode::FORBIDDEN, rule);
    }
    // Prefixing the configured origin avoids URL-join authority overrides (//host).
    let url = match reqwest::Url::parse(&format!(
        "{}{}",
        state.config.upstream.origin().ascii_serialization(),
        target
    )) {
        Ok(url) if url.origin() == state.config.upstream.origin() => url,
        _ => return block(&state, StatusCode::BAD_REQUEST, "invalid-upstream-target"),
    };
    let mut headers = parts.headers;
    strip_hop_headers(&mut headers);
    headers.remove(header::HOST);
    headers.remove(header::CONTENT_LENGTH);
    let forwarding_headers: Vec<_> = headers
        .keys()
        .filter(|name| {
            name.as_str().starts_with("x-forwarded-")
                || matches!(name.as_str(), "forwarded" | "x-real-ip")
        })
        .cloned()
        .collect();
    for name in forwarding_headers {
        headers.remove(name);
    }
    headers.insert("x-forwarded-for", peer.ip().to_string().parse().unwrap());
    headers.insert("x-forwarded-proto", "http".parse().unwrap());
    state.counters.proxied.fetch_add(1, Ordering::Relaxed);
    let upstream = match state
        .client
        .request(parts.method, url)
        .headers(headers)
        .body(bytes)
        .send()
        .await
    {
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
    let mut headers = upstream.headers().clone();
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
