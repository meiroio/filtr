use axum::{
    Json, Router,
    body::to_bytes,
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use filtr::{AppState, Config, routers};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const VULNERABLE: &str = r#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"log4j-core","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}"#;
const PATCHED: &str = r#"{"format":"filtr-1","packages":[{"purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.26.0"}]}"#;
const RSC: &str =
    r#"{"format":"filtr-1","packages":[{"purl":"pkg:npm/react-server-dom-webpack@19.1.0"}]}"#;
const PREVIEW_OLD: &str =
    r#"{"format":"filtr-1","packages":[{"purl":"pkg:maven/example/component@1.0.0.RELEASE"}]}"#;
const PREVIEW_NEW: &str =
    r#"{"format":"filtr-1","packages":[{"purl":"pkg:maven/example/component@1.0.1.RELEASE"}]}"#;

struct Harness {
    public: String,
    admin: String,
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    client: reqwest::Client,
    tasks: Vec<JoinHandle<()>>,
    ai_config: filtr::ai::AiConfig,
}

impl Drop for Harness {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Harness {
    async fn start(sbom: &Path) -> Self {
        Self::start_with_services(sbom, None).await
    }

    async fn start_with_services(sbom: &Path, ai: Option<Router>) -> Self {
        let config = filtr::ai::AiConfig {
            cache_ttl_secs: 0,
            api_key: ai.as_ref().map(|_| "test-openai-key".into()),
            ai_timeout_secs: 1,
            ..Default::default()
        };
        let ai = ai
            .map(|router| router.route("/leaderboard", get(|| async { Json(test_leaderboard()) })));
        Self::start_configured(sbom, ai, config).await
    }

    async fn start_configured(
        sbom: &Path,
        ai: Option<Router>,
        ai_config: filtr::ai::AiConfig,
    ) -> Self {
        Self::start_configured_with_webhook(sbom, ai, ai_config, Default::default()).await
    }

    async fn start_configured_with_webhook(
        sbom: &Path,
        ai: Option<Router>,
        ai_config: filtr::ai::AiConfig,
        webhook: filtr::webhook::Config,
    ) -> Self {
        Self::start_controlled(sbom, ai, ai_config, webhook, false).await
    }

    async fn start_controlled(
        sbom: &Path,
        ai: Option<Router>,
        mut ai_config: filtr::ai::AiConfig,
        webhook: filtr::webhook::Config,
        auto_block: bool,
    ) -> Self {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let public_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut service_tasks = Vec::new();
        if let Some(ai) = ai {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url: reqwest::Url = format!("http://{}", listener.local_addr().unwrap())
                .parse()
                .unwrap();
            service_tasks.push(tokio::spawn(async move {
                axum::serve(listener, ai).await.unwrap();
            }));
            ai_config.url = url.clone();
            ai_config.anthropic_url = url.clone();
            ai_config.leaderboard_url = url.join("leaderboard").unwrap();
        }
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let upstream = Router::new().fallback(move |request: Request| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                echo(request).await
            }
        });
        let config = Config {
            listen: public_listener.local_addr().unwrap(),
            admin_listen: admin_listener.local_addr().unwrap(),
            upstream: format!("http://{}", upstream_listener.local_addr().unwrap())
                .parse()
                .unwrap(),
            admin_token: TOKEN.into(),
            sbom: sbom.into(),
            rules: None,
            forwarding: Default::default(),
            ai: ai_config,
            webhook,
            auto_block_critical: auto_block,
            max_body_bytes: 1024,
            timeout_secs: 1,
            max_in_flight: 4,
        };
        let addr = config.listen;
        let public = format!("http://{}", config.listen);
        let admin = format!("http://{}", config.admin_listen);
        let ai_config = config.ai.clone();
        let state = AppState::new(config).await.unwrap();
        let (proxy, administration) = routers(state);
        let mut tasks = vec![
            tokio::spawn(async move {
                axum::serve(upstream_listener, upstream).await.unwrap();
            }),
            tokio::spawn(async move {
                axum::serve(
                    public_listener,
                    proxy.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .unwrap();
            }),
            tokio::spawn(async move {
                axum::serve(admin_listener, administration).await.unwrap();
            }),
        ];
        tasks.extend(service_tasks);
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        Self {
            public,
            admin,
            addr,
            hits,
            client,
            tasks,
            ai_config,
        }
    }

    async fn upload(&self, sbom: &str) -> reqwest::Response {
        upload_options(self, sbom, "").await
    }

    async fn preview(&self, sbom: &str, cache_only: bool) -> Value {
        self.admin_report(
            self.client
                .post(format!("{}/v1/preview?cache_only={cache_only}", self.admin))
                .header("content-type", "application/json")
                .body(sbom.to_owned()),
        )
        .await
    }

    async fn status(&self) -> Value {
        self.admin_report(self.client.get(format!("{}/v1/status", self.admin)))
            .await
    }

    async fn admin_report(&self, request: reqwest::RequestBuilder) -> Value {
        let response = request.bearer_auth(TOKEN).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
    }

    async fn traffic(&self, mode: &str) -> Value {
        self.admin_report(
            self.client
                .post(format!("{}/v1/traffic", self.admin))
                .header("content-type", "application/json")
                .body(json!({"mode":mode,"reason":"Operator test decision"}).to_string()),
        )
        .await
    }

    async fn wait_for(&self, pointer: &str, expected: Value) -> Value {
        tokio::time::timeout(std::time::Duration::from_millis(500), async {
            loop {
                let status = self.status().await;
                if status.pointer(pointer) == Some(&expected) {
                    return status;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap()
    }
}

async fn echo(request: Request) -> Response {
    if request.uri().path() == "/redirect" {
        return (StatusCode::FOUND, [(header::LOCATION, "/elsewhere")]).into_response();
    }
    if request.uri().path() == "/slow" {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 2048).await.unwrap();
    let mut response = (
        StatusCode::CREATED,
        Json(json!({
            "uri": parts.uri.to_string(), "method": parts.method.to_string(),
            "body": String::from_utf8_lossy(&body),
            "body_bytes": body.to_vec(),
            "content_encoding": parts.headers.get(header::CONTENT_ENCODING).and_then(|v| v.to_str().ok()),
            "forwarded_for": parts.headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
            "host": parts.headers.get("host").and_then(|v| v.to_str().ok()),
            "scheme": parts.headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()),
            "forwarded": parts.headers.contains_key("forwarded"),
            "secret_header": parts.headers.contains_key("x-secret"),
            "cookie": parts.headers.get("cookie").and_then(|v| v.to_str().ok())
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert("connection", HeaderValue::from_static("x-response-secret"));
    response.headers_mut().insert(
        "x-response-secret",
        HeaderValue::from_static("must-be-stripped"),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static("a=1; HttpOnly"),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static("b=2; HttpOnly"),
    );
    response
}

#[tokio::test]
async fn requires_sbom_and_authenticates_separate_admin_plane() {
    let directory = tempfile::tempdir().unwrap();
    let app = Harness::start(&directory.path().join("sbom.json")).await;
    let response = app
        .client
        .get(format!("{}/v1/status", app.public))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(app.hits.load(Ordering::SeqCst), 0);
    for endpoint in ["/livez", "/healthz", "/v1/status", "/v1/remediation"] {
        for token in [None, Some("wrong-token")] {
            let mut request = app.client.get(format!("{}{endpoint}", app.admin));
            if let Some(token) = token {
                request = request.bearer_auth(token);
            }
            assert_eq!(
                request.send().await.unwrap().status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }
    assert_eq!(app.status().await["ready"], false);
    assert_eq!(
        app.upload("{}").await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(app.status().await["ready"], false);
}

#[tokio::test]
async fn readiness_requires_an_sbom_but_liveness_does_not() {
    let directory = tempfile::tempdir().unwrap();
    let app = Harness::start(&directory.path().join("sbom.json")).await;
    for (endpoint, expected) in [
        ("/livez", StatusCode::OK),
        ("/healthz", StatusCode::SERVICE_UNAVAILABLE),
        ("/v1/remediation", StatusCode::SERVICE_UNAVAILABLE),
    ] {
        assert_eq!(
            app.client
                .get(format!("{}{endpoint}", app.admin))
                .bearer_auth(TOKEN)
                .send()
                .await
                .unwrap()
                .status(),
            expected
        );
    }
    app.upload(PATCHED).await;
    assert_eq!(
        app.client
            .get(format!("{}/healthz", app.admin))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn forwards_original_request_and_preserves_response_status_headers_and_cookies() {
    let directory = tempfile::tempdir().unwrap();
    let app = Harness::start(&directory.path().join("sbom.json")).await;
    assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
    let response = app
        .client
        .post(format!("{}/echo?hello=a%2Fb", app.public))
        .header("connection", "x-secret")
        .header("x-secret", "strip-me")
        .header("x-forwarded-for", "attacker")
        .header("host", "public.example:8443")
        .header("x-forwarded-proto", "https")
        .header("forwarded", "for=attacker")
        .header("cookie", "session=abc")
        .body("unchanged + %41")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(!response.headers().contains_key("x-response-secret"));
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        2
    );
    let body: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(body["uri"], "/echo?hello=a%2Fb");
    assert_eq!(body["body"], "unchanged + %41");
    assert_eq!(body["forwarded_for"], "127.0.0.1");
    assert_eq!(body["host"], "public.example:8443");
    assert_eq!(body["scheme"], "http");
    assert_eq!(body["forwarded"], false);
    assert_eq!(body["secret_header"], false);
    assert_eq!(body["cookie"], "session=abc");
    let response = app
        .client
        .get(format!("{}/redirect", app.public))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()[header::LOCATION], "/elsewhere");
    assert_eq!(app.hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn blocks_payloads_before_upstream_and_swaps_policy_without_restart() {
    let directory = tempfile::tempdir().unwrap();
    let app = Harness::start(&directory.path().join("sbom.json")).await;
    assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
    let requests = [
        app.client
            .get(format!("{}/?q=%2524%257Bjndi:x%257D", app.public)),
        app.client
            .get(&app.public)
            .header("x-test", "${${lower:j}ndi:x}"),
        app.client
            .post(&app.public)
            .body(r#"{"value":"\u0024\u007bjndi:x}"}"#),
    ];
    for request in requests {
        assert_eq!(
            request.send().await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(app.hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        app.upload("not JSON").await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        app.status().await["policy"]["active_rules"][0]["id"],
        "log4shell-lookups"
    );
    assert_eq!(app.upload(PATCHED).await.status(), StatusCode::OK);
    assert_eq!(
        app.client
            .post(&app.public)
            .body("${legitimate}")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(app.upload(RSC).await.status(), StatusCode::OK);
    for method in [
        reqwest::Method::POST,
        reqwest::Method::PUT,
        reqwest::Method::OPTIONS,
        reqwest::Method::DELETE,
    ] {
        assert_eq!(
            app.client
                .request(method, &app.public)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
    }
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(app.hits.load(Ordering::SeqCst), 6);
    assert_eq!(app.status().await["counters"]["blocked"], 3);
}

#[tokio::test]
async fn saves_uploads_and_restores_policy_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nested/sbom.json");
    let app = Harness::start(&path).await;
    assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), VULNERABLE);
    drop(app);
    let restarted = Harness::start(&path).await;
    assert_eq!(restarted.status().await["ready"], true);
    assert_eq!(
        restarted
            .client
            .post(&restarted.public)
            .body("${jndi:x}")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(restarted.hits.load(Ordering::SeqCst), 0);
}

struct CompressedBodyFixture {
    encoding: &'static str,
    benign: &'static [u8],
    marker: &'static [u8],
    nul: &'static [u8],
    at_limit: &'static [u8],
    over_limit: &'static [u8],
}

// Encoded with Bun 1.4.4's node:zlib. Decoded bodies are, respectively:
// 96 deterministic alphanumeric bytes; the existing inert ${jndi:test} marker;
// "benign\0body"; 1024 'x' bytes; and 1025 'x' bytes. All three benign wire
// representations contain NUL bytes, which must not be scanned as plaintext.
const COMPRESSED_BODY_FIXTURES: &[CompressedBodyFixture] = &[
    CompressedBodyFixture {
        encoding: "br",
        benign: &[
            27, 95, 0, 248, 101, 112, 94, 204, 135, 226, 182, 219, 13, 112, 137, 132, 82, 212, 48,
            232, 253, 219, 59, 232, 220, 207, 45, 188, 158, 140, 255, 40, 44, 202, 202, 213, 92,
            154, 57, 228, 100, 174, 242, 7, 210, 186, 102, 179, 177, 176, 74, 189, 118, 118, 163,
            176, 210, 50, 157, 242, 76, 111, 244, 12, 91, 206, 196, 245, 118, 129, 66, 16, 189,
            202, 189, 233, 147, 8, 184, 136, 8, 160, 100, 71, 88, 162, 87, 247, 243, 2,
        ],
        marker: &[
            139, 5, 128, 36, 123, 106, 110, 100, 105, 58, 116, 101, 115, 116, 125, 3,
        ],
        nul: &[
            11, 5, 128, 98, 101, 110, 105, 103, 110, 0, 98, 111, 100, 121, 3,
        ],
        at_limit: &[27, 255, 3, 248, 37, 240, 162, 177, 64, 32, 55],
        over_limit: &[27, 0, 4, 248, 37, 240, 162, 177, 64, 64, 55],
    },
    CompressedBodyFixture {
        encoding: "gzip",
        benign: &[
            31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 51, 43, 170, 44, 202, 116, 10, 44, 43, 47, 115, 173,
            8, 246, 48, 170, 114, 14, 75, 78, 73, 13, 242, 14, 50, 51, 47, 246, 136, 204, 75, 77,
            42, 119, 50, 243, 241, 14, 176, 136, 112, 45, 112, 207, 242, 46, 201, 204, 113, 45, 48,
            243, 48, 138, 202, 77, 74, 244, 73, 247, 73, 52, 204, 47, 137, 12, 10, 46, 114, 53,
            117, 118, 114, 174, 240, 44, 43, 244, 201, 117, 115, 180, 12, 55, 14, 117, 114, 15, 8,
            55, 140, 244, 73, 45, 43, 175, 0, 0, 63, 24, 237, 228, 96, 0, 0, 0,
        ],
        marker: &[
            31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 83, 169, 206, 202, 75, 201, 180, 42, 73, 45, 46, 169,
            5, 0, 40, 152, 17, 51, 12, 0, 0, 0,
        ],
        nul: &[
            31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 75, 74, 205, 203, 76, 207, 99, 72, 202, 79, 169, 4, 0,
            104, 120, 247, 137, 11, 0, 0, 0,
        ],
        at_limit: &[
            31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 171, 168, 24, 5, 163, 96, 20, 84, 140, 80, 0, 0, 99,
            240, 215, 72, 0, 4, 0, 0,
        ],
        over_limit: &[
            31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 171, 168, 24, 5, 163, 96, 20, 84, 140, 84, 0, 0, 145,
            241, 47, 88, 1, 4, 0, 0,
        ],
    },
    CompressedBodyFixture {
        encoding: "deflate",
        benign: &[
            120, 156, 51, 43, 170, 44, 202, 116, 10, 44, 43, 47, 115, 173, 8, 246, 48, 170, 114,
            14, 75, 78, 73, 13, 242, 14, 50, 51, 47, 246, 136, 204, 75, 77, 42, 119, 50, 243, 241,
            14, 176, 136, 112, 45, 112, 207, 242, 46, 201, 204, 113, 45, 48, 243, 48, 138, 202, 77,
            74, 244, 73, 247, 73, 52, 204, 47, 137, 12, 10, 46, 114, 53, 117, 118, 114, 174, 240,
            44, 43, 244, 201, 117, 115, 180, 12, 55, 14, 117, 114, 15, 8, 55, 140, 244, 73, 45, 43,
            175, 0, 0, 70, 198, 32, 166,
        ],
        marker: &[
            120, 156, 83, 169, 206, 202, 75, 201, 180, 42, 73, 45, 46, 169, 5, 0, 28, 248, 4, 188,
        ],
        nul: &[
            120, 156, 75, 74, 205, 203, 76, 207, 99, 72, 202, 79, 169, 4, 0, 24, 212, 4, 34,
        ],
        at_limit: &[
            120, 156, 171, 168, 24, 5, 163, 96, 20, 84, 140, 80, 0, 0, 44, 79, 224, 16,
        ],
        over_limit: &[
            120, 156, 171, 168, 24, 5, 163, 96, 20, 84, 140, 84, 0, 0, 12, 230, 224, 136,
        ],
    },
];

#[tokio::test]
async fn compressed_requests_inspect_decoded_body_and_preserve_wire_envelope() {
    let directory = tempfile::tempdir().unwrap();
    let app = Harness::start(&directory.path().join("sbom.json")).await;
    assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
    for fixture in COMPRESSED_BODY_FIXTURES {
        assert!(fixture.benign.contains(&0));
        let response = app
            .client
            .post(&app.public)
            .header(header::CONTENT_ENCODING, fixture.encoding)
            .body(fixture.benign)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "{}",
            fixture.encoding
        );
        let forwarded: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(forwarded["body_bytes"], json!(fixture.benign));
        assert_eq!(forwarded["content_encoding"], fixture.encoding);
        for (name, body) in [
            ("rule marker", fixture.marker),
            ("decoded NUL", fixture.nul),
        ] {
            let response = app
                .client
                .post(&app.public)
                .header(header::CONTENT_ENCODING, fixture.encoding)
                .body(body)
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{} {name}",
                fixture.encoding
            );
        }
    }
    assert_eq!(app.hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn compressed_requests_bound_wire_and_decoded_size() {
    let directory = tempfile::tempdir().unwrap();
    let app = Harness::start(&directory.path().join("sbom.json")).await;
    assert_eq!(app.upload(PATCHED).await.status(), StatusCode::OK);
    for fixture in COMPRESSED_BODY_FIXTURES {
        for (name, body, expected) in [
            (
                "at decoded limit",
                fixture.at_limit.to_vec(),
                StatusCode::CREATED,
            ),
            (
                "over decoded limit",
                fixture.over_limit.to_vec(),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                "over wire limit",
                vec![b'x'; 1025],
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            let response = app
                .client
                .post(&app.public)
                .header(header::CONTENT_ENCODING, fixture.encoding)
                .body(body)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{} {name}", fixture.encoding);
        }
    }
    assert_eq!(app.hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn compressed_requests_reject_malformed_truncated_and_trailing_data() {
    let directory = tempfile::tempdir().unwrap();
    let app = Harness::start(&directory.path().join("sbom.json")).await;
    assert_eq!(app.upload(PATCHED).await.status(), StatusCode::OK);
    for fixture in COMPRESSED_BODY_FIXTURES {
        for (name, body) in [
            ("empty", Vec::new()),
            ("malformed", vec![255; 4]),
            (
                "truncated",
                fixture.benign[..fixture.benign.len() - 1].to_vec(),
            ),
            ("trailing garbage", [fixture.benign, b"trailing"].concat()),
        ] {
            let response = app
                .client
                .post(&app.public)
                .header(header::CONTENT_ENCODING, fixture.encoding)
                .body(body)
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{} {name}",
                fixture.encoding
            );
        }
        if fixture.encoding != "gzip" {
            let response = app
                .client
                .post(&app.public)
                .header(header::CONTENT_ENCODING, fixture.encoding)
                .body([fixture.benign, fixture.benign].concat())
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{} concatenated streams",
                fixture.encoding
            );
        }
    }
    assert_eq!(app.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn compressed_requests_inspect_all_gzip_members_with_aggregate_limit() {
    let directory = tempfile::tempdir().unwrap();
    let app = Harness::start(&directory.path().join("sbom.json")).await;
    assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
    let fixture = COMPRESSED_BODY_FIXTURES
        .iter()
        .find(|fixture| fixture.encoding == "gzip")
        .unwrap();
    let benign = [fixture.benign, fixture.benign].concat();
    let response = app
        .client
        .post(&app.public)
        .header(header::CONTENT_ENCODING, "gzip")
        .body(benign.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let forwarded: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(forwarded["body_bytes"], json!(benign));
    assert_eq!(forwarded["content_encoding"], "gzip");
    for (name, body, expected) in [
        (
            "marker in second member",
            [fixture.benign, fixture.marker].concat(),
            StatusCode::FORBIDDEN,
        ),
        (
            "NUL in second member",
            [fixture.benign, fixture.nul].concat(),
            StatusCode::FORBIDDEN,
        ),
        (
            "aggregate decoded limit",
            [fixture.at_limit, fixture.benign].concat(),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            "trailing garbage",
            [fixture.benign, fixture.benign, b"trailing"].concat(),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let response = app
            .client
            .post(&app.public)
            .header(header::CONTENT_ENCODING, "gzip")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{name}");
    }
    assert_eq!(app.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn compressed_requests_honor_kill_switch_changed_during_body_upload() {
    let directory = tempfile::tempdir().unwrap();
    let app = Harness::start(&directory.path().join("sbom.json")).await;
    assert_eq!(app.upload(PATCHED).await.status(), StatusCode::OK);
    let fixture = COMPRESSED_BODY_FIXTURES
        .iter()
        .find(|fixture| fixture.encoding == "gzip")
        .unwrap();
    let mut stream = TcpStream::connect(app.addr).await.unwrap();
    let headers = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        fixture.benign.len(),
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    let split = fixture.benign.len() / 2;
    stream.write_all(&fixture.benign[..split]).await.unwrap();
    app.wait_for("/counters/seen", json!(1)).await;

    assert_eq!(app.traffic("block_all").await["effective"], "blocked");
    stream.write_all(&fixture.benign[split..]).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert_eq!(app.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn compressed_requests_reject_ambiguous_or_unsupported_codings() {
    let directory = tempfile::tempdir().unwrap();
    let app = Harness::start(&directory.path().join("sbom.json")).await;
    assert_eq!(app.upload(PATCHED).await.status(), StatusCode::OK);
    for encoding in [
        "compress",
        "zstd",
        "gzip, br",
        "identity, gzip",
        "gzip, gzip",
    ] {
        let response = app
            .client
            .post(&app.public)
            .header(header::CONTENT_ENCODING, encoding)
            .body("body")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{encoding}"
        );
    }
    for second in ["br", "gzip"] {
        let response = app
            .client
            .post(&app.public)
            .header(header::CONTENT_ENCODING, "br")
            .header(header::CONTENT_ENCODING, second)
            .body("body")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "duplicate br/{second}"
        );
    }
    for connection in ["close, Content-Encoding", "close, Content-Type"] {
        let response = app
            .client
            .post(&app.public)
            .header(header::CONTENT_ENCODING, "br")
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::CONNECTION, connection)
            .body(COMPRESSED_BODY_FIXTURES[0].benign)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{connection}");
    }
    assert_eq!(app.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn refuses_uninspectable_envelopes_and_bounds_body_size() {
    let directory = tempfile::tempdir().unwrap();
    let app = Harness::start(&directory.path().join("sbom.json")).await;
    app.upload(PATCHED).await;
    let cases = [
        (
            app.client
                .post(&app.public)
                .header("content-encoding", "gzip")
                .body("compressed"),
            StatusCode::BAD_REQUEST,
        ),
        (
            app.client
                .post(&app.public)
                .header("content-encoding", "br")
                .body("harmless Brotli envelope test"),
            StatusCode::BAD_REQUEST,
        ),
        (
            app.client
                .post(&app.public)
                .header("content-type", "text/plain; charset = utf-16")
                .body("body"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            app.client.get(&app.public).body("unexpected"),
            StatusCode::BAD_REQUEST,
        ),
        (
            app.client.get(&app.public).header("upgrade", "websocket"),
            StatusCode::BAD_REQUEST,
        ),
        (
            app.client
                .get(&app.public)
                .header("x-http-method-override", "POST"),
            StatusCode::BAD_REQUEST,
        ),
        (
            app.client.post(&app.public).body(vec![b'x'; 1025]),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            app.client.post(&app.public).body(vec![0]),
            StatusCode::FORBIDDEN,
        ),
        (
            app.client.request(reqwest::Method::TRACE, &app.public),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
    ];
    for (request, expected) in cases {
        assert_eq!(request.send().await.unwrap().status(), expected);
    }
    for raw in [
        "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nx\r\n0\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\nConnection: close\r\n\r\n0\r\n\r\n",
        "GET http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n",
    ] {
        let mut stream = TcpStream::connect(app.addr).await.unwrap();
        stream.write_all(raw.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            response.starts_with(b"HTTP/1.1 400"),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }
    assert_eq!(app.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn returns_gateway_timeout_instead_of_hanging() {
    let directory = tempfile::tempdir().unwrap();
    let app = Harness::start(&directory.path().join("sbom.json")).await;
    app.upload(PATCHED).await;
    let response = app
        .client
        .get(format!("{}/slow", app.public))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(app.status().await["counters"]["upstream_errors"], 1);
}

#[tokio::test]
async fn failed_persistence_keeps_active_policy() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sbom.json");
    let app = Harness::start(&path).await;
    assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert_eq!(
        app.upload(PATCHED).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        app.client
            .post(&app.public)
            .body("${jndi:x}")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(app.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn bounds_concurrency_and_times_out_stalled_bodies() {
    let directory = tempfile::tempdir().unwrap();
    let app = Harness::start(&directory.path().join("sbom.json")).await;
    app.upload(PATCHED).await;
    let mut stalled = Vec::new();
    for _ in 0..4 {
        let mut stream = TcpStream::connect(app.addr).await.unwrap();
        stream.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nConnection: close\r\n\r\n").await.unwrap();
        stalled.push(stream);
    }
    app.wait_for("/counters/seen", json!(4)).await;
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    for mut stream in stalled {
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 408"));
    }
    assert_eq!(app.hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
}

fn openai_reply(enhancements: Value) -> Value {
    json!({"id":"resp-test", "status":"completed", "output":[{"type":"message", "content":[{
        "type":"output_text", "text":review_text(enhancements)
    }]}]})
}

fn review_text(enhancements: Value) -> String {
    json!({"summary":"Reviewed the supplied inventory and evidence.", "enhancements":enhancements, "discoveries":[]})
        .to_string()
}

fn assert_cve_now_research_guidance(instructions: &str) {
    let guidance = instructions
        .split_once("site:cve.now")
        .expect("research must include a targeted cve.now search")
        .1
        .to_ascii_lowercase();
    assert!(guidance.contains("primary") && guidance.contains("advis"));
    assert!(guidance.contains("check") || guidance.contains("verif"));
    assert!(guidance.contains("native web search"));
    assert!(instructions.contains("at most 3 searches per batch"));
}

#[tokio::test]
async fn anthropic_discovers_missing_cves_with_search_provenance_and_cached_continuation() {
    let directory = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let searched = json!([
        {"type":"server_tool_use","id":"search-1","name":"web_search","input":{"query":"fictional-runtime security advisory"}},
        {"type":"web_search_tool_result","tool_use_id":"search-1","content":[{"type":"web_search_result","url":"https://vendor.example/security/advisory","encrypted_content":"opaque-provider-data"}]}
    ]);
    let ai = Router::new().route("/leaderboard", get(|| async { Json(test_leaderboard()) }))
        .route("/v1/messages", post(move |Json(request): Json<Value>| {
            let count = count.clone();
            let searched = searched.clone();
            async move {
                assert_eq!(request["cache_control"]["type"], "ephemeral");
                assert_eq!(request["system"][0]["cache_control"]["type"], "ephemeral");
                assert_cve_now_research_guidance(request["system"][0]["text"].as_str().unwrap());
                assert_eq!(request["tools"][0]["type"], "web_search_20250305");
                assert_eq!(request["tools"][0]["max_uses"], 5);
                assert_eq!(request["tools"][1]["strict"], true);
                match count.fetch_add(1, Ordering::SeqCst) {
                    0 => Json(json!({"id":"paused","stop_reason":"pause_turn","content":searched,
                        "usage":{"input_tokens":100,"output_tokens":50,"cache_creation_input_tokens":200,"server_tool_use":{"web_search_requests":1}}})),
                    1 => {
                        assert_eq!(request["messages"][1]["role"], "assistant");
                        assert_eq!(request["messages"][1]["content"], searched);
                        Json(json!({"id":"researched","stop_reason":"tool_use","content":[{"type":"tool_use","name":"submit_review","input":{
                            "summary":"Found a vendor advisory through web research.","enhancements":[],"discoveries":[
                                {"component_index":0,"cve":"CVE-2026-999901","source":"https://uncited.example/advisory","reason":"An invalid duplicate must not suppress later valid evidence.","fixed_version":"1.0.1"},
                                {"component_index":0,"cve":"CVE-2026-999901","source":"https://vendor.example/security/advisory","reason":"The vendor reports the exact installed version as affected.","fixed_version":"1.0.1"},
                                {"component_index":0,"cve":"CVE-2026-999902","source":"https://invented.example/advisory","reason":"Uncited source must be rejected.","fixed_version":"1.0.1"},
                                {"component_index":999,"cve":"CVE-2026-999903","source":"https://vendor.example/security/advisory","reason":"Unknown component must be rejected.","fixed_version":"1.0.1"}
                            ]}}],"usage":{"input_tokens":20,"output_tokens":30,"cache_read_input_tokens":200}}))
                    }
                    _ => Json(json!({"id":"search-failed","stop_reason":"end_turn","content":[{"type":"web_search_tool_result","content":{"type":"web_search_tool_result_error","error_code":"unavailable"}}]})),
                }
            }
        }));
    let config = filtr::ai::AiConfig {
        cache_ttl_secs: 0,
        anthropic_api_key: Some("test-anthropic-key".into()),
        ai_timeout_secs: 1,
        ..Default::default()
    };
    let app =
        Harness::start_configured(&directory.path().join("sbom.json"), Some(ai), config).await;
    app.upload(r#"{"format":"filtr-1","packages":[{"purl":"pkg:npm/fictional-runtime@1.0.0"}]}"#)
        .await;
    let status = app.status().await;
    assert_eq!(status["policy"]["ai"]["status"], "partial");
    assert_eq!(
        status["policy"]["ai"]["discoveries"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        status["policy"]["ai"]["rejected"].as_array().unwrap().len(),
        3
    );
    assert_eq!(
        status["policy"]["ai"]["usage"],
        json!({"input_tokens":120,"output_tokens":80,"cache_creation_input_tokens":200,"cache_read_input_tokens":200,"web_search_requests":1})
    );
    assert_eq!(
        status["policy"]["generated_rules"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        status["policy"]["ai"]["discoveries"][0]["cve"],
        "CVE-2026-999901"
    );
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(app.hits.load(Ordering::SeqCst), 1);
    app.upload(r#"{"format":"filtr-1","packages":[{"purl":"pkg:npm/fictional-runtime@1.0.1"}]}"#)
        .await;
    let status = app.status().await;
    assert_eq!(status["policy"]["ai"]["status"], "failed");
    assert_eq!(status["policy"]["generated_rules"], json!([]));
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn openai_discoveries_require_native_web_search_sources() {
    let directory = tempfile::tempdir().unwrap();
    let ai = Router::new().route("/v1/responses", post(|Json(request): Json<Value>| async move {
        assert_cve_now_research_guidance(request["instructions"].as_str().unwrap());
        assert_eq!(request["tools"][0]["type"], "web_search");
        assert_eq!(request["tools"].as_array().unwrap().len(), 1);
        assert_eq!(request["max_tool_calls"], 5);
        assert_eq!(request["include"], json!(["web_search_call.action.sources"]));
        Json(json!({"id":"researched","status":"completed","output":[
            {"type":"web_search_call","status":"completed","action":{"sources":[{"url":"https://vendor.example/security/advisory"}]}},
            {"type":"message","content":[{"type":"output_text","text":json!({"summary":"A new vendor finding.","enhancements":[],"discoveries":[
                {"component_index":0,"cve":"CVE-2026-999904","source":"https://vendor.example/security/advisory","reason":"Exact installed version is affected according to the vendor.","fixed_version":"1.0.1"}
            ]}).to_string()}]}
        ],"usage":{"input_tokens":1000,"output_tokens":100,"input_tokens_details":{"cached_tokens":500}}}))
    }));
    let app = Harness::start_with_services(&directory.path().join("sbom.json"), Some(ai)).await;
    app.upload(r#"{"format":"filtr-1","packages":[{"purl":"pkg:npm/fictional-runtime@1.0.0"}]}"#)
        .await;
    let review = &app.status().await["policy"]["ai"];
    assert_eq!(review["status"], "complete");
    assert_eq!(review["discoveries"][0]["cve"], "CVE-2026-999904");
    assert_eq!(review["usage"]["cache_read_input_tokens"], 500);
    assert_eq!(review["usage"]["web_search_requests"], 1);
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
}

fn test_leaderboard() -> Value {
    json!({"results":[
        {"rank":8,"modelId":"openai/gpt-5.6-luna","reasoning":"xhigh"},
        {"rank":4,"modelId":"anthropic/claude-opus-5","reasoning":"max"},
        {"rank":1,"modelId":"openai/gpt-6-sol","reasoning":"xhigh"}
    ]})
}

fn anthropic_reply(enhancements: Value) -> Value {
    json!({"id":"msg-test", "stop_reason":"end_turn", "content":[
        {"type":"thinking", "thinking":"not used by Filtr"},
        {"type":"text", "text":review_text(enhancements)}
    ]})
}

#[tokio::test]
async fn anthropic_uses_its_ranked_model_and_native_structured_output() {
    let directory = tempfile::tempdir().unwrap();
    let ai = Router::new()
        .route("/leaderboard", get(|headers: axum::http::HeaderMap| async move {
            assert!(!headers.contains_key(header::AUTHORIZATION));
            assert!(!headers.contains_key("x-api-key"));
            Json(test_leaderboard())
        }))
        .route("/v1/messages", post(|headers: axum::http::HeaderMap, Json(request): Json<Value>| async move {
            assert_eq!(headers["x-api-key"], "test-anthropic-key");
            assert_eq!(headers["anthropic-version"], "2023-06-01");
            assert!(!headers.contains_key(header::AUTHORIZATION));
            assert_eq!(request["model"], "claude-opus-5");
            assert_eq!(request["thinking"]["type"], "adaptive");
            assert_eq!(request["tool_choice"]["disable_parallel_tool_use"], true);
            assert_eq!(request["output_config"]["effort"], "max");
            assert_eq!(request["cache_control"]["type"], "ephemeral");
            assert_eq!(request["system"][0]["cache_control"]["type"], "ephemeral");
            assert_cve_now_research_guidance(request["system"][0]["text"].as_str().unwrap());
            assert_eq!(request["tools"][0]["name"], "web_search");
            assert_eq!(request["tools"][0]["type"], "web_search_20250305");
            assert_eq!(request["tools"][0]["max_uses"], 5);
            assert_eq!(request["tools"].as_array().unwrap().len(), 2);
            assert_eq!(request["tools"][1]["name"], "submit_review");
            assert_eq!(request["tools"][1]["strict"], true);
            let input: Value = serde_json::from_str(request["messages"][0]["content"].as_str().unwrap()).unwrap();
            assert_eq!(input["components"].as_array().unwrap().len(), 1);
            assert!(!request.to_string().contains(TOKEN));
            Json(anthropic_reply(json!([{"component_index":0,"basis":"log4shell-lookups","action":"tokens","patterns":["claude-test-marker"],"reason":"Additive test marker."}])))
        }));
    let config = filtr::ai::AiConfig {
        cache_ttl_secs: 0,
        anthropic_api_key: Some("test-anthropic-key".into()),
        ai_timeout_secs: 1,
        ..Default::default()
    };
    let app =
        Harness::start_configured(&directory.path().join("sbom.json"), Some(ai), config).await;
    assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
    let status = app.status().await;
    assert_eq!(status["policy"]["ai"]["status"], "complete");
    assert_eq!(status["policy"]["ai"]["provider"], "anthropic");
    assert_eq!(status["policy"]["ai"]["leaderboard_rank"], 4);
    assert_eq!(status["policy"]["ai"]["fallback_used"], false);
    assert_eq!(
        status["policy"]["ai"]["attempts"].as_array().unwrap().len(),
        1
    );
    assert!(!status.to_string().contains("test-anthropic-key"));
    assert_eq!(
        app.client
            .post(&app.public)
            .body("claude-test-marker")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn anthropic_failure_falls_back_to_luna_with_separate_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let ai = Router::new()
        .route("/leaderboard", get(|| async { Json(test_leaderboard()) }))
        .route(
            "/v1/messages",
            post(
                |headers: axum::http::HeaderMap, Json(request): Json<Value>| async move {
                    assert_eq!(headers["x-api-key"], "test-anthropic-key");
                    assert_eq!(request["model"], "claude-opus-5");
                    StatusCode::SERVICE_UNAVAILABLE
                },
            ),
        )
        .route(
            "/v1/responses",
            post(
                |headers: axum::http::HeaderMap, Json(request): Json<Value>| async move {
                    assert_eq!(headers[header::AUTHORIZATION], "Bearer test-openai-key");
                    assert!(!headers.contains_key("x-api-key"));
                    assert_eq!(request["model"], "gpt-5.6-luna");
                    assert_eq!(request["reasoning"]["effort"], "xhigh");
                    Json(openai_reply(json!([])))
                },
            ),
        );
    let config = filtr::ai::AiConfig {
        cache_ttl_secs: 0,
        provider: Some(filtr::ai::Provider::Anthropic),
        api_key: Some("test-openai-key".into()),
        anthropic_api_key: Some("test-anthropic-key".into()),
        ai_timeout_secs: 1,
        ..Default::default()
    };
    let app =
        Harness::start_configured(&directory.path().join("sbom.json"), Some(ai), config).await;
    app.upload(VULNERABLE).await;
    let review = &app.status().await["policy"]["ai"];
    assert_eq!(review["status"], "complete");
    assert_eq!(review["fallback_used"], true);
    assert_eq!(review["provider"], "openai");
    assert_eq!(review["model"], "gpt-5.6-luna");
    assert_eq!(review["attempts"][0]["model"], "claude-opus-5");
    assert!(
        review["attempts"][0]["error"]
            .as_str()
            .unwrap()
            .contains("503")
    );
    assert!(review["attempts"][1]["error"].is_null());
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn leaderboard_refreshes_each_upload_and_primary_timeout_uses_luna() {
    let directory = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let ai = Router::new().route("/leaderboard", get(move || {
        let count = count.clone();
        async move {
            let model = if count.fetch_add(1, Ordering::SeqCst) == 0 { "gpt-6-sol" } else { "new-leader" };
            Json(json!({"results":[{"rank":1,"modelId":format!("openai/{model}"),"reasoning":"xhigh"}]}))
        }
    })).route("/v1/responses", post(|Json(request): Json<Value>| async move {
        if request["model"] == "gpt-6-sol" {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        } else {
            assert!(request["model"] == "gpt-5.6-luna" || request["model"] == "new-leader");
        }
        Json(openai_reply(json!([])))
    }));
    let config = filtr::ai::AiConfig {
        cache_ttl_secs: 0,
        api_key: Some("test-openai-key".into()),
        ai_timeout_secs: 1,
        ..Default::default()
    };
    let app =
        Harness::start_configured(&directory.path().join("sbom.json"), Some(ai), config).await;
    app.upload(VULNERABLE).await;
    let review = &app.status().await["policy"]["ai"];
    assert_eq!(review["status"], "complete");
    assert_eq!(review["model"], "gpt-5.6-luna");
    assert_eq!(review["attempts"][0]["model"], "gpt-6-sol");
    assert!(
        review["attempts"][0]["error"]
            .as_str()
            .unwrap()
            .contains("timed out")
    );
    app.upload(VULNERABLE).await;
    let review = &app.status().await["policy"]["ai"];
    assert_eq!(review["status"], "complete");
    assert_eq!(review["model"], "new-leader");
    assert_eq!(review["fallback_used"], false);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn leaderboard_is_reused_on_restart_and_refreshed_only_by_valid_uploads() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sbom.json");
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let ai = Router::new().route("/leaderboard", get(move || {
        let count = count.clone();
        async move {
            let model = if count.fetch_add(1, Ordering::SeqCst) == 0 { "first-winner" } else { "second-winner" };
            Json(json!({"results":[{"rank":1,"modelId":format!("openai/{model}"),"reasoning":"xhigh"}]}))
        }
    })).route("/v1/responses", post(|| async { Json(openai_reply(json!([]))) }));
    let config = filtr::ai::AiConfig {
        cache_ttl_secs: 0,
        api_key: Some("test-openai-key".into()),
        ai_timeout_secs: 1,
        ..Default::default()
    };
    let app = Harness::start_configured(&path, Some(ai.clone()), config.clone()).await;
    app.upload(VULNERABLE).await;
    assert_eq!(app.status().await["policy"]["ai"]["model"], "first-winner");
    assert_eq!(
        app.status().await["policy"]["ai"]["leaderboard_source"],
        "sbom_update"
    );
    assert!(directory.path().join("sbom.json.leaderboard.json").exists());
    drop(app);
    let restarted = Harness::start_configured(&path, Some(ai.clone()), config.clone()).await;
    let review = &restarted.status().await["policy"]["ai"];
    assert_eq!(review["model"], "first-winner");
    assert_eq!(review["leaderboard_source"], "saved_snapshot");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        restarted.upload("not json").await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    restarted.upload(PATCHED).await;
    assert_eq!(
        restarted.status().await["policy"]["ai"]["model"],
        "second-winner"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(restarted);
    // Editing the persisted inventory cannot make its old leaderboard snapshot applicable.
    std::fs::write(&path, VULNERABLE).unwrap();
    let changed = Harness::start_configured(&path, Some(ai), config).await;
    let review = &changed.status().await["policy"]["ai"];
    assert_eq!(review["model"], "gpt-5.6-luna");
    assert!(
        review["selection_error"]
            .as_str()
            .unwrap()
            .contains("different inventory")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn missing_or_corrupt_saved_leaderboards_never_trigger_startup_fetches() {
    for cache in [None, Some("not json")] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sbom.json");
        std::fs::write(&path, VULNERABLE).unwrap();
        if let Some(cache) = cache {
            std::fs::write(directory.path().join("sbom.json.leaderboard.json"), cache).unwrap();
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let ai = Router::new()
            .route(
                "/leaderboard",
                get(move || {
                    let count = count.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        Json(test_leaderboard())
                    }
                }),
            )
            .route(
                "/v1/responses",
                post(|Json(request): Json<Value>| async move {
                    assert_eq!(request["model"], "gpt-5.6-luna");
                    Json(openai_reply(json!([])))
                }),
            );
        let config = filtr::ai::AiConfig {
            cache_ttl_secs: 0,
            api_key: Some("test-openai-key".into()),
            ai_timeout_secs: 1,
            ..Default::default()
        };
        let app = Harness::start_configured(&path, Some(ai), config).await;
        let review = &app.status().await["policy"]["ai"];
        assert_eq!(review["status"], "complete");
        assert_eq!(review["fallback_used"], true);
        assert!(
            review["selection_error"]
                .as_str()
                .unwrap()
                .contains("saved leaderboard unavailable")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn invalid_leaderboards_use_luna_only_when_openai_is_configured() {
    for has_openai in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let ai = Router::new()
            .route("/leaderboard", get(|| async { "not JSON" }))
            .route(
                "/v1/responses",
                post(move |Json(request): Json<Value>| {
                    let count = count.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(request["model"], "gpt-5.6-luna");
                        Json(openai_reply(json!([])))
                    }
                }),
            );
        let config = filtr::ai::AiConfig {
            cache_ttl_secs: 0,
            api_key: has_openai.then(|| "test-openai-key".into()),
            anthropic_api_key: Some("test-anthropic-key".into()),
            ai_timeout_secs: 1,
            ..Default::default()
        };
        let app =
            Harness::start_configured(&directory.path().join("sbom.json"), Some(ai), config).await;
        app.upload(VULNERABLE).await;
        let status = app.status().await;
        let review = &status["policy"]["ai"];
        assert!(
            review["selection_error"]
                .as_str()
                .unwrap()
                .contains("invalid Leaderboard JSON")
        );
        assert_eq!(
            review["status"],
            if has_openai { "complete" } else { "failed" }
        );
        assert_eq!(review["fallback_used"], has_openai);
        assert_eq!(calls.load(Ordering::SeqCst), usize::from(has_openai));
        assert_eq!(status["policy"]["generated_rules"], json!([]));
        assert_eq!(
            app.client
                .post(&app.public)
                .body("${jndi:test}")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
}

#[tokio::test]
async fn anthropic_refusals_and_truncation_keep_static_mappings_without_openai() {
    for stop_reason in ["refusal", "max_tokens", "tool_use"] {
        let directory = tempfile::tempdir().unwrap();
        let ai = Router::new()
            .route("/leaderboard", get(|| async { Json(test_leaderboard()) }))
            .route(
                "/v1/messages",
                post(move || async move {
                    let mut reply = anthropic_reply(json!([]));
                    reply["stop_reason"] = json!(stop_reason);
                    Json(reply)
                }),
            );
        let config = filtr::ai::AiConfig {
            cache_ttl_secs: 0,
            anthropic_api_key: Some("test-anthropic-key".into()),
            ai_timeout_secs: 1,
            ..Default::default()
        };
        let app =
            Harness::start_configured(&directory.path().join("sbom.json"), Some(ai), config).await;
        app.upload(VULNERABLE).await;
        let status = app.status().await;
        assert_eq!(status["policy"]["ai"]["status"], "failed");
        assert_eq!(
            status["policy"]["ai"]["attempts"].as_array().unwrap().len(),
            1
        );
        assert_eq!(status["policy"]["generated_rules"], json!([]));
        assert_eq!(
            app.client.get(&app.public).send().await.unwrap().status(),
            StatusCode::CREATED
        );
        assert_eq!(
            app.client
                .post(&app.public)
                .body("${jndi:test}")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
}

#[tokio::test]
async fn uncovered_findings_notify_without_blocking_and_clear_after_patching() {
    let directory = tempfile::tempdir().unwrap();
    let (webhook_url, mut events, webhook_task) = recording_webhook(StatusCode::NO_CONTENT).await;
    let ai = Router::new().route(
        "/v1/responses",
        post(|Json(request): Json<Value>| async move {
            let input: Value =
                serde_json::from_str(request["input"][0]["content"].as_str().unwrap()).unwrap();
            Json(if input["components"][0]["version"] == "1.0.0.RELEASE" {
                discovery_reply()
            } else {
                openai_reply(json!([]))
            })
        }),
    );
    let app = Harness::start_configured_with_webhook(
        &directory.path().join("sbom.json"),
        Some(ai.route("/leaderboard", get(|| async { Json(test_leaderboard()) }))),
        filtr::ai::AiConfig {
            cache_ttl_secs: 0,
            api_key: Some("test-openai-key".into()),
            ..Default::default()
        },
        filtr::webhook::Config {
            webhook_url: Some(webhook_url),
            ..Default::default()
        },
    )
    .await;
    let vulnerable =
        r#"{"format":"filtr-1","packages":[{"purl":"pkg:maven/example/component@1.0.0.RELEASE"}]}"#;
    app.upload(vulnerable).await;
    let status = app.status().await;
    assert_eq!(status["policy"]["generated_rules"], json!([]));
    assert_eq!(
        status["policy"]["ai"]["discoveries"][0]["cve"],
        "CVE-2026-12345"
    );
    let (_, blocked, _) = tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(blocked["remediation"]["quarantined"], false);
    assert_eq!(
        blocked["remediation"]["uncovered_vulnerabilities"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(blocked["remediation"]["ai_review"]["status"], "complete");
    for method in [
        reqwest::Method::GET,
        reqwest::Method::HEAD,
        reqwest::Method::POST,
        reqwest::Method::OPTIONS,
        reqwest::Method::PUT,
    ] {
        assert_eq!(
            app.client
                .request(method, &app.public)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
    }
    assert_eq!(app.hits.load(Ordering::SeqCst), 5);
    assert_eq!(app.upload(PATCHED).await.status(), StatusCode::OK);
    assert_eq!(app.status().await["policy"]["generated_rules"], json!([]));
    let (_, restored, _) = tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored["remediation"]["quarantined"], false);
    assert_eq!(restored["remediation"]["ai_review"]["status"], "complete");
    assert_eq!(restored["remediation"]["blockers"], json!([]));
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    webhook_task.abort();
}

#[tokio::test]
async fn restart_without_ai_uses_static_rules() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sbom.json");
    let ai = Router::new().fallback(|| async { Json(discovery_reply()) });
    let app = Harness::start_with_services(&path, Some(ai)).await;
    app.upload(VULNERABLE).await;
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    drop(app);
    let restarted = Harness::start(&path).await;
    let status = restarted.status().await;
    assert_eq!(status["policy"]["ai"]["status"], "not_configured");
    assert_eq!(status["policy"]["generated_rules"], json!([]));
    assert_eq!(
        restarted
            .client
            .get(&restarted.public)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        restarted
            .client
            .post(&restarted.public)
            .body("${jndi:test}")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(restarted.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn openai_enhances_curated_rules_without_replacing_them() {
    let directory = tempfile::tempdir().unwrap();
    let ai = Router::new().route("/v1/responses", post(|headers: axum::http::HeaderMap, Json(request): Json<Value>| async move {
        assert_eq!(headers[header::AUTHORIZATION], "Bearer test-openai-key");
        assert_eq!(request["model"], "gpt-6-sol");
        assert_eq!(request["reasoning"]["effort"], "xhigh");
        assert_eq!(request["store"], false);
        assert_eq!(request["text"]["format"]["strict"], true);
        let input: Value = serde_json::from_str(request["input"][0]["content"].as_str().unwrap()).unwrap();
        assert_eq!(input["components"].as_array().unwrap().len(), 1);
        assert_eq!(input["curated_rules"][0]["id"], "log4shell-lookups");
        assert!(input.get("findings").is_none());
        assert!(input.get("osv").is_none());
        assert!(!request.to_string().contains(TOKEN));
        Json(openai_reply(json!([{"component_index":0,"basis":"log4shell-lookups","action":"tokens","patterns":["ai-added-marker"],"reason":"Test additive marker justified by supplied evidence."}])))
    }));
    let app = Harness::start_with_services(&directory.path().join("sbom.json"), Some(ai)).await;
    assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
    let status = app.status().await;
    assert_eq!(status["policy"]["ai"]["status"], "complete");
    assert_eq!(status["policy"]["ai"]["components_reviewed"], 1);
    assert_eq!(status["policy"]["ai"]["applied_rules"], json!(["ai:0"]));
    assert_eq!(
        status["policy"]["active_rules"][0]["id"],
        "log4shell-lookups"
    );
    assert!(!status.to_string().contains("test-openai-key"));
    for marker in ["ai-added-marker", "${jndi:test}"] {
        assert_eq!(
            app.client
                .post(&app.public)
                .body(marker)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    let rules = app
        .client
        .get(format!("{}/v1/rules", app.admin))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    let rules: Value = serde_json::from_str(&rules.text().await.unwrap()).unwrap();
    assert_eq!(rules["generated_rules"][0]["origin"], "ai");
}

#[tokio::test]
async fn broad_or_invalid_ai_proposals_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let ai = Router::new().fallback(|| async { Json(openai_reply(json!([
        {"component_index":0,"basis":"log4shell-lookups","action":"deny_all","patterns":[],"reason":"An additive test marker."},
        {"component_index":0,"basis":"log4shell-lookups","action":"allow","patterns":[],"reason":"Remove quarantine."},
        {"component_index":99,"basis":"log4shell-lookups","action":"deny_all","patterns":[],"reason":"Invalid component."},
        {"component_index":0,"basis":"CVE-2099-99999","action":"deny_all","patterns":[],"reason":"Invented CVE."},
        {"component_index":0,"basis":"log4shell-lookups","action":"tokens","patterns":[],"reason":"Empty patterns."}
    ]))) });
    let app = Harness::start_with_services(&directory.path().join("sbom.json"), Some(ai)).await;
    app.upload(VULNERABLE).await;
    let status = app.status().await;
    assert_eq!(status["policy"]["ai"]["status"], "partial");
    assert_eq!(
        status["policy"]["ai"]["rejected"].as_array().unwrap().len(),
        5
    );
    assert_eq!(status["policy"]["ai"]["applied_rules"], json!([]));
    assert_eq!(status["policy"]["generated_rules"], json!([]));
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(app.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ai_failures_replace_previous_enhancements_with_static_rules() {
    let cases = [
        (
            StatusCode::TOO_MANY_REQUESTS,
            json!({"error":"rate limited"}),
        ),
        (
            StatusCode::OK,
            json!({"id":"resp-test", "status":"incomplete", "output":[]}),
        ),
        (
            StatusCode::OK,
            json!({"id":"resp-test", "status":"completed", "output":[{"type":"message","content":[{"type":"refusal"}]}]}),
        ),
        (
            StatusCode::OK,
            json!({"id":"resp-test", "status":"completed", "output":[{"type":"message","content":[{"type":"output_text","text":"not json"}]}]}),
        ),
    ];
    for (code, value) in cases {
        let directory = tempfile::tempdir().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let ai = Router::new().fallback(move || {
            let value = value.clone();
            let calls = calls.clone();
            async move {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    (StatusCode::OK, Json(openai_reply(json!([{"component_index":0,"basis":"log4shell-lookups","action":"tokens","patterns":["previous-ai-marker"],"reason":"An additive test marker."}]))))
                } else {
                    (code, Json(value))
                }
            }
        });
        let app = Harness::start_with_services(&directory.path().join("sbom.json"), Some(ai)).await;
        assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
        assert_eq!(app.status().await["policy"]["ai"]["status"], "complete");
        assert_eq!(
            app.client.get(&app.public).send().await.unwrap().status(),
            StatusCode::CREATED
        );
        assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
        let status = app.status().await;
        assert_eq!(status["policy"]["ai"]["status"], "failed");
        assert_eq!(status["policy"]["ai"]["applied_rules"], json!([]));
        assert_eq!(status["policy"]["ai"]["fallback_used"], true);
        assert_eq!(
            status["policy"]["ai"]["attempts"].as_array().unwrap().len(),
            2
        );
        assert_eq!(status["policy"]["generated_rules"], json!([]));
        assert_eq!(
            app.client
                .post(&app.public)
                .body("previous-ai-marker")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            app.client
                .post(&app.public)
                .body("${jndi:test}")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
}

fn discovery_reply() -> Value {
    json!({"id":"research", "status":"completed", "output":[
        {"type":"web_search_call","status":"completed","action":{"sources":[{"url":"https://vendor.example/advisory"}]}},
        {"type":"message","content":[{"type":"output_text","text":json!({"summary":"An affected installed version.","enhancements":[],"discoveries":[
            {"component_index":0,"cve":"CVE-2026-12345","source":"https://vendor.example/advisory","reason":"The vendor lists this exact version as affected through HTTP.","fixed_version":"1.0.1.RELEASE"}
        ]}).to_string()}]}
    ]})
}

fn targeted_reply() -> Value {
    let mut response = discovery_reply();
    let mut payload: Value = serde_json::from_str(
        response["output"][1]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    payload["discoveries"][0]["restriction"] = json!({"methods":[],"path_prefix":"","headers":[{"name":"x-test-exploit","kind":"exact","value":"yes"}],"body_patterns":[]});
    payload["discoveries"][0]["coverage_note"] = json!("Test marker scopes this request class.");
    response["output"][1]["content"][0]["text"] = json!(payload.to_string());
    response
}

fn emergency_reply() -> Value {
    let mut response = discovery_reply();
    response["output"][0]["action"]["sources"]
        .as_array_mut()
        .unwrap()
        .push(json!({"url":"https://vendor.example/active-exploitation"}));
    let mut payload: Value = serde_json::from_str(
        response["output"][1]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    payload["discoveries"][0]["emergency"] = json!({"critical":true,"remotely_exploitable":true,"authentication_required":false,"actively_exploited":true,"affects_http1_upstream":true,"source":"https://vendor.example/active-exploitation","reason":"Test evidence supports an actively exploited unauthenticated critical HTTP/1 issue without a narrow mitigation."});
    payload["discoveries"][0]["coverage_note"] =
        json!("No supported narrow mitigation in this test.");
    response["output"][1]["content"][0]["text"] = json!(payload.to_string());
    response
}

#[tokio::test]
async fn manual_traffic_mode_persists_and_resumes_filters_without_bypass() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sbom.json");
    let (url, mut events, task) = recording_webhook(StatusCode::NO_CONTENT).await;
    let app = Harness::start_configured_with_webhook(
        &path,
        None,
        Default::default(),
        filtr::webhook::Config {
            webhook_url: Some(url),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        app.client
            .post(format!("{}/v1/traffic", app.admin))
            .body(r#"{"mode":"block_all","reason":"test"}"#)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for body in [
        r#"{"mode":"bypass","reason":"bad"}"#,
        r#"{"mode":"filter","reason":""}"#,
        r#"{"mode":"block_all","reason":"x","unknown":true}"#,
    ] {
        assert_eq!(
            app.client
                .post(format!("{}/v1/traffic", app.admin))
                .bearer_auth(TOKEN)
                .body(body)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    assert_eq!(app.traffic("block_all").await["effective"], "blocked");
    let (_, event, _) = tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event["trigger"], "traffic_mode");
    assert_eq!(event["remediation"]["traffic"]["mode"], "block_all");
    assert_eq!(event["remediation"]["quarantined"], true);
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    app.upload(VULNERABLE).await;
    app.preview(PATCHED, true).await;
    app.upload(PATCHED).await;
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    drop(app);
    let restarted = Harness::start(&path).await;
    assert_eq!(restarted.status().await["traffic"]["mode"], "block_all");
    assert_eq!(
        restarted
            .client
            .get(&restarted.public)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(restarted.traffic("filter").await["effective"], "filtering");
    restarted.upload(VULNERABLE).await;
    assert_eq!(
        restarted
            .client
            .get(&restarted.public)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        restarted
            .client
            .post(&restarted.public)
            .body("${jndi:test}")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let state_path = directory.path().join("sbom.json.traffic.json");
    std::fs::remove_file(&state_path).unwrap();
    std::fs::create_dir(&state_path).unwrap();
    assert_eq!(
        restarted
            .client
            .post(format!("{}/v1/traffic", restarted.admin))
            .bearer_auth(TOKEN)
            .body(r#"{"mode":"block_all","reason":"Cannot persist"}"#)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(restarted.status().await["traffic"]["mode"], "filter");
    task.abort();
}

#[tokio::test]
async fn scoped_brotli_rule_blocks_before_decoding_and_patched_sbom_restores_requests() {
    let directory = tempfile::tempdir().unwrap();
    let mut response = targeted_reply();
    let mut payload: Value = serde_json::from_str(
        response["output"][1]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    payload["discoveries"][0]["restriction"]["headers"] =
        json!([{"name":"content-encoding","kind":"exact","value":"br"}]);
    payload["discoveries"][0]["coverage_note"] =
        json!("Synthetic fixture restricts incoming Brotli-encoded requests only.");
    response["output"][1]["content"][0]["text"] = json!(payload.to_string());
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let ai = Router::new().route(
        "/v1/responses",
        post(move |Json(request): Json<Value>| {
            let response = response.clone();
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                let input: Value =
                    serde_json::from_str(request["input"][0]["content"].as_str().unwrap()).unwrap();
                Json(if input["components"][0]["version"] == "1.0.0.RELEASE" {
                    response
                } else {
                    openai_reply(json!([]))
                })
            }
        }),
    );
    let app = Harness::start_with_services(&directory.path().join("sbom.json"), Some(ai)).await;
    assert_eq!(app.upload(PREVIEW_OLD).await.status(), StatusCode::OK);
    assert_eq!(
        app.status().await["policy"]["generated_rules"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let fixture = &COMPRESSED_BODY_FIXTURES[0];
    for body in [fixture.benign, b"malformed Brotli fixture".as_slice()] {
        let response = app
            .client
            .post(&app.public)
            .header(header::CONTENT_ENCODING, "br")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(
        app.client
            .post(&app.public)
            .header(header::CONTENT_ENCODING, "identity")
            .body("normal traffic")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(app.hits.load(Ordering::SeqCst), 1);

    assert_eq!(app.upload(PREVIEW_NEW).await.status(), StatusCode::OK);
    assert_eq!(app.status().await["policy"]["generated_rules"], json!([]));
    let response = app
        .client
        .post(&app.public)
        .header(header::CONTENT_ENCODING, "br")
        .body(fixture.benign)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let forwarded: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(forwarded["body_bytes"], json!(fixture.benign));
    assert_eq!(forwarded["content_encoding"], "br");
    assert_eq!(
        app.client
            .post(&app.public)
            .body("normal traffic")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(app.hits.load(Ordering::SeqCst), 3);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn targeted_ai_rule_blocks_only_matching_header_class() {
    let directory = tempfile::tempdir().unwrap();
    let ai = Router::new().fallback(|| async { Json(targeted_reply()) });
    let app = Harness::start_with_services(&directory.path().join("sbom.json"), Some(ai)).await;
    app.upload(PREVIEW_OLD).await;
    assert_eq!(
        app.status().await["policy"]["generated_rules"][0]["action"]["type"],
        "request"
    );
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(
        app.client
            .post(&app.public)
            .body("normal JSON")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        app.client
            .get(&app.public)
            .header("x-test-exploit", "no")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        app.client
            .get(&app.public)
            .header("x-test-exploit", "YES")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let report = app
        .admin_report(app.client.get(format!("{}/v1/remediation", app.admin)))
        .await;
    assert_eq!(report["quarantined"], false);
    assert_eq!(report["summary"]["blocking_rules"], 1);
    assert_eq!(report["summary"]["uncovered_findings"], 0);
}

#[tokio::test]
async fn critical_auto_block_is_opt_in_and_operator_filter_wins() {
    let directory = tempfile::tempdir().unwrap();
    let ai = Router::new()
        .route("/leaderboard", get(|| async { Json(test_leaderboard()) }))
        .route(
            "/v1/responses",
            post(|Json(request): Json<Value>| async move {
                let input: Value =
                    serde_json::from_str(request["input"][0]["content"].as_str().unwrap()).unwrap();
                Json(if input["components"][0]["version"] == "2.14.1" {
                    emergency_reply()
                } else {
                    openai_reply(json!([]))
                })
            }),
        );
    let path = directory.path().join("sbom.json");
    let app = Harness::start_controlled(
        &path,
        Some(ai),
        filtr::ai::AiConfig {
            api_key: Some("test-key".into()),
            ..Default::default()
        },
        Default::default(),
        true,
    )
    .await;
    app.upload(VULNERABLE).await;
    assert_eq!(
        app.status().await["traffic"]["block_reason"],
        "traffic-blocked-critical"
    );
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(app.traffic("filter").await["effective"], "filtering");
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(
        app.client
            .post(&app.public)
            .body("${jndi:test}")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(app.traffic("auto").await["effective"], "blocked");
    app.upload(PATCHED).await;
    assert_eq!(app.status().await["traffic"]["effective"], "filtering");
    app.upload(VULNERABLE).await;
    assert_eq!(app.status().await["traffic"]["effective"], "blocked");
    let mut offline = app.ai_config.clone();
    offline.api_key = None;
    offline.anthropic_api_key = None;
    drop(app);
    let restarted = Harness::start_controlled(&path, None, offline, Default::default(), true).await;
    assert_eq!(
        restarted.status().await["policy"]["ai"]["status"],
        "not_configured"
    );
    assert_eq!(
        restarted
            .client
            .get(&restarted.public)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(restarted.traffic("filter").await["effective"], "filtering");
    drop(restarted);
    let ai = Router::new().fallback(|| async { Json(emergency_reply()) });
    let default_app =
        Harness::start_with_services(&directory.path().join("default.json"), Some(ai)).await;
    default_app.upload(PREVIEW_OLD).await;
    assert_eq!(
        default_app.status().await["traffic"]["auto_block_critical"],
        false
    );
    assert_eq!(
        default_app
            .client
            .get(&default_app.public)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn kill_switch_remains_available_while_ai_preview_runs() {
    let directory = tempfile::tempdir().unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let started = entered.clone();
    let release = Arc::new(tokio::sync::Notify::new());
    let resume = release.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let ai = Router::new().fallback(move || {
        let entered = started.clone();
        let release = resume.clone();
        let call = count.fetch_add(1, Ordering::SeqCst);
        async move {
            if call > 0 {
                entered.notify_one();
                release.notified().await;
            }
            Json(openai_reply(json!([])))
        }
    });
    let app = Harness::start_configured(
        &directory.path().join("sbom.json"),
        Some(ai),
        filtr::ai::AiConfig {
            api_key: Some("test-key".into()),
            model: Some("openai/test-model".into()),
            ..Default::default()
        },
    )
    .await;
    app.upload(PREVIEW_OLD).await;
    let preview = app.preview(PREVIEW_NEW, false);
    let control = async {
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        assert_eq!(app.traffic("block_all").await["effective"], "blocked");
        assert_eq!(
            app.client.get(&app.public).send().await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        release.notify_one();
    };
    let (result, ()) = tokio::join!(preview, control);
    assert_eq!(result["candidate"]["remediation"]["quarantined"], true);
    assert_eq!(app.traffic("filter").await["effective"], "filtering");
}

#[tokio::test]
async fn preview_validates_requests_and_never_installs_an_initial_policy() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sbom.json");
    let app = Harness::start(&path).await;
    assert_eq!(
        app.client
            .post(format!("{}/v1/preview?cache_only=true", app.admin))
            .body(PATCHED)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for (query, body, status) in [
        ("cache_only=invalid", PATCHED, StatusCode::BAD_REQUEST),
        ("cache_onyl=true", PATCHED, StatusCode::BAD_REQUEST),
        (
            "cache_only=true",
            "invalid-json",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        assert_eq!(
            app.client
                .post(format!("{}/v1/preview?{query}", app.admin))
                .bearer_auth(TOKEN)
                .body(body)
                .send()
                .await
                .unwrap()
                .status(),
            status
        );
    }
    assert_eq!(
        app.client
            .post(format!("{}/v1/preview?cache_only=true", app.admin))
            .bearer_auth(TOKEN)
            .header("content-encoding", "gzip")
            .body(PATCHED)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let result = app.preview(PATCHED, true).await;
    assert_eq!(result["installed"], false);
    assert!(result["baseline"].is_null());
    assert_eq!(result["analysis_complete"], false);
    assert_eq!(
        result["candidate"]["policy"]["ai"]["unreviewed_components"],
        json!([0])
    );
    assert_eq!(result["candidate"]["policy"]["ai"]["attempts"], json!([]));
    assert_eq!(app.status().await["ready"], false);
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(!path.exists());
    assert!(!directory.path().join("sbom.json.ai-cache.json").exists());
    assert!(!directory.path().join("sbom.json.leaderboard.json").exists());
}

#[tokio::test]
async fn preview_reuses_cache_and_paid_reviews_without_policy_or_webhook_changes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sbom.json");
    let cache = directory.path().join("sbom.json.ai-cache.json");
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let ai = Router::new().route(
        "/v1/responses",
        post(move || {
            let call = count.fetch_add(1, Ordering::SeqCst);
            async move {
                Json(match call {
                    0 => discovery_reply(),
                    1 => openai_reply(json!([])),
                    _ => panic!("unexpected AI call"),
                })
            }
        }),
    );
    let (url, mut events, task) = recording_webhook(StatusCode::NO_CONTENT).await;
    let app = Harness::start_configured_with_webhook(
        &path,
        Some(ai),
        filtr::ai::AiConfig {
            api_key: Some("test-key".into()),
            model: Some("openai/preview-test-model".into()),
            ..Default::default()
        },
        filtr::webhook::Config {
            webhook_url: Some(url),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(app.upload(PREVIEW_OLD).await.status(), StatusCode::OK);
    tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap();
    let live = app.status().await["policy"].clone();
    let saved = std::fs::read(&path).unwrap();
    let original_cache = std::fs::read(&cache).unwrap();
    let unavailable = app.preview(PREVIEW_NEW, true).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(unavailable["analysis_complete"], false);
    assert_eq!(unavailable["diff"]["resolved_cves"], json!([]));
    assert_eq!(
        unavailable["diff"]["unverified_absent_cves"],
        json!(["CVE-2026-12345"])
    );
    assert_eq!(std::fs::read(&cache).unwrap(), original_cache);
    let partial = app.preview(r#"{"format":"filtr-1","packages":[{"purl":"pkg:maven/example/component@1.0.0.RELEASE"},{"purl":"pkg:npm/new-helper@1.0.0"},{"purl":"pkg:npm/new-helper@1.0.0"}]}"#, true).await;
    assert_eq!(partial["candidate"]["policy"]["ai"]["cache"]["hits"], 1);
    assert_eq!(
        partial["candidate"]["policy"]["ai"]["unreviewed_components"],
        json!([1, 2])
    );
    assert_eq!(partial["candidate"]["remediation"]["quarantined"], false);
    let reviewed = app.preview(PREVIEW_NEW, false).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(reviewed["analysis_complete"], true);
    assert_eq!(reviewed["diff"]["resolved_cves"], json!(["CVE-2026-12345"]));
    assert_eq!(
        reviewed["diff"]["components_added"][0]["installed_version"],
        "1.0.1.RELEASE"
    );
    let warmed_cache = std::fs::read(&cache).unwrap();
    let cached = app.preview(PREVIEW_NEW, true).await;
    assert_eq!(cached["analysis_complete"], true);
    assert_eq!(cached["candidate"]["policy"]["ai"]["cache"]["hits"], 1);
    assert_eq!(cached["candidate"]["policy"]["ai"]["attempts"], json!([]));
    assert_eq!(
        cached["candidate"]["policy"]["ai"]["usage"]["web_search_requests"],
        0
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(std::fs::read(&cache).unwrap(), warmed_cache);
    assert_eq!(std::fs::read(&path).unwrap(), saved);
    assert_eq!(app.status().await["policy"], live);
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    assert!(!directory.path().join("sbom.json.leaderboard.json").exists());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), events.recv())
            .await
            .is_err()
    );
    task.abort();
}

#[tokio::test]
async fn preview_reads_saved_rankings_and_keeps_live_policy_during_review() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sbom.json");
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let ranks = Arc::new(AtomicUsize::new(0));
    let rank_count = ranks.clone();
    let entered = Arc::new(tokio::sync::Notify::new());
    let started = entered.clone();
    let release = Arc::new(tokio::sync::Notify::new());
    let resume = release.clone();
    let ai = Router::new()
        .route(
            "/leaderboard",
            get(move || {
                rank_count.fetch_add(1, Ordering::SeqCst);
                async { Json(test_leaderboard()) }
            }),
        )
        .route(
            "/v1/responses",
            post(move || {
                let call = count.fetch_add(1, Ordering::SeqCst);
                let entered = started.clone();
                let release = resume.clone();
                async move {
                    if call == 1 {
                        entered.notify_one();
                        release.notified().await;
                    }
                    Json(openai_reply(json!([])))
                }
            }),
        );
    let app = Harness::start_configured(
        &path,
        Some(ai),
        filtr::ai::AiConfig {
            api_key: Some("test-key".into()),
            ..Default::default()
        },
    )
    .await;
    app.upload(PREVIEW_OLD).await;
    let live = app.status().await["policy"].clone();
    let snapshot_path = directory.path().join("sbom.json.leaderboard.json");
    let snapshot = std::fs::read(&snapshot_path).unwrap();
    let pending = app.preview(PREVIEW_NEW, false);
    let verify = async {
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        assert_eq!(app.status().await["policy"], live);
        assert_eq!(
            app.client.get(&app.public).send().await.unwrap().status(),
            StatusCode::CREATED
        );
        assert_eq!(app.upload(PATCHED).await.status(), StatusCode::CONFLICT);
        release.notify_one();
    };
    let (result, ()) = tokio::join!(pending, verify);
    assert_eq!(result["analysis_complete"], true);
    assert_eq!(ranks.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(std::fs::read(&snapshot_path).unwrap(), snapshot);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), PREVIEW_OLD);
    assert_eq!(app.status().await["policy"], live);
    let mut offline_config = app.ai_config.clone();
    offline_config.api_key = None;
    offline_config.anthropic_api_key = None;
    drop(app);
    let offline = Harness::start_configured(&path, None, offline_config).await;
    let cached = offline.preview(PREVIEW_NEW, true).await;
    assert_eq!(cached["analysis_complete"], true);
    assert_eq!(cached["candidate"]["policy"]["ai"]["cache"]["hits"], 1);
    assert_eq!(cached["candidate"]["policy"]["ai"]["attempts"], json!([]));
}

#[tokio::test]
async fn preview_reports_timeouts_and_expired_cache_without_policy_changes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sbom.json");
    let cache = directory.path().join("sbom.json.ai-cache.json");
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let ai = Router::new().route(
        "/v1/responses",
        post(move || {
            let call = count.fetch_add(1, Ordering::SeqCst);
            async move {
                if call > 0 {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                }
                Json(discovery_reply())
            }
        }),
    );
    let app = Harness::start_configured(
        &path,
        Some(ai),
        filtr::ai::AiConfig {
            api_key: Some("test-key".into()),
            model: Some("openai/preview-test-model".into()),
            ai_review_timeout_secs: 1,
            ..Default::default()
        },
    )
    .await;
    app.upload(PREVIEW_OLD).await;
    let live = app.status().await["policy"].clone();
    let original_cache = std::fs::read(&cache).unwrap();
    let failed = app.preview(PREVIEW_NEW, false).await;
    assert_eq!(failed["analysis_complete"], false);
    assert_eq!(failed["candidate"]["policy"]["ai"]["status"], "failed");
    assert_eq!(
        failed["candidate"]["policy"]["ai"]["unreviewed_components"],
        json!([0])
    );
    assert_eq!(failed["diff"]["resolved_cves"], json!([]));
    assert_eq!(std::fs::read(&cache).unwrap(), original_cache);
    let mut expired: Value = serde_json::from_slice(&original_cache).unwrap();
    for entry in expired["entries"].as_object_mut().unwrap().values_mut() {
        entry["checked_at"] = json!(0);
    }
    std::fs::write(&cache, serde_json::to_vec(&expired).unwrap()).unwrap();
    let expired_bytes = std::fs::read(&cache).unwrap();
    let cached = app.preview(PREVIEW_OLD, true).await;
    assert_eq!(cached["analysis_complete"], false);
    assert_eq!(cached["candidate"]["policy"]["ai"]["cache"]["hits"], 0);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(std::fs::read(&cache).unwrap(), expired_bytes);
    std::fs::write(&cache, "invalid-cache").unwrap();
    let corrupt = app.preview(PREVIEW_OLD, true).await;
    assert_eq!(corrupt["analysis_complete"], false);
    assert_eq!(corrupt["candidate"]["policy"]["ai"]["status"], "failed");
    assert_eq!(corrupt["candidate"]["policy"]["ai"]["attempts"], json!([]));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(std::fs::read_to_string(&cache).unwrap(), "invalid-cache");
    assert_eq!(app.status().await["policy"], live);
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
}

fn large_inventory() -> String {
    let mut packages: Vec<_> = (0..3000)
        .map(|i| json!({"purl":format!("pkg:npm/package-{i}@1.0.0")}))
        .collect();
    packages[0] = json!({"purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"});
    json!({"format":"filtr-1","packages":packages}).to_string()
}

#[tokio::test]
async fn large_ai_reviews_send_every_component_in_bounded_batches() {
    let directory = tempfile::tempdir().unwrap();
    let requests = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
    let captured = requests.clone();
    let ai = Router::new().route(
        "/v1/responses",
        post(move |Json(request): Json<Value>| {
            let captured = captured.clone();
            async move {
                let text = request["input"][0]["content"].as_str().unwrap();
                assert!(text.len() <= 128 * 1024);
                captured
                    .lock()
                    .unwrap()
                    .push(serde_json::from_str(text).unwrap());
                Json(openai_reply(json!([])))
            }
        }),
    );
    let app = Harness::start_with_services(&directory.path().join("sbom.json"), Some(ai)).await;
    assert_eq!(
        app.upload(&large_inventory()).await.status(),
        StatusCode::OK
    );
    let status = app.status().await;
    assert_eq!(status["policy"]["ai"]["status"], "complete");
    assert_eq!(status["policy"]["ai"]["components_reviewed"], 3000);
    assert!(status["policy"]["ai"]["batches_total"].as_u64().unwrap() > 1);
    assert_eq!(
        status["policy"]["ai"]["batches_completed"],
        status["policy"]["ai"]["batches_total"]
    );
    assert!(status["policy"]["ai"]["input_bytes"].as_u64().unwrap() > 256 * 1024);
    let sent = requests.lock().unwrap();
    assert_eq!(
        sent.len(),
        status["policy"]["ai"]["batches_total"].as_u64().unwrap() as usize
    );
    let indexes: std::collections::BTreeSet<_> = sent
        .iter()
        .flat_map(|input| input["components"].as_array().unwrap())
        .map(|c| c["component_index"].as_u64().unwrap())
        .collect();
    assert_eq!(indexes, (0..3000).collect());
}

#[tokio::test]
async fn a_failed_batch_discards_successful_batch_enhancements() {
    let directory = tempfile::tempdir().unwrap();
    let ai = Router::new().route("/v1/responses", post(|Json(request): Json<Value>| async move {
        let input: Value = serde_json::from_str(request["input"][0]["content"].as_str().unwrap()).unwrap();
        let is_last = input["components"].as_array().unwrap().iter().any(|c| c["component_index"] == 2999);
        if is_last {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            return StatusCode::BAD_REQUEST.into_response();
        }
        Json(openai_reply(json!([{"component_index":0,"basis":"log4shell-lookups","action":"tokens","patterns":["batch-marker"],"reason":"Test enhancement that must not activate after another batch fails."}]))).into_response()
    }));
    let app = Harness::start_with_services(&directory.path().join("sbom.json"), Some(ai)).await;
    assert_eq!(
        app.upload(&large_inventory()).await.status(),
        StatusCode::OK
    );
    let status = app.status().await;
    assert_eq!(status["policy"]["ai"]["status"], "failed");
    assert!(
        status["policy"]["ai"]["batches_completed"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(status["policy"]["generated_rules"], json!([]));
    assert_eq!(
        app.client
            .post(&app.public)
            .body("batch-marker")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        app.client
            .post(&app.public)
            .body("${jndi:test}")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn generated_rules_activate_only_after_ai_review_succeeds() {
    let directory = tempfile::tempdir().unwrap();
    let finish_review = Arc::new(tokio::sync::Notify::new());
    let completion = finish_review.clone();
    let ai = Router::new().fallback(move || {
        let completion = completion.clone();
        async move {
            completion.notified().await;
            Json(targeted_reply())
        }
    });
    let app = Harness::start_with_services(&directory.path().join("sbom.json"), Some(ai)).await;
    let request = app
        .client
        .post(format!("{}/v1/sbom", app.admin))
        .bearer_auth(TOKEN)
        .body(VULNERABLE);
    let upload = tokio::spawn(async move { request.send().await.unwrap() });
    let pending = app.wait_for("/policy/ai/status", json!("pending")).await;
    assert_eq!(
        app.client
            .post(format!("{}/v1/refresh", app.admin))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(pending["policy"]["generated_rules"], json!([]));
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    finish_review.notify_one();
    assert_eq!(upload.await.unwrap().status(), StatusCode::OK);
    let complete = app.status().await;
    assert_eq!(complete["policy"]["ai"]["status"], "complete");
    assert_eq!(
        app.client
            .get(&app.public)
            .header("x-test-exploit", "yes")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(app.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn static_rules_remain_active_while_ai_is_pending_and_after_timeout() {
    let directory = tempfile::tempdir().unwrap();
    let ai = Router::new().fallback(|| async {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        Json(openai_reply(json!([])))
    });
    let path = directory.path().join("sbom.json");
    let app = Harness::start_with_services(&path, Some(ai.clone())).await;
    let request = app
        .client
        .post(format!("{}/v1/sbom", app.admin))
        .bearer_auth(TOKEN)
        .body(VULNERABLE);
    let upload = tokio::spawn(async move { request.send().await.unwrap() });
    let status = app.wait_for("/policy/ai/status", json!("pending")).await;
    assert_eq!(status["policy"]["generated_rules"], json!([]));
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(
        app.client
            .post(&app.public)
            .body("${jndi:test}")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(upload.await.unwrap().status(), StatusCode::OK);
    let status = app.status().await;
    assert_eq!(status["policy"]["ai"]["status"], "failed");
    assert_eq!(status["policy"]["generated_rules"], json!([]));
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(app.hits.load(Ordering::SeqCst), 2);
    drop(app);
    let restarted = Harness::start_with_services(&path, Some(ai)).await;
    let status = restarted.status().await;
    assert_eq!(status["policy"]["ai"]["status"], "failed");
    assert_eq!(status["policy"]["generated_rules"], json!([]));
    assert_eq!(
        restarted
            .client
            .get(&restarted.public)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        restarted
            .client
            .post(&restarted.public)
            .body("${jndi:test}")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn incomplete_inventory_is_reported_without_database_guards() {
    let directory = tempfile::tempdir().unwrap();
    let ai = Router::new().fallback(|| async { Json(openai_reply(json!([]))) });
    let app = Harness::start_with_services(&directory.path().join("sbom.json"), Some(ai)).await;
    let sbom = r#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
        {"type":"application","name":"unknown-application"},
        {"type":"library","name":"module","purl":"pkg:golang/example/module@UNKNOWN"},
        {"type":"application","name":"runtime","purl":"pkg:generic/runtime@1.2.3"}
    ]}"#;
    assert_eq!(app.upload(sbom).await.status(), StatusCode::OK);
    let status = app.status().await;
    assert!(status["policy"].get("osv").is_none());
    assert_eq!(
        status["policy"]["inventory_gaps"],
        json!([
            {"component_index":0,"reason":"missing_purl"},
            {"component_index":0,"reason":"missing_or_unknown_version"},
            {"component_index":1,"reason":"missing_or_unknown_version"}
        ])
    );
    assert_eq!(status["policy"]["ai"]["components_reviewed"], 3);
    assert_eq!(status["policy"]["generated_rules"], json!([]));
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn upload_returns_readable_gaps_with_types_images_and_distinct_counts() {
    let directory = tempfile::tempdir().unwrap();
    let app = Harness::start(&directory.path().join("sbom.json")).await;
    assert!(app.status().await["inventory"].is_null());
    let provenance =
        json!([{"name":"api","image":"example/api:release","image_id":"sha256:example"}])
            .to_string();
    let source = json!([{"name":"filtr:inventory:source","value":"api"}]);
    let sbom = json!({
        "bomFormat":"CycloneDX", "specVersion":"1.6",
        "metadata":{"properties":[{"name":"filtr:inventory:provenance","value":provenance}]},
        "components":[
            {"type":"operating-system","name":"alpine","version":"3.23.3","properties":source},
            {"type":"library","name":"helper","purl":"pkg:golang/example/helper@UNKNOWN","properties":source},
            {"type":"application","name":"unknown-app","properties":source}
        ]
    });
    let response = app.upload(&sbom.to_string()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let report: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    let inventory = &report["inventory"];
    assert_eq!(inventory["identity_complete"], false);
    assert_eq!(inventory["components"], 3);
    assert_eq!(inventory["gap_count"], 4);
    assert_eq!(inventory["components_with_gaps"], 3);
    let gaps = inventory["gaps"].as_array().unwrap();
    assert_eq!(gaps[0]["name"], "alpine");
    assert_eq!(gaps[0]["component_type"], "operating-system");
    assert_eq!(gaps[0]["reason"], "missing_purl");
    assert_eq!(gaps[0]["installed_version"], "3.23.3");
    assert!(
        gaps[0]["suggested_action"]
            .as_str()
            .unwrap()
            .contains("/etc/os-release")
    );
    assert_eq!(gaps[1]["package"], "pkg:golang/example/helper");
    assert_eq!(gaps[1]["reason"], "missing_or_unknown_version");
    assert_eq!(gaps[1]["installed_version"], "UNKNOWN");
    assert_eq!(gaps[2]["component_index"], gaps[3]["component_index"]);
    for gap in gaps {
        assert_eq!(gap["sources"][0]["image"], "example/api:release");
        assert_eq!(gap["sources"][0]["image_id"], "sha256:example");
    }
    assert_eq!(app.status().await["inventory"], *inventory);
    let remediation: Value = serde_json::from_slice(
        &app.client
            .get(format!("{}/v1/remediation", app.admin))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(remediation["inventory_gaps"], inventory["gaps"]);
    let refreshed: Value = serde_json::from_slice(
        &app.client
            .post(format!("{}/v1/refresh", app.admin))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(refreshed["inventory"], *inventory);
    assert_eq!(refreshed["policy"]["ai"]["attempts"], json!([]));
    assert_eq!(report["policy"]["ai"]["attempts"], json!([]));
    assert_eq!(
        report["policy"]["inventory_gaps"][0],
        json!({"component_index":0,"reason":"missing_purl"})
    );
    let patched: Value =
        serde_json::from_slice(&app.upload(PATCHED).await.bytes().await.unwrap()).unwrap();
    assert_eq!(patched["inventory"]["identity_complete"], true);
    assert_eq!(patched["inventory"]["gap_count"], 0);
    assert_eq!(patched["inventory"]["components_with_gaps"], 0);
    assert_eq!(patched["inventory"]["gaps"], json!([]));
}

#[tokio::test]
async fn pinned_models_reuse_component_reviews_across_uploads_and_offline_restarts() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sbom.json");
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let ai = Router::new()
        .route(
            "/leaderboard",
            get(|| async {
                panic!("pinned models must not fetch rankings");
                #[allow(unreachable_code)]
                StatusCode::BAD_REQUEST
            }),
        )
        .route(
            "/v1/responses",
            post(move |Json(request): Json<Value>| {
                let count = count.clone();
                async move {
                    assert_eq!(request["model"], "budget-test-model");
                    assert!(request.get("reasoning").is_none());
                    let input: Value =
                        serde_json::from_str(request["input"][0]["content"].as_str().unwrap())
                            .unwrap();
                    let call = count.fetch_add(1, Ordering::SeqCst);
                    let components = input["components"].as_array().unwrap();
                    match call {
                        0 => {
                            assert_eq!(components.len(), 2);
                            Json(discovery_reply())
                        }
                        1 => {
                            assert_eq!(components.len(), 1);
                            assert_eq!(components[0]["component_index"], 2);
                            Json(openai_reply(json!([])))
                        }
                        2 => {
                            assert_eq!(components.len(), 3);
                            Json(openai_reply(json!([])))
                        }
                        _ => panic!("unexpected paid review"),
                    }
                }
            }),
        );
    let config = filtr::ai::AiConfig {
        api_key: Some("test-key".into()),
        model: Some("openai/budget-test-model".into()),
        ..Default::default()
    };
    let app = Harness::start_configured(&path, Some(ai), config).await;
    assert_eq!(
        app.client
            .post(format!("{}/v1/refresh", app.admin))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.client
            .post(format!("{}/v1/refresh", app.admin))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let first = r#"{"format":"filtr-1","packages":[{"purl":"pkg:npm/a@1.0.0"},{"purl":"pkg:npm/b@1.0.0"}]}"#;
    app.upload(first).await;
    assert_eq!(app.status().await["policy"]["ai"]["cache"]["misses"], 2);
    assert!(directory.path().join("sbom.json.ai-cache.json").exists());
    let reordered = r#"{"format":"filtr-1","packages":[{"purl":"pkg:npm/b@1.0.0"},{"purl":"pkg:npm/a@1.0.0"}]}"#;
    app.upload(reordered).await;
    let status = app.status().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(status["policy"]["ai"]["cache"]["hits"], 2);
    assert_eq!(
        status["policy"]["ai"]["discoveries"][0]["component_index"],
        1
    );
    assert_eq!(status["policy"]["components"][1]["package"], "pkg:npm/a");
    let added = r#"{"format":"filtr-1","packages":[{"purl":"pkg:npm/b@1.0.0"},{"purl":"pkg:npm/a@1.0.0"},{"purl":"pkg:npm/c@2.0.0"}]}"#;
    app.upload(added).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(app.status().await["policy"]["ai"]["cache"]["hits"], 2);
    let response = app
        .client
        .post(format!("{}/v1/refresh", app.admin))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(app.status().await["policy"]["ai"]["cache"]["hits"], 0);
    assert_eq!(app.status().await["policy"]["generated_rules"], json!([]));
    let config = app.ai_config.clone();
    drop(app);
    // The mock provider is now offline. A restart must restore cached negative reviews without calling it.
    let restarted = Harness::start_configured(&path, None, config).await;
    let status = restarted.status().await;
    assert_eq!(status["policy"]["ai"]["status"], "complete");
    assert_eq!(status["policy"]["ai"]["cache"]["hits"], 3);
    assert_eq!(status["policy"]["ai"]["attempts"], json!([]));
    assert_eq!(
        restarted
            .client
            .get(&restarted.public)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
}

async fn cached_review_fixture() -> (
    tempfile::TempDir,
    Harness,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let directory = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let ranks = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let rankings = ranks.clone();
    let ai = Router::new()
        .route(
            "/leaderboard",
            get(move || {
                rankings.fetch_add(1, Ordering::SeqCst);
                async { Json(test_leaderboard()) }
            }),
        )
        .route(
            "/v1/responses",
            post(move || {
                let call = count.fetch_add(1, Ordering::SeqCst);
                async move {
                    Json(if call == 0 {
                        targeted_reply()
                    } else {
                        openai_reply(json!([]))
                    })
                }
            }),
        );
    let app = Harness::start_configured(
        &directory.path().join("sbom.json"),
        Some(ai),
        filtr::ai::AiConfig {
            api_key: Some("test-key".into()),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(app.upload(PREVIEW_OLD).await.status(), StatusCode::OK);
    assert_eq!(
        app.preview(PREVIEW_NEW, false).await["analysis_complete"],
        true
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(ranks.load(Ordering::SeqCst), 1);
    (directory, app, calls, ranks)
}

async fn upload_options(app: &Harness, sbom: &str, options: &str) -> reqwest::Response {
    let url = if options.is_empty() {
        format!("{}/v1/sbom", app.admin)
    } else {
        format!("{}/v1/sbom?{options}", app.admin)
    };
    app.client
        .post(url)
        .bearer_auth(TOKEN)
        .header("content-type", "application/json")
        .body(sbom.to_owned())
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn cache_only_upload_replays_versions_without_external_calls_or_cache_writes() {
    let (directory, app, calls, ranks) = cached_review_fixture().await;
    let path = directory.path().join("sbom.json");
    let cache = directory.path().join("sbom.json.ai-cache.json");
    let rankings = directory.path().join("sbom.json.leaderboard.json");
    let cache_bytes = std::fs::read(&cache).unwrap();
    let cache_modified = std::fs::metadata(&cache).unwrap().modified().unwrap();
    let ranking_bytes = std::fs::read(&rankings).unwrap();
    for (sbom, expected) in [
        (PREVIEW_OLD, StatusCode::FORBIDDEN),
        (PREVIEW_NEW, StatusCode::CREATED),
        (PREVIEW_OLD, StatusCode::FORBIDDEN),
    ] {
        let response = upload_options(&app, sbom, "cache_only=true").await;
        assert_eq!(response.status(), StatusCode::OK);
        let report: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(report["installed"], true);
        assert_eq!(report["cache_only"], true);
        assert_eq!(report["policy"]["ai"]["status"], "complete");
        assert_eq!(report["policy"]["ai"]["cache"]["hits"], 1);
        assert_eq!(report["policy"]["ai"]["attempts"], json!([]));
        assert_eq!(report["policy"]["ai"]["usage"]["web_search_requests"], 0);
        assert_eq!(
            app.client
                .get(&app.public)
                .header("x-test-exploit", "yes")
                .send()
                .await
                .unwrap()
                .status(),
            expected
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), sbom);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(ranks.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read(&cache).unwrap(), cache_bytes);
    assert_eq!(
        std::fs::metadata(&cache).unwrap().modified().unwrap(),
        cache_modified
    );
    assert_eq!(std::fs::read(&rankings).unwrap(), ranking_bytes);
}

#[tokio::test]
async fn previous_v2_cache_only_upload_replays_rules_without_external_calls() {
    let (directory, app, calls, ranks) = cached_review_fixture().await;
    let cache_path = directory.path().join("sbom.json.ai-cache.json");
    let rankings_path = directory.path().join("sbom.json.leaderboard.json");
    let original_rules = app.status().await["policy"]["generated_rules"].clone();
    assert_eq!(original_rules.as_array().unwrap().len(), 1);

    let mut previous: Value = serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();
    let scope = previous["scope"].as_object_mut().unwrap();
    assert!(scope.remove("research_guidance").is_some());
    scope.insert("version".into(), json!(2));
    let previous_bytes = serde_json::to_vec(&previous).unwrap();
    std::fs::write(&cache_path, &previous_bytes).unwrap();
    let modified = std::fs::metadata(&cache_path).unwrap().modified().unwrap();
    let rankings_bytes = std::fs::read(&rankings_path).unwrap();

    for (sbom, expected, rules) in [
        (PREVIEW_OLD, StatusCode::FORBIDDEN, original_rules.clone()),
        (PREVIEW_NEW, StatusCode::CREATED, json!([])),
        (PREVIEW_OLD, StatusCode::FORBIDDEN, original_rules),
    ] {
        let response = upload_options(&app, sbom, "cache_only=true").await;
        assert_eq!(response.status(), StatusCode::OK);
        let report: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(report["installed"], true);
        assert_eq!(report["cache_only"], true);
        assert_eq!(report["policy"]["generated_rules"], rules);
        assert_eq!(report["policy"]["ai"]["status"], "complete");
        assert_eq!(report["policy"]["ai"]["cache"]["hits"], 1);
        assert_eq!(report["policy"]["ai"]["cache"]["misses"], 0);
        assert_eq!(report["policy"]["ai"]["attempts"], json!([]));
        assert_eq!(report["policy"]["ai"]["usage"]["web_search_requests"], 0);
        assert_eq!(
            app.client
                .get(&app.public)
                .header("x-test-exploit", "yes")
                .send()
                .await
                .unwrap()
                .status(),
            expected
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(ranks.load(Ordering::SeqCst), 1);
    }
    assert_eq!(std::fs::read(&cache_path).unwrap(), previous_bytes);
    assert_eq!(
        std::fs::metadata(&cache_path).unwrap().modified().unwrap(),
        modified
    );
    assert_eq!(std::fs::read(&rankings_path).unwrap(), rankings_bytes);
}

#[tokio::test]
async fn cache_only_upload_rejections_preserve_live_policy_files_and_webhooks() {
    let (directory, warm, calls, ranks) = cached_review_fixture().await;
    let path = directory.path().join("sbom.json");
    let cache = directory.path().join("sbom.json.ai-cache.json");
    let rankings = directory.path().join("sbom.json.leaderboard.json");
    let (url, mut events, task) = recording_webhook(StatusCode::NO_CONTENT).await;
    let mut config = warm.ai_config.clone();
    config.cache_only = true;
    let app = Harness::start_configured_with_webhook(
        &path,
        None,
        config,
        filtr::webhook::Config {
            webhook_url: Some(url),
            ..Default::default()
        },
    )
    .await;
    tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap();
    let live = app.status().await["policy"].clone();
    let saved = std::fs::read(&path).unwrap();
    let ranking_bytes = std::fs::read(&rankings).unwrap();
    let saved_modified = std::fs::metadata(&path).unwrap().modified().unwrap();
    let rankings_modified = std::fs::metadata(&rankings).unwrap().modified().unwrap();
    let original_cache: Value = serde_json::from_slice(&std::fs::read(&cache).unwrap()).unwrap();
    for mode in ["missing", "expired", "rejected"] {
        let mut candidate_cache = original_cache.clone();
        let entries = candidate_cache["entries"].as_object_mut().unwrap();
        let key = entries
            .keys()
            .find(|key| key.contains("1.0.1.RELEASE"))
            .unwrap()
            .clone();
        match mode {
            "missing" => {
                entries.remove(&key);
            }
            "expired" => entries[&key]["checked_at"] = json!(0),
            _ => {
                entries[&key]["reply"]["enhancements"] = json!([{
                    "component_index":0,"basis":"not-an-enabled-rule","action":"tokens",
                    "patterns":["untrusted-marker"],"reason":"Invalid cached proposal must fail validation."
                }])
            }
        }
        std::fs::write(&cache, serde_json::to_vec(&candidate_cache).unwrap()).unwrap();
        let cache_bytes = std::fs::read(&cache).unwrap();
        let cache_modified = std::fs::metadata(&cache).unwrap().modified().unwrap();
        let response = upload_options(&app, PREVIEW_NEW, "cache_only=true").await;
        assert_eq!(response.status(), StatusCode::CONFLICT, "{mode}");
        let report: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(report["installed"], false);
        assert_eq!(report["error"], "cached-review-incomplete");
        assert_eq!(report["cache_only"], true);
        assert_eq!(app.status().await["policy"], live);
        assert_eq!(std::fs::read(&path).unwrap(), saved);
        assert_eq!(std::fs::read(&cache).unwrap(), cache_bytes);
        assert_eq!(std::fs::read(&rankings).unwrap(), ranking_bytes);
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            saved_modified
        );
        assert_eq!(
            std::fs::metadata(&cache).unwrap().modified().unwrap(),
            cache_modified
        );
        assert_eq!(
            std::fs::metadata(&rankings).unwrap().modified().unwrap(),
            rankings_modified
        );
        assert_eq!(
            app.client
                .get(&app.public)
                .header("x-test-exploit", "yes")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    for query in [
        "cache_onyl=true",
        "cache_only=invalid",
        "cache_only=true&cache_only=false",
        "other=1",
    ] {
        assert_eq!(
            upload_options(&app, PREVIEW_NEW, query).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(ranks.load(Ordering::SeqCst), 1);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), events.recv())
            .await
            .is_err()
    );
    task.abort();
}

#[tokio::test]
async fn global_cache_only_restores_without_keys_and_cannot_be_bypassed() {
    let (directory, warm, calls, ranks) = cached_review_fixture().await;
    let path = directory.path().join("sbom.json");
    let cache = directory.path().join("sbom.json.ai-cache.json");
    let rankings = directory.path().join("sbom.json.leaderboard.json");
    let cache_bytes = std::fs::read(&cache).unwrap();
    let ranking_bytes = std::fs::read(&rankings).unwrap();
    let mut config = warm.ai_config.clone();
    config.cache_only = true;
    config.api_key = None;
    config.anthropic_api_key = None;
    let app = Harness::start_configured(&path, None, config).await;
    let initial = app.status().await;
    assert_eq!(initial["ai_mode"]["cache_only"], true);
    assert_eq!(initial["policy"]["ai"]["status"], "complete");
    assert_eq!(initial["policy"]["ai"]["cache"]["hits"], 1);
    assert_eq!(initial["policy"]["ai"]["attempts"], json!([]));
    assert_eq!(
        app.client
            .get(&app.public)
            .header("x-test-exploit", "yes")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let preview = app.preview(PREVIEW_NEW, false).await;
    assert_eq!(preview["cache_only"], true);
    assert_eq!(preview["analysis_complete"], true);
    let refreshed = app
        .admin_report(app.client.post(format!("{}/v1/refresh", app.admin)))
        .await;
    assert_eq!(refreshed["policy"]["ai"]["attempts"], json!([]));
    let missing = r#"{"format":"filtr-1","packages":[{"purl":"pkg:npm/uncached@1.0.0"}]}"#;
    for options in ["", "cache_only=false"] {
        let response = upload_options(&app, missing, options).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let result: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(result["installed"], false);
        assert_eq!(result["cache_only"], true);
    }
    let installed: Value =
        serde_json::from_slice(&app.upload(PREVIEW_NEW).await.bytes().await.unwrap()).unwrap();
    assert_eq!(installed["installed"], true);
    assert_eq!(installed["cache_only"], true);
    assert_eq!(
        app.client
            .get(&app.public)
            .header("x-test-exploit", "yes")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), PREVIEW_NEW);
    assert_eq!(std::fs::read(&cache).unwrap(), cache_bytes);
    assert_eq!(std::fs::read(&rankings).unwrap(), ranking_bytes);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(ranks.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn global_cache_only_does_not_refresh_expired_reviews_even_with_credentials() {
    let (directory, warm, calls, ranks) = cached_review_fixture().await;
    let path = directory.path().join("sbom.json");
    let cache = directory.path().join("sbom.json.ai-cache.json");
    let mut config = warm.ai_config.clone();
    config.cache_only = true;
    config.cache_ttl_secs = 2;
    let app = Harness::start_configured(&path, None, config).await;
    assert_eq!(app.status().await["policy"]["ai"]["status"], "complete");
    let cache_bytes = std::fs::read(&cache).unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let preview = app.preview(PREVIEW_OLD, false).await;
    assert_eq!(preview["analysis_complete"], false);
    assert_eq!(preview["candidate"]["policy"]["ai"]["status"], "partial");
    assert_eq!(preview["candidate"]["policy"]["ai"]["cache"]["hits"], 0);
    assert_eq!(app.upload(PREVIEW_OLD).await.status(), StatusCode::CONFLICT);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(ranks.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read(&cache).unwrap(), cache_bytes);
    assert_eq!(
        app.client
            .get(&app.public)
            .header("x-test-exploit", "yes")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn global_cache_only_accepts_pinned_provider_scope_without_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sbom.json");
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let ai = Router::new().route(
        "/v1/responses",
        post(move || {
            count.fetch_add(1, Ordering::SeqCst);
            async { Json(targeted_reply()) }
        }),
    );
    let warm = Harness::start_configured(
        &path,
        Some(ai),
        filtr::ai::AiConfig {
            api_key: Some("test-key".into()),
            model: Some("openai/cached-pinned-model".into()),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(warm.upload(PREVIEW_OLD).await.status(), StatusCode::OK);
    let cache = directory.path().join("sbom.json.ai-cache.json");
    let original = std::fs::read(&cache).unwrap();
    let mut config = warm.ai_config.clone();
    config.api_key = None;
    config.cache_only = true;
    let app = Harness::start_configured(&path, None, config).await;
    assert_eq!(app.status().await["policy"]["ai"]["status"], "complete");
    assert_eq!(app.status().await["policy"]["ai"]["cache"]["hits"], 1);
    assert_eq!(
        app.client
            .get(&app.public)
            .header("x-test-exploit", "yes")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read(&cache).unwrap(), original);
}

#[tokio::test]
async fn global_cache_only_startup_reports_missing_coverage_and_keeps_static_filtering() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sbom.json");
    std::fs::write(&path, VULNERABLE).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let ai = Router::new().fallback(move || {
        count.fetch_add(1, Ordering::SeqCst);
        async { StatusCode::BAD_GATEWAY }
    });
    let app = Harness::start_configured(
        &path,
        Some(ai),
        filtr::ai::AiConfig {
            cache_only: true,
            ..Default::default()
        },
    )
    .await;
    let report = app.status().await;
    assert_eq!(report["ai_mode"]["cache_only"], true);
    assert_eq!(report["policy"]["ai"]["status"], "partial");
    assert_eq!(report["policy"]["ai"]["unreviewed_components"], json!([0]));
    assert_eq!(report["policy"]["ai"]["attempts"], json!([]));
    assert_eq!(
        app.client
            .post(&app.public)
            .body("${jndi:test}")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(app.upload(PATCHED).await.status(), StatusCode::CONFLICT);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), VULNERABLE);
    assert!(!directory.path().join("sbom.json.ai-cache.json").exists());
    assert!(!directory.path().join("sbom.json.leaderboard.json").exists());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn expiration_automatically_refreshes_the_unchanged_running_inventory() {
    let directory = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let ai = Router::new().route(
        "/v1/responses",
        post(move || {
            let count = count.clone();
            async move {
                Json(if count.fetch_add(1, Ordering::SeqCst) == 0 {
                    openai_reply(json!([]))
                } else {
                    targeted_reply()
                })
            }
        }),
    );
    let config = filtr::ai::AiConfig {
        api_key: Some("test-key".into()),
        model: Some("openai/budget-test-model".into()),
        cache_ttl_secs: 1,
        ..Default::default()
    };
    let app =
        Harness::start_configured(&directory.path().join("sbom.json"), Some(ai), config).await;
    app.upload(VULNERABLE).await;
    assert_eq!(app.status().await["policy"]["generated_rules"], json!([]));
    let refreshed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let status = app.status().await;
            if !status["policy"]["generated_rules"]
                .as_array()
                .unwrap()
                .is_empty()
            {
                break status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(refreshed["policy"]["ai"]["status"], "complete");
    assert_eq!(refreshed["policy"]["ai"]["cache"]["hits"], 0);
    assert_eq!(
        app.client
            .get(&app.public)
            .header("x-test-exploit", "yes")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn failed_automatic_refresh_uses_static_rules_without_a_paid_retry_loop() {
    let directory = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let ai = Router::new().route(
        "/v1/messages",
        post(move |Json(request): Json<Value>| {
            let count = count.clone();
            async move {
                assert_eq!(request["model"], "budget-test-model");
                assert!(request.get("thinking").is_none());
                assert!(request.get("output_config").is_none());
                if count.fetch_add(1, Ordering::SeqCst) == 0 {
                    Json(anthropic_reply(json!([]))).into_response()
                } else {
                    StatusCode::BAD_REQUEST.into_response()
                }
            }
        }),
    );
    let config = filtr::ai::AiConfig {
        anthropic_api_key: Some("test-key".into()),
        model: Some("anthropic/budget-test-model".into()),
        cache_ttl_secs: 1,
        ..Default::default()
    };
    let app =
        Harness::start_configured(&directory.path().join("sbom.json"), Some(ai), config).await;
    app.upload(VULNERABLE).await;
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let status = app.status().await;
            if status["policy"]["ai"]["status"] == "failed" {
                break status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert!(status["policy"]["ai"]["cache"]["next_refresh_at"].is_null());
    assert_eq!(status["policy"]["generated_rules"], json!([]));
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(
        app.client
            .post(&app.public)
            .body("${jndi:test}")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn explicit_refresh_clears_cache_without_provider_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sbom.json");
    let app = Harness::start(&path).await;
    app.upload(VULNERABLE).await;
    let cache = directory.path().join("sbom.json.ai-cache.json");
    std::fs::write(&cache, "stale cache").unwrap();
    let response = app
        .client
        .post(format!("{}/v1/refresh", app.admin))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!cache.exists());
    assert_eq!(
        app.status().await["policy"]["ai"]["status"],
        "not_configured"
    );
}

#[tokio::test]
async fn remediation_tracks_static_rules_and_clears_after_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let app = Harness::start(&directory.path().join("sbom.json")).await;
    assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
    let report: Value = serde_json::from_slice(
        &app.client
            .get(format!("{}/v1/remediation", app.admin))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(report["quarantined"], false);
    assert_eq!(report["blockers"][0]["origin"], "static");
    assert_eq!(report["blockers"][0]["cves"][0], "CVE-2021-44228");
    assert_eq!(
        report["blockers"][0]["affected_components"][0]["recommendations"],
        json!([])
    );
    assert_eq!(app.upload(PATCHED).await.status(), StatusCode::OK);
    let report: Value = serde_json::from_slice(
        &app.client
            .get(format!("{}/v1/remediation", app.admin))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(report["blockers"], json!([]));
}

async fn recording_webhook(
    status: StatusCode,
) -> (
    reqwest::Url,
    tokio::sync::mpsc::UnboundedReceiver<(axum::http::HeaderMap, Value, String)>,
    JoinHandle<()>,
) {
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hooks/filtr", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let router = Router::new().fallback(move |request: Request| {
        let sender = sender.clone();
        async move {
            let (parts, body) = request.into_parts();
            let body = to_bytes(body, 1024 * 1024).await.unwrap();
            sender
                .send((
                    parts.headers,
                    serde_json::from_slice(&body).unwrap_or(Value::Null),
                    parts.uri.path().into(),
                ))
                .unwrap();
            (status, [(header::LOCATION, "/must-not-follow")])
        }
    });
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, receiver, task)
}

#[tokio::test]
async fn webhooks_report_real_policy_changes_without_ai_or_duplicate_notifications() {
    let directory = tempfile::tempdir().unwrap();
    let (url, mut events, task) = recording_webhook(StatusCode::NO_CONTENT).await;
    let app = Harness::start_configured_with_webhook(
        &directory.path().join("sbom.json"),
        None,
        Default::default(),
        filtr::webhook::Config {
            webhook_url: Some(url.clone()),
            webhook_token: Some("test-webhook-secret".into()),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
    let (headers, event, path) =
        tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(path, "/hooks/filtr");
    assert_eq!(headers[header::AUTHORIZATION], "Bearer test-webhook-secret");
    assert_eq!(headers["x-filtr-event-id"], event["id"].as_str().unwrap());
    assert_eq!(event["event"], "filtr.remediation_updated");
    assert_eq!(event["trigger"], "sbom_update");
    assert_eq!(
        event["remediation"]["blockers"][0]["cves"][0],
        "CVE-2021-44228"
    );
    assert_eq!(
        event["remediation"]["ai_review"]["status"],
        "not_configured"
    );
    let serialized = event.to_string();
    assert!(!serialized.contains(TOKEN));
    assert!(!serialized.contains("test-webhook-secret"));
    assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
    let _ = app.status().await;
    assert_eq!(app.upload(PATCHED).await.status(), StatusCode::OK);
    let (_, cleared, _) = tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cleared["remediation"]["blockers"], json!([]));
    assert_ne!(event["id"], cleared["id"]);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), events.recv())
            .await
            .is_err()
    );
    drop(app);
    let restarted = Harness::start_configured_with_webhook(
        &directory.path().join("sbom.json"),
        None,
        Default::default(),
        filtr::webhook::Config {
            webhook_url: Some(url),
            ..Default::default()
        },
    )
    .await;
    let (headers, event, _) =
        tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
            .await
            .unwrap()
            .unwrap();
    assert!(!headers.contains_key(header::AUTHORIZATION));
    assert_eq!(event["trigger"], "startup");
    assert_eq!(event["remediation"]["blockers"], json!([]));
    assert_eq!(
        restarted.status().await["policy"]["ai"]["attempts"],
        json!([])
    );
    task.abort();
}

#[tokio::test]
async fn webhook_retries_preserve_id_without_following_redirects_or_delaying_uploads() {
    let directory = tempfile::tempdir().unwrap();
    let (url, mut events, task) = recording_webhook(StatusCode::TEMPORARY_REDIRECT).await;
    let app = Harness::start_configured_with_webhook(
        &directory.path().join("sbom.json"),
        None,
        Default::default(),
        filtr::webhook::Config {
            webhook_url: Some(url),
            webhook_token: Some("private-receiver-token".into()),
            ..Default::default()
        },
    )
    .await;
    let response = tokio::time::timeout(std::time::Duration::from_secs(1), app.upload(VULNERABLE))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut first = None;
    for _ in 0..3 {
        let (headers, event, path) =
            tokio::time::timeout(std::time::Duration::from_secs(4), events.recv())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(path, "/hooks/filtr");
        assert_eq!(headers["x-filtr-event-id"], event["id"].as_str().unwrap());
        if let Some(first) = &first {
            assert_eq!(&event, first);
        } else {
            first = Some(event);
        }
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), events.recv())
            .await
            .is_err()
    );
    assert_eq!(
        app.status().await["policy"]["active_rules"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    task.abort();
}

#[tokio::test]
async fn remediation_reads_cached_findings_without_provider_calls() {
    let directory = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let ai = Router::new().route(
        "/v1/responses",
        post(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            async { Json(discovery_reply()) }
        }),
    );
    let config = filtr::ai::AiConfig {
        api_key: Some("test-key".into()),
        model: Some("openai/test-model".into()),
        ..Default::default()
    };
    let app =
        Harness::start_configured(&directory.path().join("sbom.json"), Some(ai), config).await;
    let inventory = r#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","purl":"pkg:npm/a@1.0.0","properties":[{"name":"filtr:inventory:source","value":"api"}]}]}"#;
    assert_eq!(app.upload(inventory).await.status(), StatusCode::OK);
    assert_eq!(app.upload(inventory).await.status(), StatusCode::OK);
    for _ in 0..2 {
        let response = app
            .client
            .get(format!("{}/v1/remediation", app.admin))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let remediation: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(remediation["quarantined"], false);
        assert_eq!(remediation["summary"]["blocking_rules"], 0);
        assert_eq!(remediation["summary"]["uncovered_findings"], 1);
        let component = &remediation["uncovered_vulnerabilities"][0]["affected_components"][0];
        assert_eq!(component["component_index"], 0);
        assert_eq!(component["package"], "pkg:npm/a");
        assert_eq!(component["sources"][0]["name"], "api");
        assert_eq!(remediation["ai_review"]["cache"]["hits"], 1);
        assert_eq!(
            component["recommendations"][0]["suggested_fixed_version"],
            "1.0.1.RELEASE"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "report reads must not call AI"
        );
    }
}
