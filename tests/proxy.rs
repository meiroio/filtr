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

struct Harness {
    public: String,
    admin: String,
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    client: reqwest::Client,
    tasks: Vec<JoinHandle<()>>,
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
        Self::start_with_osv(sbom, Router::new().fallback(|| async { Json(json!({})) })).await
    }

    async fn start_with_osv(sbom: &Path, osv: Router) -> Self {
        Self::start_with_services(sbom, osv, None).await
    }

    async fn start_with_services(sbom: &Path, osv: Router, ai: Option<Router>) -> Self {
        let config = filtr::ai::AiConfig {
            api_key: ai.as_ref().map(|_| "test-openai-key".into()),
            ai_timeout_secs: 1,
            ..Default::default()
        };
        let ai = ai
            .map(|router| router.route("/leaderboard", get(|| async { Json(test_leaderboard()) })));
        Self::start_configured(sbom, osv, ai, config).await
    }

    async fn start_configured(
        sbom: &Path,
        osv: Router,
        ai: Option<Router>,
        mut ai_config: filtr::ai::AiConfig,
    ) -> Self {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let public_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let osv_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let osv_url = format!("http://{}", osv_listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let osv_task = tokio::spawn(async move {
            axum::serve(osv_listener, osv).await.unwrap();
        });
        let mut service_tasks = vec![osv_task];
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
            osv_url,
            osv_timeout_secs: 1,
            ai: ai_config,
            max_body_bytes: 1024,
            timeout_secs: 1,
            max_in_flight: 4,
        };
        let addr = config.listen;
        let public = format!("http://{}", config.listen);
        let admin = format!("http://{}", config.admin_listen);
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
        }
    }

    async fn upload(&self, sbom: &str) -> reqwest::Response {
        self.client
            .post(format!("{}/v1/sbom", self.admin))
            .bearer_auth(TOKEN)
            .header("content-type", "application/json")
            .body(sbom.to_owned())
            .send()
            .await
            .unwrap()
    }

    async fn status(&self) -> Value {
        let response = self
            .client
            .get(format!("{}/v1/status", self.admin))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        serde_json::from_str(&response.text().await.unwrap()).unwrap()
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
            "forwarded_for": parts.headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
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
    for endpoint in ["/livez", "/healthz", "/v1/status"] {
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
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(app.hits.load(Ordering::SeqCst), 2);
    assert_eq!(app.status().await["counters"]["blocked"], 7);
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
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
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

#[tokio::test]
async fn osv_reports_coverage_per_package_and_version() {
    let directory = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let osv = Router::new().route("/v1/query", post(move |Json(query): Json<Value>| {
        let count = count.clone();
        async move {
            count.fetch_add(1, Ordering::SeqCst);
            let vulns = match query["package"]["purl"].as_str().unwrap() {
                "pkg:maven/org.apache.logging.log4j/log4j-core" if query["version"] == "2.14.1" => json!([
                    {"id":"GHSA-log4shell", "aliases":["CVE-2021-44228"], "summary":"Lookup vulnerability"},
                    {"id":"CVE-2021-45105", "summary":"No local rule"},
                    {"id":"GHSA-withdrawn", "withdrawn":"2026-01-01T00:00:00Z"}
                ]),
                "pkg:npm/react-server-dom-webpack" => json!([{"id":"CVE-2025-55182"}]),
                "pkg:npm/unrelated" => json!([{"id":"GHSA-unrelated", "aliases":["CVE-2021-44228"]}, {"id":"GHSA-no-cve"}]),
                "pkg:maven/org.apache.logging.log4j/log4j-core" => json!([{"id":"CVE-2021-44228"}]),
                other => panic!("unexpected package {other}"),
            };
            Json(json!({"vulns": vulns}))
        }
    }));
    let app = Harness::start_with_osv(&directory.path().join("sbom.json"), osv).await;
    let inventory = json!({"bomFormat":"CycloneDX", "specVersion":"1.6", "components":[
        {"name":"application"},
        {"name":"log4j", "purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
        {"name":"duplicate log4j", "purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
        {"name":"patched log4j", "purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0"},
        {"name":"RSC", "purl":"pkg:npm/react-server-dom-webpack@19.1.0"},
        {"name":"other", "purl":"pkg:npm/unrelated@1.0.0"},
        {"name":"unknown version", "purl":"pkg:npm/react-server-dom-parcel"},
        {"name":"placeholder version", "purl":"pkg:npm/react-server-dom-parcel", "version":" UNKNOWN "},
        {"name":"invalid version", "purl":"pkg:npm/react-server-dom-parcel", "version":"19.1 0"},
        {"name":"unsupported", "purl":"pkg:generic/example@1.0.0"}
    ]});
    let response = app.upload(&inventory.to_string()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    let report = &response["policy"]["osv"];
    assert_eq!(report["status"], "partial");
    assert_eq!(report["summary"]["queried_packages"], 4);
    assert_eq!(report["summary"]["skipped_components"], 5);
    assert_eq!(report["summary"]["advisories"], 6);
    assert_eq!(report["summary"]["with_blocking_rules"], 2);
    assert_eq!(report["summary"]["uncovered"], 4);
    assert_eq!(report["summary"]["uncovered_before_generation"], 4);
    assert_eq!(report["summary"]["quarantined"], 0);
    assert_eq!(response["policy"]["ai"]["status"], "not_configured");
    assert_eq!(response["policy"]["generated_rules"], json!([]));
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    let packages = report["packages"].as_array().unwrap();
    let log4j = packages.iter().find(|p| p["version"] == "2.14.1").unwrap();
    assert_eq!(log4j["components"].as_array().unwrap().len(), 2);
    let lookup = log4j["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "GHSA-log4shell")
        .unwrap();
    assert_eq!(lookup["coverage"], "blocking_rule_available");
    assert_eq!(lookup["blocking_rules"], json!(["log4shell-lookups"]));
    assert_eq!(lookup["cves"], json!(["CVE-2021-44228"]));
    let patched = packages.iter().find(|p| p["version"] == "2.15.0").unwrap();
    assert_eq!(patched["vulnerabilities"][0]["coverage"], "uncovered");
    assert_eq!(patched["vulnerabilities"][0]["static_rules"], json!([]));
    let unrelated = packages
        .iter()
        .find(|p| p["package"] == "pkg:npm/unrelated")
        .unwrap();
    assert!(
        unrelated["vulnerabilities"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["coverage"] == "uncovered" && v["blocking_rules"] == json!([]))
    );
    assert_eq!(app.status().await["policy"]["osv"], *report);
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn osv_follows_pages_without_duplicate_advisories() {
    let directory = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let osv = Router::new().route(
        "/v1/query",
        post(move |Json(query): Json<Value>| {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                let record = json!({"id":"GHSA-log4shell", "aliases":["CVE-2021-44228"]});
                if query.get("page_token").is_none() {
                    Json(json!({"vulns":[record], "next_page_token":"second"}))
                } else {
                    assert_eq!(query["page_token"], "second");
                    Json(json!({"vulns":[record, {"id":"CVE-2021-45105"}]}))
                }
            }
        }),
    );
    let app = Harness::start_with_osv(&directory.path().join("sbom.json"), osv).await;
    assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
    let report = app.status().await;
    assert_eq!(report["policy"]["osv"]["status"], "complete");
    assert_eq!(report["policy"]["osv"]["summary"]["advisories"], 2);
    assert_eq!(report["policy"]["osv"]["summary"]["uncovered"], 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn osv_failures_never_report_a_clean_scan() {
    for response in [
        (StatusCode::TOO_MANY_REQUESTS, "rate limited"),
        (StatusCode::OK, "not json"),
        (StatusCode::OK, r#"{"unexpected":"response"}"#),
        (StatusCode::OK, r#"{"error":{"code":500}}"#),
        (StatusCode::OK, r#"{"vulns":[{"id":"../../unsafe"}]}"#),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let osv = Router::new().fallback(move || async move { response });
        let app = Harness::start_with_osv(&directory.path().join("sbom.json"), osv).await;
        assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
        let report = app.status().await;
        assert_eq!(report["policy"]["osv"]["status"], "failed");
        assert_eq!(report["policy"]["osv"]["summary"]["failed_packages"], 1);
        assert!(report["policy"]["osv"]["packages"][0]["error"].is_string());
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
async fn local_rules_activate_before_osv_finishes() {
    let directory = tempfile::tempdir().unwrap();
    let osv = Router::new().fallback(|| async {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        Json(json!({}))
    });
    let app = Harness::start_with_osv(&directory.path().join("sbom.json"), osv).await;
    let request = app
        .client
        .post(format!("{}/v1/sbom", app.admin))
        .bearer_auth(TOKEN)
        .body(VULNERABLE);
    let upload = tokio::spawn(async move { request.send().await.unwrap() });
    let report = app.wait_for("/policy/osv/status", json!("pending")).await;
    assert_eq!(report["ready"], true);
    assert!(report["policy"]["osv"]["summary"].is_null());
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
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(upload.await.unwrap().status(), StatusCode::OK);
    let report = app.status().await;
    assert_eq!(report["policy"]["osv"]["status"], "failed");
    assert!(
        report["policy"]["osv"]["error"]
            .as_str()
            .unwrap()
            .contains("deadline")
    );
    assert_eq!(report["policy"]["generated_rules"], json!([]));
    assert_eq!(app.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn restart_refreshes_osv_from_saved_sbom() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sbom.json");
    let app = Harness::start(&path).await;
    app.upload(VULNERABLE).await;
    assert_eq!(
        app.status().await["policy"]["osv"]["summary"]["advisories"],
        0
    );
    drop(app);
    let osv = Router::new().fallback(|| async { Json(json!({"vulns":[{"id":"CVE-2021-45105"}]})) });
    let restarted = Harness::start_with_osv(&path, osv).await;
    assert_eq!(
        restarted.status().await["policy"]["osv"]["summary"]["uncovered"],
        1
    );
}

#[tokio::test]
async fn repeated_osv_pages_preserve_partial_findings() {
    let directory = tempfile::tempdir().unwrap();
    let osv = Router::new().fallback(|| async {
        Json(json!({"vulns":[{"id":"CVE-2021-44228"}], "next_page_token":"repeated"}))
    });
    let app = Harness::start_with_osv(&directory.path().join("sbom.json"), osv).await;
    app.upload(VULNERABLE).await;
    let report = app.status().await;
    let osv = &report["policy"]["osv"];
    assert_eq!(osv["status"], "partial");
    assert_eq!(osv["summary"]["with_blocking_rules"], 1);
    assert_eq!(osv["summary"]["failed_packages"], 1);
    assert!(
        osv["packages"][0]["error"]
            .as_str()
            .unwrap()
            .contains("pagination token")
    );
}

#[tokio::test]
async fn oversized_osv_responses_are_failed_lookups() {
    let directory = tempfile::tempdir().unwrap();
    let osv = Router::new().fallback(|| async { vec![b'x'; 4 * 1024 * 1024 + 1] });
    let app = Harness::start_with_osv(&directory.path().join("sbom.json"), osv).await;
    app.upload(VULNERABLE).await;
    let report = app.status().await;
    assert_eq!(report["policy"]["osv"]["status"], "failed");
    assert!(
        report["policy"]["osv"]["packages"][0]["error"]
            .as_str()
            .unwrap()
            .contains("exceeds 4194304 bytes")
    );
}

fn openai_reply(enhancements: Value) -> Value {
    json!({"id":"resp-test", "status":"completed", "output":[{"type":"message", "content":[{
        "type":"output_text", "text":review_text(enhancements)
    }]}]})
}

fn review_text(enhancements: Value) -> String {
    json!({"summary":"Reviewed the supplied inventory and evidence.", "enhancements":enhancements})
        .to_string()
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
            assert_eq!(request["output_config"]["effort"], "max");
            assert_eq!(request["output_config"]["format"]["type"], "json_schema");
            let input: Value = serde_json::from_str(request["messages"][0]["content"].as_str().unwrap()).unwrap();
            assert_eq!(input["components"].as_array().unwrap().len(), 1);
            assert!(!request.to_string().contains(TOKEN));
            Json(anthropic_reply(json!([{"component_index":0,"basis":"log4shell-lookups","action":"tokens","patterns":["claude-test-marker"],"reason":"Additive test marker."}])))
        }));
    let config = filtr::ai::AiConfig {
        anthropic_api_key: Some("test-anthropic-key".into()),
        ai_timeout_secs: 1,
        ..Default::default()
    };
    let app = Harness::start_configured(
        &directory.path().join("sbom.json"),
        Router::new().fallback(|| async { Json(json!({})) }),
        Some(ai),
        config,
    )
    .await;
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
        provider: Some(filtr::ai::Provider::Anthropic),
        api_key: Some("test-openai-key".into()),
        anthropic_api_key: Some("test-anthropic-key".into()),
        ai_timeout_secs: 1,
        ..Default::default()
    };
    let app = Harness::start_configured(
        &directory.path().join("sbom.json"),
        Router::new().fallback(|| async { Json(json!({"vulns":[{"id":"CVE-2021-45105"}]})) }),
        Some(ai),
        config,
    )
    .await;
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
        app.status().await["policy"]["osv"]["summary"]["quarantined"],
        1
    );
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
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
        api_key: Some("test-openai-key".into()),
        ai_timeout_secs: 1,
        ..Default::default()
    };
    let app = Harness::start_configured(
        &directory.path().join("sbom.json"),
        Router::new().fallback(|| async { Json(json!({})) }),
        Some(ai),
        config,
    )
    .await;
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
        api_key: Some("test-openai-key".into()),
        ai_timeout_secs: 1,
        ..Default::default()
    };
    let osv = Router::new().fallback(|| async { Json(json!({})) });
    let app = Harness::start_configured(&path, osv.clone(), Some(ai.clone()), config.clone()).await;
    app.upload(VULNERABLE).await;
    assert_eq!(app.status().await["policy"]["ai"]["model"], "first-winner");
    assert_eq!(
        app.status().await["policy"]["ai"]["leaderboard_source"],
        "sbom_update"
    );
    assert!(directory.path().join("sbom.json.leaderboard.json").exists());
    drop(app);
    let restarted =
        Harness::start_configured(&path, osv.clone(), Some(ai.clone()), config.clone()).await;
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
    let changed = Harness::start_configured(&path, osv, Some(ai), config).await;
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
            api_key: Some("test-openai-key".into()),
            ai_timeout_secs: 1,
            ..Default::default()
        };
        let app = Harness::start_configured(
            &path,
            Router::new().fallback(|| async { Json(json!({})) }),
            Some(ai),
            config,
        )
        .await;
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
            api_key: has_openai.then(|| "test-openai-key".into()),
            anthropic_api_key: Some("test-anthropic-key".into()),
            ai_timeout_secs: 1,
            ..Default::default()
        };
        let app = Harness::start_configured(
            &directory.path().join("sbom.json"),
            Router::new().fallback(|| async { Json(json!({})) }),
            Some(ai),
            config,
        )
        .await;
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
            anthropic_api_key: Some("test-anthropic-key".into()),
            ai_timeout_secs: 1,
            ..Default::default()
        };
        let osv =
            Router::new().fallback(|| async { Json(json!({"vulns":[{"id":"CVE-2021-45105"}]})) });
        let app =
            Harness::start_configured(&directory.path().join("sbom.json"), osv, Some(ai), config)
                .await;
        app.upload(VULNERABLE).await;
        let status = app.status().await;
        assert_eq!(status["policy"]["ai"]["status"], "failed");
        assert_eq!(
            status["policy"]["ai"]["attempts"].as_array().unwrap().len(),
            1
        );
        assert_eq!(status["policy"]["generated_rules"], json!([]));
        assert_eq!(status["policy"]["osv"]["summary"]["uncovered"], 1);
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
async fn generated_quarantine_blocks_every_method_and_clears_after_patching() {
    let directory = tempfile::tempdir().unwrap();
    let osv = Router::new().route(
        "/v1/query",
        post(|Json(query): Json<Value>| async move {
            if query["version"] == "1.0.0.RELEASE" {
                Json(json!({"vulns":[{"id":"CVE-2026-12345"}]}))
            } else {
                Json(json!({}))
            }
        }),
    );
    let ai = Router::new().fallback(|| async { Json(openai_reply(json!([]))) });
    let app =
        Harness::start_with_services(&directory.path().join("sbom.json"), osv, Some(ai)).await;
    let vulnerable =
        r#"{"format":"filtr-1","packages":[{"purl":"pkg:maven/example/component@1.0.0.RELEASE"}]}"#;
    app.upload(vulnerable).await;
    let status = app.status().await;
    assert_eq!(status["policy"]["osv"]["summary"]["quarantined"], 1);
    let generated = &status["policy"]["generated_rules"][0];
    assert_eq!(generated["origin"], "osv_quarantine");
    assert_eq!(generated["version"], "1.0.0.RELEASE");
    assert_eq!(generated["action"]["type"], "deny_all");
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
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(app.hits.load(Ordering::SeqCst), 0);
    assert_eq!(app.upload(PATCHED).await.status(), StatusCode::OK);
    assert_eq!(app.status().await["policy"]["generated_rules"], json!([]));
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn restart_without_ai_uses_static_rules_even_when_osv_is_down() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sbom.json");
    let osv = Router::new().fallback(|| async { Json(json!({"vulns":[{"id":"CVE-2021-45105"}]})) });
    let ai = Router::new().fallback(|| async { Json(openai_reply(json!([]))) });
    let app = Harness::start_with_services(&path, osv, Some(ai)).await;
    app.upload(VULNERABLE).await;
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    drop(app);
    let outage = Router::new().fallback(|| async { StatusCode::SERVICE_UNAVAILABLE });
    let restarted = Harness::start_with_osv(&path, outage).await;
    let status = restarted.status().await;
    assert_eq!(status["policy"]["osv"]["status"], "failed");
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
    let osv = Router::new().fallback(|| async { Json(json!({"vulns":[{"id":"CVE-2021-44228", "details":"Lookup substitution is interpreted by the installed package."}]})) });
    let ai = Router::new().route("/v1/responses", post(|headers: axum::http::HeaderMap, Json(request): Json<Value>| async move {
        assert_eq!(headers[header::AUTHORIZATION], "Bearer test-openai-key");
        assert_eq!(request["model"], "gpt-6-sol");
        assert_eq!(request["reasoning"]["effort"], "xhigh");
        assert_eq!(request["store"], false);
        assert_eq!(request["text"]["format"]["strict"], true);
        let input: Value = serde_json::from_str(request["input"][0]["content"].as_str().unwrap()).unwrap();
        assert_eq!(input["components"].as_array().unwrap().len(), 1);
        assert_eq!(input["curated_rules"][0]["id"], "log4shell-lookups");
        assert!(input["findings"][0]["vulnerabilities"][0]["details"].is_string());
        assert!(!request.to_string().contains(TOKEN));
        Json(openai_reply(json!([{"component_index":0,"basis":"log4shell-lookups","action":"tokens","patterns":["ai-added-marker"],"reason":"Test additive marker justified by supplied evidence."}])))
    }));
    let app =
        Harness::start_with_services(&directory.path().join("sbom.json"), osv, Some(ai)).await;
    assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
    let status = app.status().await;
    assert_eq!(status["policy"]["ai"]["status"], "complete");
    assert_eq!(status["policy"]["ai"]["components_reviewed"], 1);
    assert_eq!(status["policy"]["ai"]["applied_rules"], json!(["ai:0"]));
    assert_eq!(status["policy"]["osv"]["summary"]["ai_rule_matches"], 1);
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
async fn invalid_ai_proposals_cannot_weaken_quarantine() {
    let directory = tempfile::tempdir().unwrap();
    let osv = Router::new().fallback(|| async { Json(json!({"vulns":[{"id":"CVE-2021-45105"}]})) });
    let ai = Router::new().fallback(|| async { Json(openai_reply(json!([
        {"component_index":0,"basis":"CVE-2021-45105","action":"tokens","patterns":["extra-marker"],"reason":"An additive test marker."},
        {"component_index":0,"basis":"CVE-2021-45105","action":"allow","patterns":[],"reason":"Remove quarantine."},
        {"component_index":99,"basis":"CVE-2021-45105","action":"deny_all","patterns":[],"reason":"Invalid component."},
        {"component_index":0,"basis":"CVE-2099-99999","action":"deny_all","patterns":[],"reason":"Invented CVE."},
        {"component_index":0,"basis":"CVE-2021-45105","action":"tokens","patterns":[],"reason":"Empty patterns."}
    ]))) });
    let app =
        Harness::start_with_services(&directory.path().join("sbom.json"), osv, Some(ai)).await;
    app.upload(VULNERABLE).await;
    let status = app.status().await;
    assert_eq!(status["policy"]["ai"]["status"], "partial");
    assert_eq!(
        status["policy"]["ai"]["rejected"].as_array().unwrap().len(),
        4
    );
    assert_eq!(status["policy"]["ai"]["applied_rules"], json!(["ai:0"]));
    assert_eq!(
        status["policy"]["generated_rules"][0]["origin"],
        "osv_quarantine"
    );
    assert_eq!(
        status["policy"]["generated_rules"][0]["action"]["type"],
        "deny_all"
    );
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(app.hits.load(Ordering::SeqCst), 0);
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
        let osv =
            Router::new().fallback(|| async { Json(json!({"vulns":[{"id":"CVE-2021-45105"}]})) });
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
        let app =
            Harness::start_with_services(&directory.path().join("sbom.json"), osv, Some(ai)).await;
        assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
        assert_eq!(app.status().await["policy"]["ai"]["status"], "complete");
        assert_eq!(
            app.client.get(&app.public).send().await.unwrap().status(),
            StatusCode::FORBIDDEN
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
        assert_eq!(status["policy"]["osv"]["summary"]["quarantined"], 0);
        assert_eq!(status["policy"]["osv"]["summary"]["uncovered"], 1);
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

fn large_advisory_inventory() -> Router {
    Router::new().fallback(|| async {
        let vulns: Vec<_> = (0..50)
            .map(|index| json!({"id":format!("CVE-2026-{:05}", index), "details":"x".repeat(8192)}))
            .collect();
        Json(json!({"vulns": vulns}))
    })
}

#[tokio::test]
async fn large_ai_reviews_send_every_advisory_in_bounded_batches() {
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
    let app = Harness::start_with_services(
        &directory.path().join("sbom.json"),
        large_advisory_inventory(),
        Some(ai),
    )
    .await;
    assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
    let status = app.status().await;
    assert_eq!(status["policy"]["ai"]["status"], "complete");
    assert_eq!(status["policy"]["ai"]["components_reviewed"], 1);
    assert_eq!(status["policy"]["ai"]["batches_total"], 4);
    assert_eq!(status["policy"]["ai"]["batches_completed"], 4);
    assert!(status["policy"]["ai"]["input_bytes"].as_u64().unwrap() > 256 * 1024);
    assert_eq!(status["policy"]["osv"]["summary"]["quarantined"], 50);
    let sent = requests.lock().unwrap();
    assert_eq!(sent.len(), 4);
    let ids: std::collections::BTreeSet<_> = sent
        .iter()
        .flat_map(|input| {
            input["findings"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|p| p["vulnerabilities"].as_array().unwrap())
                .map(|v| v["id"].as_str().unwrap().to_owned())
        })
        .collect();
    assert_eq!(ids, (0..50).map(|i| format!("CVE-2026-{i:05}")).collect());
}

#[tokio::test]
async fn a_failed_batch_discards_successful_batch_enhancements() {
    let directory = tempfile::tempdir().unwrap();
    let ai = Router::new().route("/v1/responses", post(|Json(request): Json<Value>| async move {
        let input: Value = serde_json::from_str(request["input"][0]["content"].as_str().unwrap()).unwrap();
        let is_last = input["findings"].as_array().unwrap().iter().any(|p| p["vulnerabilities"][0]["id"] == "CVE-2026-00049");
        if is_last {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            return StatusCode::BAD_REQUEST.into_response();
        }
        Json(openai_reply(json!([{"component_index":0,"basis":"log4shell-lookups","action":"tokens","patterns":["batch-marker"],"reason":"Test enhancement that must not activate after another batch fails."}]))).into_response()
    }));
    let app = Harness::start_with_services(
        &directory.path().join("sbom.json"),
        large_advisory_inventory(),
        Some(ai),
    )
    .await;
    assert_eq!(app.upload(VULNERABLE).await.status(), StatusCode::OK);
    let status = app.status().await;
    assert_eq!(status["policy"]["ai"]["status"], "failed");
    assert_eq!(status["policy"]["ai"]["batches_completed"], 3);
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
    let osv = Router::new().fallback(|| async { Json(json!({"vulns":[{"id":"CVE-2021-45105"}]})) });
    let finish_review = Arc::new(tokio::sync::Notify::new());
    let completion = finish_review.clone();
    let ai = Router::new().fallback(move || {
        let completion = completion.clone();
        async move {
            completion.notified().await;
            Json(openai_reply(json!([])))
        }
    });
    let app =
        Harness::start_with_services(&directory.path().join("sbom.json"), osv, Some(ai)).await;
    let request = app
        .client
        .post(format!("{}/v1/sbom", app.admin))
        .bearer_auth(TOKEN)
        .body(VULNERABLE);
    let upload = tokio::spawn(async move { request.send().await.unwrap() });
    let pending = app.wait_for("/policy/ai/status", json!("pending")).await;
    assert_eq!(pending["policy"]["generated_rules"], json!([]));
    assert_eq!(pending["policy"]["osv"]["summary"]["uncovered"], 1);
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::CREATED
    );
    finish_review.notify_one();
    assert_eq!(upload.await.unwrap().status(), StatusCode::OK);
    let complete = app.status().await;
    assert_eq!(complete["policy"]["ai"]["status"], "complete");
    assert_eq!(complete["policy"]["osv"]["summary"]["quarantined"], 1);
    assert_eq!(
        app.client.get(&app.public).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(app.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn static_rules_remain_active_while_ai_is_pending_and_after_timeout() {
    let directory = tempfile::tempdir().unwrap();
    let osv = Router::new().fallback(|| async { Json(json!({"vulns":[{"id":"CVE-2021-45105"}]})) });
    let ai = Router::new().fallback(|| async {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        Json(openai_reply(json!([])))
    });
    let path = directory.path().join("sbom.json");
    let app = Harness::start_with_services(&path, osv.clone(), Some(ai.clone())).await;
    let request = app
        .client
        .post(format!("{}/v1/sbom", app.admin))
        .bearer_auth(TOKEN)
        .body(VULNERABLE);
    let upload = tokio::spawn(async move { request.send().await.unwrap() });
    let status = app.wait_for("/policy/ai/status", json!("pending")).await;
    assert_eq!(status["policy"]["generated_rules"], json!([]));
    assert_eq!(status["policy"]["osv"]["summary"]["uncovered"], 1);
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
    let restarted = Harness::start_with_services(&path, osv, Some(ai)).await;
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
