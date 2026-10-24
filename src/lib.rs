#![forbid(unsafe_code)]

pub mod ai;
pub mod generated;
mod network;
pub mod policy;
mod proxy;
mod remediation;
pub mod sbom;

use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwapOption;
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use futures_util::StreamExt;
use policy::{Catalog, Policy};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, Semaphore};

#[derive(Parser)]
#[command(
    version,
    about = "SBOM-aware HTTP firewall reverse proxy. Administration is loopback-only."
)]
pub struct Config {
    #[arg(long, env = "FILTR_LISTEN", default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,
    #[arg(long, env = "FILTR_ADMIN_LISTEN", default_value = "127.0.0.1:9090")]
    pub admin_listen: SocketAddr,
    #[arg(long, env = "FILTR_UPSTREAM")]
    pub upstream: reqwest::Url,
    #[arg(long, env = "FILTR_ADMIN_TOKEN", hide_env_values = true)]
    pub admin_token: String,
    #[arg(long, env = "FILTR_SBOM", default_value = "data/sbom.json")]
    pub sbom: PathBuf,
    /// Replace the bundled catalogue with a local JSON catalogue.
    #[arg(long, env = "FILTR_RULES")]
    pub rules: Option<PathBuf>,
    #[command(flatten)]
    pub ai: ai::AiConfig,
    #[arg(long, default_value_t = 1_048_576)]
    pub max_body_bytes: usize,
    #[arg(long, default_value_t = 10)]
    pub timeout_secs: u64,
    #[arg(long, default_value_t = 128)]
    pub max_in_flight: usize,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        self.ai.validate()?;
        ensure!(
            self.admin_listen.ip().is_loopback(),
            "admin listener must use a loopback address"
        );
        ensure!(
            self.listen != self.admin_listen,
            "public and admin addresses must differ"
        );
        ensure!(
            self.admin_token.len() == 128
                && self.admin_token.bytes().all(|b| b.is_ascii_hexdigit()),
            "admin token must contain 128 hexadecimal characters encoding a 64-byte secret"
        );
        ensure!(
            matches!(self.upstream.scheme(), "http" | "https")
                && self.upstream.host_str().is_some(),
            "upstream must be an HTTP(S) origin"
        );
        ensure!(
            self.upstream.username().is_empty()
                && self.upstream.password().is_none()
                && self.upstream.path() == "/"
                && self.upstream.query().is_none()
                && self.upstream.fragment().is_none(),
            "upstream must be an origin without credentials, path, query or fragment"
        );
        ensure!(
            (1..=16 * 1024 * 1024).contains(&self.max_body_bytes),
            "body limit must be between 1 byte and 16 MiB"
        );
        ensure!(
            (1..=300).contains(&self.timeout_secs) && (1..=4096).contains(&self.max_in_flight),
            "invalid timeout or concurrency limit"
        );
        if let Some(port) = self.upstream.port_or_known_default() {
            let same_listener = [self.listen, self.admin_listen].iter().any(|address| {
                address.port() != 0
                    && address.port() == port
                    && self.upstream.host_str().is_some_and(|host| {
                        host == address.ip().to_string()
                            || host == "localhost"
                            || address.ip().is_unspecified()
                    })
            });
            ensure!(
                !same_listener,
                "upstream must not point back to a Filtr listener"
            );
        }
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct Counters {
    seen: AtomicU64,
    blocked: AtomicU64,
    proxied: AtomicU64,
    upstream_errors: AtomicU64,
}

pub struct AppState {
    config: Config,
    catalog: Catalog,
    policy: ArcSwapOption<Policy>,
    client: reqwest::Client,
    ai: ai::Client,
    counters: Counters,
    requests: Arc<Semaphore>,
    admin_requests: Arc<Semaphore>,
    updates: Arc<Mutex<()>>,
}

pub fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take((sbom::MAX_SBOM_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= sbom::MAX_SBOM_BYTES, "file exceeds 64 MiB");
    Ok(bytes)
}

impl AppState {
    pub async fn new(config: Config) -> Result<Arc<Self>> {
        config.validate()?;
        let catalog = match &config.rules {
            Some(path) => Catalog::parse(&read_bounded(path)?)?,
            None => Catalog::bundled()?,
        };
        let ai = ai::Client::new(config.ai.clone(), &config.sbom)?;
        let policy = match read_bounded(&config.sbom) {
            Ok(bytes) => {
                let mut policy = Policy::compile(sbom::parse(&bytes)?, &catalog)?;
                ai.enhance(&mut policy, ai::ReviewTrigger::Startup).await;
                Some(Arc::new(policy))
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                None
            }
            Err(error) => return Err(error.context("cannot load saved SBOM")),
        };
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .http1_only()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(config.timeout_secs))
            .pool_max_idle_per_host(config.max_in_flight)
            .build()?;
        let state = Arc::new(Self {
            requests: Arc::new(Semaphore::new(config.max_in_flight)),
            admin_requests: Arc::new(Semaphore::new(8)),
            config,
            catalog,
            client,
            ai,
            policy: ArcSwapOption::from(policy),
            counters: Counters::default(),
            updates: Arc::new(Mutex::new(())),
        });
        schedule_refresh(&state);
        Ok(state)
    }
}

fn schedule_refresh(state: &Arc<AppState>) {
    let state = Arc::downgrade(state);
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(Duration::from_secs(1));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            timer.tick().await;
            let Some(state) = state.upgrade() else { break };
            let due = state
                .policy
                .load_full()
                .is_some_and(|policy| state.ai.refresh_due(&policy));
            if !due {
                continue;
            }
            let Ok(guard) = state.updates.clone().try_lock_owned() else {
                continue;
            };
            if let Err(error) = reanalyze(state, guard, ai::ReviewTrigger::Expired).await {
                tracing::error!(error = %error, "automatic AI refresh failed");
            }
        }
    });
}

async fn reanalyze(
    state: Arc<AppState>,
    _guard: tokio::sync::OwnedMutexGuard<()>,
    trigger: ai::ReviewTrigger,
) -> Result<Arc<Policy>> {
    let current = state
        .policy
        .load_full()
        .context("an SBOM must be installed before refresh")?;
    let components = current
        .report
        .components
        .iter()
        .map(|item| item.component.clone())
        .collect();
    let mut policy = Policy::compile(components, &state.catalog)?;
    policy.report.ai = state.ai.pending_review();
    state.policy.store(Some(Arc::new(policy.clone())));
    state.ai.enhance(&mut policy, trigger).await;
    let policy = Arc::new(policy);
    state.policy.store(Some(policy.clone()));
    Ok(policy)
}

async fn refresh(State(state): State<Arc<AppState>>) -> Response {
    let Ok(guard) = state.updates.clone().try_lock_owned() else {
        return error(StatusCode::CONFLICT, "sbom-update-in-progress");
    };
    if state.policy.load_full().is_none() {
        return error(StatusCode::CONFLICT, "sbom-required");
    }
    match tokio::spawn(reanalyze(state, guard, ai::ReviewTrigger::Refresh)).await {
        Ok(Ok(policy)) => Json(json!({"ready":true,"policy":policy.report})).into_response(),
        _ => error(StatusCode::INTERNAL_SERVER_ERROR, "refresh-failed"),
    }
}

pub fn routers(state: Arc<AppState>) -> (Router, Router) {
    let public = Router::new()
        .fallback(proxy::forward)
        .layer(middleware::from_fn_with_state(state.clone(), public_gate))
        .with_state(state.clone());
    let admin = Router::new()
        .route("/livez", get(|| async { StatusCode::OK }))
        .route("/healthz", get(health))
        .route("/v1/status", get(status))
        .route("/v1/rules", get(rules))
        .route("/v1/remediation", get(remediation))
        .route("/v1/sbom", post(upload))
        .route("/v1/refresh", post(refresh))
        .layer(middleware::from_fn_with_state(state.clone(), admin_gate))
        .with_state(state);
    (public, admin)
}

fn error(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({"error": code}))).into_response()
}

pub(crate) fn block(state: &AppState, status: StatusCode, code: &str) -> Response {
    state.counters.blocked.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(rule = code, status = status.as_u16(), "request blocked");
    error(status, code)
}

async fn public_gate(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    state.counters.seen.fetch_add(1, Ordering::Relaxed);
    let Ok(permit) = state.requests.clone().try_acquire_owned() else {
        return block(&state, StatusCode::SERVICE_UNAVAILABLE, "capacity-exceeded");
    };
    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    // Keep the permit until the downstream consumes or drops the response stream.
    let stream = futures_util::stream::unfold(
        (body.into_data_stream(), permit),
        |(mut stream, permit)| async move { stream.next().await.map(|item| (item, (stream, permit))) },
    );
    Response::from_parts(parts, Body::from_stream(stream))
}

async fn admin_gate(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    let expected = format!("Bearer {}", state.config.admin_token);
    let provided = request
        .headers()
        .get(header::AUTHORIZATION)
        .map(|h| h.as_bytes())
        .unwrap_or_default();
    if !bool::from(provided.ct_eq(expected.as_bytes())) {
        let mut response = error(StatusCode::UNAUTHORIZED, "unauthorized");
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
        return response;
    }
    let Ok(_permit) = state.admin_requests.clone().try_acquire_owned() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "capacity-exceeded");
    };
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

async fn health(State(state): State<Arc<AppState>>) -> Response {
    let ready = state.policy.load().is_some();
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({"ready": ready})),
    )
        .into_response()
}

async fn status(State(state): State<Arc<AppState>>) -> Response {
    let policy = state.policy.load_full();
    Json(json!({
        "ready": policy.is_some(),
        "policy": policy.as_ref().map(|p| &p.report),
        "limits": {"body_bytes": state.config.max_body_bytes, "timeout_secs": state.config.timeout_secs, "max_in_flight": state.config.max_in_flight},
        "counters": {
            "seen": state.counters.seen.load(Ordering::Relaxed),
            "blocked": state.counters.blocked.load(Ordering::Relaxed),
            "proxied": state.counters.proxied.load(Ordering::Relaxed),
            "upstream_errors": state.counters.upstream_errors.load(Ordering::Relaxed)
        }
    })).into_response()
}

async fn rules(State(state): State<Arc<AppState>>) -> Response {
    let policy = state.policy.load_full();
    Json(json!({"version": 1, "rules": state.catalog.specs(), "generated_rules": policy.as_ref().map(|p| &p.report.generated_rules), "ai": policy.as_ref().map(|p| &p.report.ai)})).into_response()
}

async fn remediation(State(state): State<Arc<AppState>>) -> Response {
    let Some(policy) = state.policy.load_full() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "sbom-required");
    };
    Json(remediation::report(&policy.report)).into_response()
}

fn persist(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path).context("cannot atomically save SBOM")?;
    Ok(())
}

async fn install(
    state: Arc<AppState>,
    bytes: axum::body::Bytes,
    _guard: tokio::sync::OwnedMutexGuard<()>,
) -> Result<Arc<Policy>> {
    let saved_state = state.clone();
    let mut policy = tokio::task::spawn_blocking(move || {
        let components = sbom::parse(&bytes)?;
        let policy = Policy::compile(components, &saved_state.catalog)?;
        persist(&saved_state.config.sbom, &bytes)?;
        Ok::<_, anyhow::Error>(policy)
    })
    .await
    .context("SBOM compilation task failed")??;
    // Static mappings remain active until an AI review succeeds, even after disconnect.
    state.policy.store(Some(Arc::new(policy.clone())));
    tracing::info!(
        components = policy.report.components.len(),
        active_rules = policy.report.active_rules.len(),
        "SBOM policy activated"
    );
    policy.report.ai = state.ai.pending_review();
    state.policy.store(Some(Arc::new(policy.clone())));
    state
        .ai
        .enhance(&mut policy, ai::ReviewTrigger::SbomUpdate)
        .await;
    let policy = Arc::new(policy);
    state.policy.store(Some(policy.clone()));
    Ok(policy)
}

async fn upload(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if request.headers().contains_key(header::CONTENT_ENCODING) {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "encoded-sbom-not-supported",
        );
    }
    let Ok(update_guard) = state.updates.clone().try_lock_owned() else {
        return error(StatusCode::CONFLICT, "sbom-update-in-progress");
    };
    let bytes = match tokio::time::timeout(
        Duration::from_secs(state.config.timeout_secs),
        to_bytes(request.into_body(), sbom::MAX_SBOM_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid-or-oversized-sbom-body",
            );
        }
        Err(_) => return error(StatusCode::REQUEST_TIMEOUT, "sbom-upload-timeout"),
    };
    let result = tokio::spawn(install(state, bytes, update_guard)).await;
    match result {
        Ok(Ok(policy)) => Json(json!({"ready": true, "policy": policy.report})).into_response(),
        Ok(Err(error)) => {
            let status = if error.downcast_ref::<std::io::Error>().is_some()
                || error.downcast_ref::<tempfile::PersistError>().is_some()
                || error.downcast_ref::<tokio::task::JoinError>().is_some()
            {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::UNPROCESSABLE_ENTITY
            };
            (status, Json(json!({"error": error.to_string()}))).into_response()
        }
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "sbom-update-failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn http_and_ai_timeouts_have_distinct_cli_arguments() {
        Config::command().debug_assert();
        let config = Config::try_parse_from([
            "filtr",
            "--upstream",
            "http://127.0.0.1:3000",
            "--admin-token",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--timeout-secs",
            "7",
            "--ai-timeout-secs",
            "23",
            "--ai-review-timeout-secs",
            "47",
            "--ai-provider",
            "anthropic",
        ])
        .unwrap();
        assert_eq!(config.timeout_secs, 7);
        assert_eq!(config.ai.ai_timeout_secs, 23);
        assert_eq!(config.ai.ai_review_timeout_secs, 47);
        assert_eq!(config.ai.provider, Some(ai::Provider::Anthropic));
        config.validate().unwrap();
    }

    #[test]
    fn admin_tokens_require_exactly_64_bytes_encoded_as_hex() {
        let token = "ab".repeat(64);
        let mut config = Config::try_parse_from([
            "filtr",
            "--upstream",
            "http://127.0.0.1:3000",
            "--admin-token",
            &token,
        ])
        .unwrap();
        config.validate().unwrap();
        for invalid in [
            "ab".repeat(32),
            "a".repeat(127),
            "a".repeat(129),
            "g".repeat(128),
        ] {
            config.admin_token = invalid;
            assert!(config.validate().is_err());
        }
    }
}
