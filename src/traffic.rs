use crate::{AppState, ai::Status, error, persist, policy::Report, read_bounded};
use anyhow::{Context, Result, ensure};
use arc_swap::{ArcSwap, ArcSwapOption};
use axum::{
    Json,
    body::to_bytes,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Auto,
    Filter,
    BlockAll,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
struct AutomaticFinding {
    cve: String,
    package: String,
    installed_version: String,
    source: String,
    reason: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Setting {
    mode: Mode,
    reason: String,
    changed_at: u64,
    automatic_findings: Vec<AutomaticFinding>,
    automatic_updated_at: u64,
}

pub(crate) struct Controller {
    setting: ArcSwap<Setting>,
    updates: Arc<Mutex<()>>,
    path: PathBuf,
    auto_block: bool,
    persistence_error: ArcSwapOption<String>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Controller {
    pub(crate) fn load(sbom: &Path, auto_block: bool) -> Result<Self> {
        let mut path = sbom.as_os_str().to_owned();
        path.push(".traffic.json");
        let path = PathBuf::from(path);
        let setting = match read_bounded(&path) {
            Ok(bytes) => {
                serde_json::from_slice::<Setting>(&bytes).context("invalid saved traffic state")?
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                Setting {
                    mode: Mode::Auto,
                    reason: "Default targeted filtering".into(),
                    changed_at: 0,
                    automatic_findings: Vec::new(),
                    automatic_updated_at: 0,
                }
            }
            Err(error) => return Err(error.context("cannot load traffic state")),
        };
        ensure!(
            !setting.reason.trim().is_empty()
                && setting.reason.len() <= 2048
                && setting.automatic_findings.len() <= 512,
            "invalid saved traffic state limits"
        );
        Ok(Self {
            setting: ArcSwap::from_pointee(setting),
            updates: Arc::new(Mutex::new(())),
            path,
            auto_block,
            persistence_error: ArcSwapOption::empty(),
        })
    }

    fn blocked(&self, setting: &Setting) -> Option<&'static str> {
        match setting.mode {
            Mode::BlockAll => Some("traffic-blocked-operator"),
            Mode::Auto if self.auto_block && !setting.automatic_findings.is_empty() => {
                Some("traffic-blocked-critical")
            }
            _ => None,
        }
    }

    pub(crate) fn block_reason(&self) -> Option<&'static str> {
        self.blocked(&self.setting.load())
    }

    pub(crate) fn report(&self, sbom_ready: bool) -> Value {
        self.describe(&self.setting.load(), sbom_ready)
    }

    fn describe(&self, setting: &Setting, sbom_ready: bool) -> Value {
        json!({"mode":setting.mode,"reason":setting.reason,"changed_at":setting.changed_at,
            "effective":if self.blocked(setting).is_some(){"blocked"}else{"filtering"},
            "block_reason":self.blocked(setting),"sbom_ready":sbom_ready,"auto_block_critical":self.auto_block,
            "automatic_findings":setting.automatic_findings,"automatic_updated_at":setting.automatic_updated_at,
            "persistence_error":self.persistence_error.load_full().as_deref()})
    }

    pub(crate) fn preview(&self, report: &Report) -> Value {
        let mut setting = self.setting.load_full().as_ref().clone();
        if let Some(findings) = Self::assessment(report) {
            setting.automatic_findings = findings;
        }
        let mut result = self.describe(&setting, true);
        result["preview"] = json!(true);
        result["automatic_updated_at"] = Value::Null;
        result
    }

    fn assessment(report: &Report) -> Option<Vec<AutomaticFinding>> {
        if !matches!(report.ai.status, Status::Complete) {
            return None;
        }
        Some(
            report
                .ai
                .discoveries
                .iter()
                .filter(|d| d.emergency_recommended())
                .filter_map(|finding| {
                    let component = &report.components.get(finding.component_index)?.component;
                    let emergency = finding.emergency.as_ref()?;
                    Some(AutomaticFinding {
                        cve: finding.cve.clone(),
                        package: component.package.clone()?,
                        installed_version: component.version.clone()?,
                        source: emergency.source.clone(),
                        reason: emergency.reason.clone(),
                    })
                })
                .collect(),
        )
    }

    async fn save(&self, setting: &Setting) -> Result<()> {
        let path = self.path.clone();
        let bytes = serde_json::to_vec(setting)?;
        tokio::task::spawn_blocking(move || persist(&path, &bytes)).await??;
        Ok(())
    }

    pub(crate) async fn observe(&self, report: &Report) {
        let Some(mut findings) = Self::assessment(report) else {
            return;
        };
        findings.sort();
        findings.dedup();
        let _guard = self.updates.lock().await;
        let mut next = self.setting.load_full().as_ref().clone();
        if next.automatic_findings == findings {
            return;
        }
        next.automatic_findings = findings;
        next.automatic_updated_at = now();
        if self.save(&next).await.is_err() {
            self.persistence_error.store(Some(Arc::new(
                "automatic traffic assessment could not be persisted".into(),
            )));
            tracing::error!("automatic traffic assessment persistence failed");
            if next.automatic_findings.is_empty() {
                return;
            }
        } else {
            self.persistence_error.store(None);
        }
        self.setting.store(Arc::new(next));
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    mode: Mode,
    reason: String,
}

pub(crate) async fn get(State(state): State<Arc<AppState>>) -> Response {
    Json(state.traffic.report(state.policy.load().is_some())).into_response()
}

pub(crate) async fn set(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if request.headers().contains_key(header::CONTENT_ENCODING) {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "encoded-control-not-supported",
        );
    }
    let bytes = match tokio::time::timeout(
        Duration::from_secs(state.config.timeout_secs),
        to_bytes(request.into_body(), 4096),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid-or-oversized-control-body",
            );
        }
        Err(_) => return error(StatusCode::REQUEST_TIMEOUT, "control-body-timeout"),
    };
    let change: Change = match serde_json::from_slice(&bytes) {
        Ok(c) => c,
        Err(_) => return error(StatusCode::UNPROCESSABLE_ENTITY, "invalid-traffic-mode"),
    };
    if change.reason.trim().is_empty() || change.reason.len() > 2048 {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "traffic-reason-required");
    }
    let Ok(guard) = state.traffic.updates.clone().try_lock_owned() else {
        return error(StatusCode::CONFLICT, "traffic-update-in-progress");
    };
    match tokio::spawn(apply(state, change, guard)).await {
        Ok(response) => response,
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "traffic-update-failed"),
    }
}

async fn apply(
    state: Arc<AppState>,
    change: Change,
    _guard: tokio::sync::OwnedMutexGuard<()>,
) -> Response {
    let mut next = state.traffic.setting.load_full().as_ref().clone();
    next.mode = change.mode;
    next.reason = change.reason;
    next.changed_at = now();
    if state.traffic.save(&next).await.is_err() {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "traffic-state-save-failed",
        );
    }
    state.traffic.setting.store(Arc::new(next));
    state.traffic.persistence_error.store(None);
    state.notify("traffic_mode");
    Json(state.traffic.report(state.policy.load().is_some())).into_response()
}
