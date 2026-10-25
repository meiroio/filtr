use crate::{
    AppState, ai, error,
    policy::{Policy, Report},
    read_sbom, remediation, sbom,
};
use axum::{
    Json,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub(crate) async fn preview(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let cache_only = match request.uri().query() {
        None | Some("") | Some("cache_only=false") => false,
        Some("cache_only=true") => true,
        _ => return error(StatusCode::BAD_REQUEST, "invalid-preview-options"),
    };
    // Serialize cache writers and freeze the baseline without publishing a pending policy.
    let Ok(guard) = state.updates.clone().try_lock_owned() else {
        return error(StatusCode::CONFLICT, "sbom-update-in-progress");
    };
    let bytes = match read_sbom(&state, request).await {
        Ok(bytes) => bytes,
        Err((status, code)) => return error(status, code),
    };
    match tokio::spawn(evaluate(state, bytes, cache_only, guard)).await {
        Ok(response) => response,
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "preview-failed"),
    }
}

async fn evaluate(
    state: Arc<AppState>,
    bytes: axum::body::Bytes,
    cache_only: bool,
    _guard: tokio::sync::OwnedMutexGuard<()>,
) -> Response {
    let baseline = state.policy.load_full();
    let compile_state = state.clone();
    let compiled = tokio::task::spawn_blocking(move || {
        Policy::compile(sbom::parse(&bytes)?, &compile_state.catalog)
    })
    .await;
    let mut candidate = match compiled {
        Ok(Ok(policy)) => policy,
        Ok(Err(reason)) => return error(StatusCode::UNPROCESSABLE_ENTITY, &reason.to_string()),
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "preview-compilation-failed",
            );
        }
    };
    state
        .ai
        .enhance(&mut candidate, ai::ReviewTrigger::Preview { cache_only })
        .await;
    let mut result = report(
        baseline.as_ref().map(|p| &p.report),
        &candidate.report,
        cache_only,
    );
    result["baseline"] = baseline
        .as_ref()
        .map_or(Value::Null, |policy| state.remediation(&policy.report));
    result["candidate"]["remediation"] =
        remediation::with_traffic(&candidate.report, state.traffic.preview(&candidate.report));
    Json(result).into_response()
}

fn report(baseline: Option<&Report>, candidate: &Report, cache_only: bool) -> Value {
    let complete = matches!(candidate.ai.status, ai::Status::Complete);
    let previous_cves = baseline.map(cves).unwrap_or_default();
    let candidate_cves = cves(candidate);
    let absent: Vec<_> = previous_cves.difference(&candidate_cves).copied().collect();
    let previous_components = baseline.map(components).unwrap_or_default();
    let candidate_components = components(candidate);
    let added: Vec<_> = candidate_components
        .iter()
        .filter(|(identity, _)| !previous_components.contains_key(*identity))
        .map(|(_, index)| remediation::component_details(candidate, *index))
        .collect();
    let removed: Vec<_> = previous_components
        .iter()
        .filter(|(identity, _)| !candidate_components.contains_key(*identity))
        .filter_map(|(_, index)| {
            baseline.map(|report| remediation::component_details(report, *index))
        })
        .collect();
    json!({
        "preview": true, "installed": false, "cache_only": cache_only,
        "analysis_complete": complete,
        "baseline": baseline.map(remediation::report),
        "candidate": {"policy": candidate, "inventory": remediation::inventory(candidate), "remediation": remediation::report(candidate)},
        "diff": {
            "resolved_cves": if complete { absent.clone() } else { Vec::new() },
            "unverified_absent_cves": if complete { Vec::new() } else { absent },
            "remaining_cves": previous_cves.intersection(&candidate_cves).collect::<Vec<_>>(),
            "new_cves": candidate_cves.difference(&previous_cves).collect::<Vec<_>>(),
            "components_added": added, "components_removed": removed,
        },
        "warning": "Preview only; live policy, saved SBOM, rankings and webhooks are unchanged. Cached findings have their recorded age. Missing/expired reviews and failed analysis are not proof that absent CVEs are resolved. Even complete analysis and empty gap lists do not prove vulnerability-free software. Deploy real artifacts before uploading their actual inventory.",
    })
}

fn cves(report: &Report) -> BTreeSet<&str> {
    report
        .active_rules
        .iter()
        .chain(report.advisory_rules.iter())
        .map(|rule| rule.cve.as_str())
        .chain(
            report
                .generated_rules
                .iter()
                .flat_map(|rule| rule.cves.iter().map(String::as_str)),
        )
        .chain(
            report
                .ai
                .discoveries
                .iter()
                .map(|finding| finding.cve.as_str()),
        )
        .collect()
}

type Identity<'a> = (Option<&'a str>, Option<&'a str>, Option<&'a str>);

fn components(report: &Report) -> BTreeMap<Identity<'_>, usize> {
    report
        .components
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let component = &item.component;
            (
                (
                    component.package.as_deref(),
                    component.version.as_deref(),
                    component
                        .package
                        .is_none()
                        .then_some(component.name.as_str()),
                ),
                index,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cve_remaining_on_another_version_is_not_resolved() {
        let catalog = crate::policy::Catalog::bundled().unwrap();
        let old = Policy::compile(sbom::parse(br#"{"format":"filtr-1","packages":[{"purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},{"purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.12.1"}]}"#).unwrap(), &catalog).unwrap();
        let mut new = Policy::compile(sbom::parse(br#"{"format":"filtr-1","packages":[{"purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.12.1"}]}"#).unwrap(), &catalog).unwrap();
        new.report.ai.status = ai::Status::Complete;
        let result = report(Some(&old.report), &new.report, true);
        assert_eq!(result["diff"]["resolved_cves"], json!([]));
        assert_eq!(result["diff"]["remaining_cves"], json!(["CVE-2021-44228"]));
        assert_eq!(
            result["diff"]["components_removed"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(result["diff"]["components_added"], json!([]));
    }
}
