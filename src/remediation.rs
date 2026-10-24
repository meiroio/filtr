use crate::policy::{Action, Report};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(crate) fn report(policy: &Report) -> Value {
    let mut blockers = Vec::new();
    for rule in &policy.active_rules {
        let components: Vec<_> = policy
            .components
            .iter()
            .enumerate()
            .filter(|(_, coverage)| coverage.active_rules.contains(&rule.id))
            .map(|(index, _)| affected_component(policy, index, &[rule.cve.as_str()]))
            .collect();
        blockers.push(json!({
            "rule_id": rule.id, "origin": "static", "cves": [&rule.cve],
            "action": rule.action, "reason": rule.description, "source": rule.source,
            "affected_components": components,
        }));
    }
    for rule in &policy.generated_rules {
        let cves: Vec<_> = rule.cves.iter().map(String::as_str).collect();
        let components: Vec<_> = policy
            .components
            .iter()
            .enumerate()
            .filter(|(_, coverage)| {
                coverage.component.package.as_ref() == Some(&rule.package)
                    && rule
                        .version
                        .as_ref()
                        .is_none_or(|version| coverage.component.version.as_ref() == Some(version))
            })
            .map(|(index, _)| affected_component(policy, index, &cves))
            .collect();
        blockers.push(json!({
            "rule_id": rule.id, "origin": rule.origin, "cves": rule.cves,
            "action": rule.action, "reason": rule.description, "source": rule.source,
            "affected_components": components,
        }));
    }
    let cves: BTreeSet<_> = policy
        .active_rules
        .iter()
        .map(|r| &r.cve)
        .chain(policy.generated_rules.iter().flat_map(|r| &r.cves))
        .collect();
    let quarantined = policy
        .active_rules
        .iter()
        .map(|r| &r.action)
        .chain(policy.generated_rules.iter().map(|r| &r.action))
        .any(|action| matches!(action, Action::DenyAll));
    json!({
        "version": 1,
        "quarantined": quarantined,
        "scope": "whole_upstream",
        "summary": {"blocking_rules": blockers.len(), "blocking_cves": cves.len(), "inventory_gaps": policy.inventory_gaps.len()},
        "blockers": blockers,
        "inventory_gaps": policy.inventory_gaps,
        "ai_review": {"status": policy.ai.status, "cache": policy.ai.cache},
        "warning": "Read-only installed-policy report; no AI, advisory, leaderboard or refresh calls. Fixed versions are cached AI suggestions, not independently verified upgrade guarantees. Source/image attribution is supplied by the SBOM, not inferred. Inventory gaps do not block traffic. No active rules does not establish vulnerability-free software.",
    })
}

fn affected_component(policy: &Report, index: usize, cves: &[&str]) -> Value {
    let component = &policy.components[index].component;
    let recommendations: Vec<_> = policy.ai.discoveries.iter()
        .filter(|finding| finding.component_index == index && cves.contains(&finding.cve.as_str()))
        .map(|finding| json!({
            "cve": finding.cve,
            "suggested_fixed_version": if finding.fixed_version.is_empty() { None } else { Some(&finding.fixed_version) },
            "source": finding.source,
        })).collect();
    json!({
        "component_index": index, "name": component.name, "package": component.package,
        "installed_version": component.version, "sources": component.sources,
        "recommendations": recommendations,
    })
}
