use crate::policy::Report;
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(crate) fn inventory(policy: &Report) -> Value {
    let components_with_gaps: BTreeSet<_> = policy
        .inventory_gaps
        .iter()
        .map(|gap| gap.component_index)
        .collect();
    let gaps: Vec<_> = policy.inventory_gaps.iter().map(|gap| {
        let mut detail = component_details(policy, gap.component_index);
        let suggested_action = match (gap.reason, policy.components[gap.component_index].component.kind.as_deref()) {
            (_, Some("operating-system")) => "Verify the distro/release from the final image's /etc/os-release and Dockerfile final stage. Preserve OS package PURLs and image provenance; do not fabricate an OS PURL.",
            ("missing_purl", _) => "Recover the package identity from the deployed artifact, lockfile or scanner evidence and record its verified PURL.",
            _ => "Recover the exact installed version from the deployed binary's build metadata, verified source release/commit or package database. Preserve the evidence; do not guess or copy an unrelated product version.",
        };
        detail["reason"] = json!(gap.reason);
        detail["suggested_action"] = json!(suggested_action);
        detail
    }).collect();
    json!({
        "components": policy.components.len(),
        "identity_complete": gaps.is_empty(),
        "gap_count": gaps.len(),
        "components_with_gaps": components_with_gaps.len(),
        "gaps": gaps,
    })
}

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
    let uncovered = uncovered(policy);
    json!({
        "version": 1,
        "quarantined": false,
        "scope": "matching_requests",
        "summary": {"blocking_rules": blockers.len(), "blocking_cves": cves.len(), "uncovered_findings":uncovered.len(),"inventory_gaps": policy.inventory_gaps.len()},
        "blockers": blockers,
        "uncovered_vulnerabilities": uncovered,
        "transport": {"listener":["HTTP/1.0","HTTP/1.1"],"upstream":"HTTP/1.1","http3":"Not accepted or inspected; mitigate HTTP/3-specific issues at the QUIC/ingress endpoint."},
        "inventory_gaps": inventory(policy)["gaps"],
        "ai_review": {"status": policy.ai.status, "cache": policy.ai.cache},
        "warning": "Read-only installed-policy report; no AI, advisory, leaderboard or refresh calls. Fixed versions are cached AI suggestions, not independently verified upgrade guarantees. Source/image attribution is supplied by the SBOM, not inferred. Inventory gaps do not block traffic. No active rules does not establish vulnerability-free software.",
    })
}

fn uncovered(policy: &Report) -> Vec<Value> {
    let mut uncovered = Vec::new();
    for rule in &policy.advisory_rules {
        let components: Vec<_> = policy
            .components
            .iter()
            .enumerate()
            .filter(|(_, item)| item.advisory_rules.contains(&rule.id))
            .map(|(index, _)| affected_component(policy, index, &[&rule.cve]))
            .collect();
        uncovered.push(json!({"cve":rule.cve,"origin":"static","reason":rule.description,"source":rule.source,"coverage_note":"Catalogue restriction is broader than targeted filtering; no narrow rule is installed.","affected_components":components}));
    }
    for finding in &policy.ai.discoveries {
        let covered = policy.generated_rules.iter().any(|rule| {
            rule.cves.contains(&finding.cve)
                && policy
                    .components
                    .get(finding.component_index)
                    .is_some_and(|item| {
                        item.component.package.as_ref() == Some(&rule.package)
                            && rule.version.as_ref().is_none_or(|version| {
                                item.component.version.as_ref() == Some(version)
                            })
                    })
        });
        if !covered {
            uncovered.push(json!({"cve":finding.cve,"origin":"ai_discovery","reason":finding.reason,"source":finding.source,
                "coverage_note":if finding.coverage_note.is_empty(){"No evidenced narrow restriction was provided; SRE action required."}else{&finding.coverage_note},
                "affected_components":[affected_component(policy,finding.component_index,&[&finding.cve])],"emergency_recommended":finding.emergency_recommended(),"emergency":finding.emergency}));
        }
    }
    uncovered
}

pub(crate) fn with_traffic(policy: &Report, traffic: Value) -> Value {
    let mut report = report(policy);
    let blocked = traffic["effective"] == "blocked";
    report["quarantined"] = json!(blocked);
    if blocked {
        report["scope"] = json!("whole_upstream");
    }
    report["traffic"] = traffic;
    report
}

fn affected_component(policy: &Report, index: usize, cves: &[&str]) -> Value {
    let recommendations: Vec<_> = policy.ai.discoveries.iter()
        .filter(|finding| finding.component_index == index && cves.contains(&finding.cve.as_str()))
        .map(|finding| json!({
            "cve": finding.cve,
            "suggested_fixed_version": if finding.fixed_version.is_empty() { None } else { Some(&finding.fixed_version) },
            "source": finding.source,
        })).collect();
    let mut component = component_details(policy, index);
    component["recommendations"] = json!(recommendations);
    component
}

pub(crate) fn component_details(policy: &Report, index: usize) -> Value {
    let component = &policy.components[index].component;
    json!({
        "component_index": index, "name": component.name, "package": component.package,
        "component_type": component.kind,
        "installed_version": component.version, "sources": component.sources,
    })
}
