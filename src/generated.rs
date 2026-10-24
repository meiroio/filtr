use crate::policy::{Action, Policy, Report};
use anyhow::Result;
use serde::Serialize;

#[derive(Clone, Serialize)]
pub struct Rule {
    pub id: String,
    pub origin: &'static str,
    pub package: String,
    pub version: Option<String>,
    pub basis: String,
    pub cves: Vec<String>,
    pub action: Action,
    pub description: String,
    pub source: String,
}

/// Generate emergency blocks in the candidate policy after a successful AI review.
pub(crate) fn quarantine(policy: &mut Policy) -> Result<()> {
    let mut candidate = policy.clone();
    candidate
        .report
        .generated_rules
        .retain(|r| !matches!(r.origin, "scan_guard" | "osv_quarantine"));
    let mut rules = Vec::new();
    for (package_index, package) in policy.report.osv.packages.iter().enumerate() {
        for (index, vulnerability) in package.vulnerabilities.iter().enumerate() {
            if !vulnerability.static_rules.is_empty() {
                continue;
            }
            rules.push(Rule {
                id: format!("auto:osv:{package_index}:{index}"),
                origin: "osv_quarantine",
                package: package.package.clone(), version: Some(package.version.clone()),
                basis: vulnerability.id.clone(), cves: vulnerability.cves.clone(),
                action: Action::DenyAll,
                description: "Emergency quarantine: the installed package has an OSV finding without a curated rule. Block this entire upstream until a patched SBOM or curated mitigation is installed.".into(),
                source: vulnerability.url.clone(),
            });
        }
    }
    if policy.report.osv.status != "complete" {
        rules.push(scan_guard());
    }
    candidate.add_generated(rules)?;
    *policy = candidate;
    Ok(())
}

fn scan_guard() -> Rule {
    Rule { id: "auto:scan-guard".into(), origin: "scan_guard", package: "*".into(), version: None, basis: "osv:incomplete".into(), cves: Vec::new(),
        action: Action::DenyAll, description: "Block the entire upstream after a successful AI review when OSV coverage is failed, partial or skipped. This is an uncertainty guard, not a CVE-specific mitigation.".into(), source: "https://osv.dev/".into() }
}

pub(crate) fn refresh_coverage(report: &mut Report) {
    for package in &mut report.osv.packages {
        for vulnerability in &mut package.vulnerabilities {
            let matching: Vec<_> = report
                .generated_rules
                .iter()
                .filter(|rule| {
                    rule.package == package.package
                        && rule.version.as_deref() == Some(&package.version)
                        && (rule.basis == vulnerability.id
                            || vulnerability.aliases.contains(&rule.basis)
                            || rule.cves.iter().any(|cve| vulnerability.cves.contains(cve)))
                })
                .collect();
            vulnerability.generated_rules = matching.iter().map(|rule| rule.id.clone()).collect();
            vulnerability.blocking_rules = vulnerability
                .static_rules
                .iter()
                .chain(&vulnerability.generated_rules)
                .cloned()
                .collect();
            vulnerability.coverage = if matching.iter().any(|rule| rule.origin == "osv_quarantine")
            {
                "quarantined"
            } else if vulnerability.blocking_rules.is_empty() {
                "uncovered"
            } else {
                "blocking_rule_available"
            };
        }
    }
    report.osv.refresh_counts();
}
