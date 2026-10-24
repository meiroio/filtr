use crate::policy::{Coverage, Report};
use anyhow::{Context, Result, ensure};
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod packages;

const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PACKAGE_FINDINGS: usize = 1_000;
const MAX_FINDINGS: usize = 10_000;
const MAX_PAGES: usize = 20;

#[derive(Clone, Serialize)]
pub struct ScanReport {
    pub status: &'static str,
    pub checked_at_unix: Option<u64>,
    pub error: Option<String>,
    pub summary: Option<Summary>,
    pub packages: Vec<PackageFindings>,
    pub skipped_components: Vec<SkippedComponent>,
}

impl Default for ScanReport {
    fn default() -> Self {
        Self {
            status: "pending",
            checked_at_unix: None,
            error: None,
            summary: None,
            packages: Vec::new(),
            skipped_components: Vec::new(),
        }
    }
}

#[derive(Clone, Default, Serialize)]
pub struct Summary {
    pub queried_packages: usize,
    pub failed_packages: usize,
    pub skipped_components: usize,
    pub advisories: usize,
    pub with_blocking_rules: usize,
    pub uncovered: usize,
    pub uncovered_before_generation: usize,
    pub quarantined: usize,
    pub ai_rule_matches: usize,
}

#[derive(Clone, Serialize)]
pub struct SkippedComponent {
    pub name: String,
    pub package: Option<String>,
    pub version: Option<String>,
    pub reason: &'static str,
}

#[derive(Clone, Serialize)]
pub struct PackageFindings {
    pub package: String,
    pub version: String,
    pub components: Vec<String>,
    pub status: &'static str,
    pub error: Option<String>,
    pub vulnerabilities: Vec<Vulnerability>,
    #[serde(skip)]
    query: serde_json::Value,
    #[serde(skip)]
    active_rules: BTreeSet<String>,
}

#[derive(Clone, Serialize)]
pub struct Vulnerability {
    pub id: String,
    pub aliases: Vec<String>,
    pub cves: Vec<String>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub url: String,
    pub coverage: &'static str,
    pub blocking_rules: Vec<String>,
    pub static_rules: Vec<String>,
    pub generated_rules: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryResponse {
    #[serde(default)]
    vulns: Vec<Advisory>,
    next_page_token: Option<String>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct Advisory {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    summary: Option<String>,
    details: Option<String>,
    withdrawn: Option<String>,
}

pub(crate) struct Client {
    http: reqwest::Client,
    endpoint: reqwest::Url,
    timeout: Duration,
}

pub(crate) fn validate_config(endpoint: &reqwest::Url, timeout_secs: u64) -> Result<()> {
    validate_service_config(endpoint, timeout_secs, "OSV")
}

pub(crate) fn validate_service_config(
    endpoint: &reqwest::Url,
    timeout_secs: u64,
    service: &str,
) -> Result<()> {
    let local = endpoint.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    ensure!(
        endpoint.scheme() == "https" || (endpoint.scheme() == "http" && local),
        "{service} endpoint must use HTTPS (HTTP is allowed for loopback testing)"
    );
    ensure!(
        endpoint.host_str().is_some()
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.path() == "/"
            && endpoint.query().is_none()
            && endpoint.fragment().is_none(),
        "{service} endpoint must be an origin without credentials, path, query or fragment"
    );
    ensure!(
        (1..=3600).contains(&timeout_secs),
        "{service} deadline must be between 1 and 3600 seconds"
    );
    Ok(())
}

impl Client {
    pub fn new(endpoint: reqwest::Url, timeout_secs: u64) -> Result<Self> {
        let http = service_client(10)?;
        Ok(Self {
            http,
            endpoint,
            timeout: Duration::from_secs(timeout_secs),
        })
    }

    pub async fn scan(&self, policy: &Report) -> ScanReport {
        let mut report = inventory(&policy.components);
        let rules: BTreeMap<_, _> = policy
            .active_rules
            .iter()
            .map(|r| (r.id.as_str(), r.cve.as_str()))
            .collect();
        let queries: Vec<_> = report
            .packages
            .iter()
            .enumerate()
            .map(|(index, package)| {
                let rules = package
                    .active_rules
                    .iter()
                    .filter_map(|id| {
                        rules
                            .get(id.as_str())
                            .map(|cve| (id.clone(), (*cve).to_owned()))
                    })
                    .collect();
                (index, package.clone(), rules)
            })
            .collect();
        let collect = async {
            let mut jobs = stream::iter(queries)
                .map(|(index, package, rules)| async move {
                    (index, self.query_package(package, &rules).await)
                })
                .buffer_unordered(32);
            let mut findings = 0;
            while let Some((index, mut package)) = jobs.next().await {
                let remaining = MAX_FINDINGS - findings;
                if package.vulnerabilities.len() > remaining {
                    package.vulnerabilities.truncate(remaining);
                    package.status = "partial";
                    package.error = Some("scan finding limit exceeded".into());
                    report.packages[index] = package;
                    report.error = Some("scan finding limit exceeded".into());
                    break;
                }
                findings += package.vulnerabilities.len();
                report.packages[index] = package;
            }
        };
        if tokio::time::timeout(self.timeout, collect).await.is_err() {
            report.error = Some("OSV scan deadline exceeded".into());
        }
        finish(&mut report);
        report
    }

    async fn query_package(
        &self,
        mut package: PackageFindings,
        rules: &BTreeMap<String, String>,
    ) -> PackageFindings {
        let result = self.query_pages(&mut package, rules).await;
        match result {
            Ok(()) => package.status = "complete",
            Err(error) => {
                package.status = if package.vulnerabilities.is_empty() {
                    "failed"
                } else {
                    "partial"
                };
                package.error = Some(format!("{error:#}"));
            }
        }
        package
    }

    async fn query_pages(
        &self,
        package: &mut PackageFindings,
        rules: &BTreeMap<String, String>,
    ) -> Result<()> {
        let mut token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut seen_ids = BTreeSet::new();
        for _ in 0..MAX_PAGES {
            let mut query = package.query.clone();
            if let Some(token) = &token {
                query["page_token"] = json!(token);
            }
            let response = self
                .http
                .post(self.endpoint.join("v1/query")?)
                .header("content-type", "application/json")
                .body(serde_json::to_vec(&query)?)
                .send()
                .await
                .context("OSV request failed")?;
            let page: QueryResponse = read_json(response, MAX_RESPONSE_BYTES, "OSV").await?;
            ensure!(page.error.is_none(), "OSV returned an API error");
            for advisory in page.vulns {
                if advisory.withdrawn.is_some() {
                    continue;
                }
                ensure!(
                    valid_id(&advisory.id)
                        && advisory.aliases.len() <= 128
                        && advisory.aliases.iter().all(|id| valid_id(id)),
                    "OSV returned invalid advisory identifiers"
                );
                if !seen_ids.insert(advisory.id.clone()) {
                    continue;
                }
                ensure!(
                    package.vulnerabilities.len() < MAX_PACKAGE_FINDINGS,
                    "package advisory limit exceeded"
                );
                package.vulnerabilities.push(classify(advisory, rules));
            }
            match page.next_page_token.filter(|token| !token.is_empty()) {
                None => {
                    package.vulnerabilities.sort_by(|a, b| a.id.cmp(&b.id));
                    return Ok(());
                }
                Some(next) => {
                    ensure!(
                        next.len() <= 4096 && seen_tokens.insert(next.clone()),
                        "OSV repeated or oversized pagination token"
                    );
                    token = Some(next);
                }
            }
        }
        anyhow::bail!("OSV pagination limit exceeded")
    }
}

fn inventory(components: &[Coverage]) -> ScanReport {
    let mut packages: BTreeMap<(String, String), PackageFindings> = BTreeMap::new();
    let mut report = ScanReport::default();
    for item in components {
        let component = &item.component;
        let reason = match (component.package.as_deref(), component.version.as_deref()) {
            (None, _) => Some("missing_purl"),
            (_, None) => Some("missing_version"),
            (_, Some(version))
                if version.trim().is_empty()
                    || ["NOASSERTION", "NONE", "UNKNOWN"]
                        .iter()
                        .any(|v| version.trim().eq_ignore_ascii_case(v)) =>
            {
                Some("missing_version")
            }
            (_, Some(version))
                if version.len() > 512 || version.chars().any(char::is_whitespace) =>
            {
                Some("invalid_version")
            }
            _ => None,
        };
        if let Some(reason) = reason {
            report.skipped_components.push(SkippedComponent {
                name: component.name.clone(),
                package: component.package.clone(),
                version: component.version.clone(),
                reason,
            });
            continue;
        }
        let package = component
            .package
            .clone()
            .expect("eligible package has a PURL");
        let version = component
            .version
            .clone()
            .expect("eligible package has a version");
        let query = match packages::query(&package, &version) {
            Ok(query) => query,
            Err(reason) => {
                report.skipped_components.push(SkippedComponent {
                    name: component.name.clone(),
                    package: Some(package),
                    version: Some(version),
                    reason,
                });
                continue;
            }
        };
        let entry = packages
            .entry((package.clone(), version.clone()))
            .or_insert_with(|| PackageFindings {
                package,
                version,
                components: Vec::new(),
                status: "pending",
                error: None,
                vulnerabilities: Vec::new(),
                query,
                active_rules: BTreeSet::new(),
            });
        entry.components.push(component.name.clone());
        entry.active_rules.extend(item.active_rules.iter().cloned());
    }
    report.packages = packages.into_values().collect();
    report
}

fn classify(advisory: Advisory, rules: &BTreeMap<String, String>) -> Vulnerability {
    let ids: BTreeSet<_> = std::iter::once(&advisory.id)
        .chain(&advisory.aliases)
        .collect();
    let blocking_rules: Vec<_> = rules
        .iter()
        .filter(|(_, cve)| ids.contains(cve))
        .map(|(id, _)| id.clone())
        .collect();
    let cves = ids
        .into_iter()
        .filter(|id| id.starts_with("CVE-"))
        .cloned()
        .collect();
    Vulnerability {
        url: format!("https://osv.dev/vulnerability/{}", advisory.id),
        coverage: if blocking_rules.is_empty() {
            "uncovered"
        } else {
            "blocking_rule_available"
        },
        id: advisory.id,
        aliases: advisory.aliases,
        cves,
        summary: advisory.summary.map(|s| s.chars().take(2048).collect()),
        details: advisory.details.map(|s| s.chars().take(8192).collect()),
        static_rules: blocking_rules.clone(),
        blocking_rules,
        generated_rules: Vec::new(),
    }
}

fn finish(report: &mut ScanReport) {
    let mut summary = Summary {
        skipped_components: report.skipped_components.len(),
        ..Summary::default()
    };
    for package in &mut report.packages {
        if package.status == "pending" {
            package.status = "incomplete";
            package.error = report.error.clone();
        }
        if package.status == "complete" {
            summary.queried_packages += 1;
        } else {
            summary.failed_packages += 1;
        }
        summary.advisories += package.vulnerabilities.len();
        summary.with_blocking_rules += package
            .vulnerabilities
            .iter()
            .filter(|v| !v.blocking_rules.is_empty())
            .count();
    }
    summary.uncovered = summary.advisories - summary.with_blocking_rules;
    report.status = if summary.failed_packages == 0 && summary.skipped_components == 0 {
        "complete"
    } else if summary.queried_packages > 0 || summary.advisories > 0 || report.packages.is_empty() {
        "partial"
    } else {
        "failed"
    };
    report.checked_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|time| time.as_secs());
    report.summary = Some(summary);
    report.refresh_counts();
}

pub(crate) fn service_client(timeout_secs: u64) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(timeout_secs))
        .build()?)
}

impl ScanReport {
    pub(crate) fn refresh_counts(&mut self) {
        let Some(summary) = &mut self.summary else {
            return;
        };
        let findings: Vec<_> = self
            .packages
            .iter()
            .flat_map(|p| &p.vulnerabilities)
            .collect();
        summary.with_blocking_rules = findings
            .iter()
            .filter(|v| !v.blocking_rules.is_empty())
            .count();
        summary.uncovered = summary.advisories - summary.with_blocking_rules;
        summary.uncovered_before_generation = findings
            .iter()
            .filter(|v| v.static_rules.is_empty())
            .count();
        summary.quarantined = findings
            .iter()
            .filter(|v| v.coverage == "quarantined")
            .count();
        summary.ai_rule_matches = findings
            .iter()
            .filter(|v| v.generated_rules.iter().any(|id| id.starts_with("ai:")))
            .count();
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 200
        && !matches!(id, "." | "..")
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b":_.-".contains(&c))
}

pub(crate) async fn read_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
    limit: usize,
    service: &str,
) -> Result<T> {
    ensure!(
        response.status().is_success(),
        "{service} returned HTTP {}",
        response.status().as_u16()
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("cannot read service response")?
    {
        ensure!(
            bytes.len() + chunk.len() <= limit,
            "{service} response exceeds {} bytes",
            limit
        );
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).with_context(|| format!("invalid {service} JSON response"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_requires_https_or_loopback() {
        for url in [
            "https://api.osv.dev/",
            "http://127.0.0.1:9999/",
            "http://[::1]:9999/",
        ] {
            assert!(validate_config(&url.parse().unwrap(), 30).is_ok());
        }
        for url in [
            "http://example.com/",
            "https://user:secret@example.com/",
            "https://api.osv.dev/path",
            "https://api.osv.dev/?secret=token",
            "https://api.osv.dev/#fragment",
            "file:///tmp/osv",
        ] {
            assert!(validate_config(&url.parse().unwrap(), 30).is_err(), "{url}");
        }
        assert!(validate_config(&"https://api.osv.dev/".parse().unwrap(), 0).is_err());
    }
}
