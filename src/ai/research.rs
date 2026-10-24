use super::{Provider, Rejected, Review, ReviewedBatch};
use crate::{
    generated,
    policy::{Action, Report},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Serialize)]
pub struct InventoryGap {
    pub component_index: usize,
    pub reason: &'static str,
}

pub(crate) fn inventory_gaps(components: &[crate::policy::Coverage]) -> Vec<InventoryGap> {
    components
        .iter()
        .enumerate()
        .flat_map(|(component_index, item)| {
            let missing_purl = item.component.package.is_none().then_some("missing_purl");
            let missing_version = known_version(item.component.version.as_deref())
                .is_none()
                .then_some("missing_or_unknown_version");
            [missing_purl, missing_version]
                .into_iter()
                .flatten()
                .map(move |reason| InventoryGap {
                    component_index,
                    reason,
                })
        })
        .collect()
}

fn known_version(version: Option<&str>) -> Option<&str> {
    version
        .filter(|v| !v.trim().is_empty() && !v.eq_ignore_ascii_case("unknown") && *v != "(devel)")
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    pub component_index: usize,
    pub cve: String,
    pub source: String,
    pub reason: String,
    pub fixed_version: String,
}

pub(super) fn review_discoveries(
    report: &Report,
    completed: &ReviewedBatch,
    review: &mut Review,
    rules: &mut Vec<generated::Rule>,
) {
    for finding in &completed.reply.discoveries {
        if review.discoveries.iter().any(|known| {
            known.component_index == finding.component_index && known.cve == finding.cve
        }) {
            continue;
        }
        let index = rules.len() + review.rejected.len();
        let result = if !completed.batch.includes_component(finding.component_index) {
            Err(anyhow::anyhow!(
                "discovered component was not supplied in this AI batch"
            ))
        } else if rules.len() >= 512 {
            Err(anyhow::anyhow!("AI review exceeds 512 accepted rules"))
        } else {
            validate(report, finding, &completed.reply.sources, index)
        };
        match result {
            Ok(rule) => {
                rules.push(rule);
                review.discoveries.push(finding.clone());
            }
            Err(error) => review.rejected.push(Rejected {
                index,
                reason: error.to_string(),
            }),
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_input_tokens: u64,
    pub cache_read_input_tokens: u64,
    pub web_search_requests: u64,
}

impl Usage {
    pub fn add(&mut self, other: &Self) {
        self.input_tokens = self.input_tokens.saturating_add(other.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(other.output_tokens);
        self.cache_creation_input_tokens = self
            .cache_creation_input_tokens
            .saturating_add(other.cache_creation_input_tokens);
        self.cache_read_input_tokens = self
            .cache_read_input_tokens
            .saturating_add(other.cache_read_input_tokens);
        self.web_search_requests = self
            .web_search_requests
            .saturating_add(other.web_search_requests);
    }

    pub fn read(response: &Value, provider: Provider) -> Self {
        let mut usage: Self = serde_json::from_value(response["usage"].clone()).unwrap_or_default();
        if provider == Provider::Openai {
            usage.cache_read_input_tokens =
                response["usage"]["input_tokens_details"]["cached_tokens"]
                    .as_u64()
                    .unwrap_or(0);
            usage.web_search_requests = response["output"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|item| item["type"] == "web_search_call")
                .count() as u64;
        } else {
            usage.web_search_requests = response["usage"]["server_tool_use"]["web_search_requests"]
                .as_u64()
                .unwrap_or(0);
        }
        usage
    }
}

pub(super) fn sources(response: &Value, provider: Provider) -> Result<BTreeSet<String>> {
    let mut sources = BTreeSet::new();
    let items = response[if provider == Provider::Openai {
        "output"
    } else {
        "content"
    }]
    .as_array()
    .context("AI response items missing")?;
    for item in items {
        if provider == Provider::Anthropic && item["type"] == "web_search_tool_result" {
            ensure!(item["content"].is_array(), "AI web search failed");
            for result in item["content"].as_array().unwrap() {
                if result["type"] == "web_search_result" {
                    add_source(&mut sources, &result["url"]);
                }
            }
        } else if provider == Provider::Openai && item["type"] == "web_search_call" {
            ensure!(
                item["status"] == "completed",
                "AI web search did not complete"
            );
            for source in item["action"]["sources"].as_array().into_iter().flatten() {
                add_source(&mut sources, &source["url"]);
            }
            add_source(&mut sources, &item["action"]["url"]);
        }
    }
    ensure!(sources.len() <= 1024, "AI search source limit exceeded");
    Ok(sources)
}

fn add_source(sources: &mut BTreeSet<String>, value: &Value) {
    if let Some(url) = value.as_str().filter(|url| safe_source(url)) {
        sources.insert(url.to_owned());
    }
}

fn safe_source(value: &str) -> bool {
    value.len() <= 2048
        && reqwest::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
        })
}

pub(super) fn validate(
    report: &Report,
    finding: &Discovery,
    sources: &BTreeSet<String>,
    index: usize,
) -> Result<generated::Rule> {
    let (year, number) = finding
        .cve
        .strip_prefix("CVE-")
        .and_then(|id| id.split_once('-'))
        .context("invalid discovered CVE")?;
    ensure!(
        year.len() == 4
            && (4..=12).contains(&number.len())
            && year
                .bytes()
                .chain(number.bytes())
                .all(|b| b.is_ascii_digit()),
        "invalid discovered CVE"
    );
    ensure!(
        sources.contains(&finding.source),
        "discovery source was not returned by provider web search"
    );
    ensure!(
        !finding.reason.trim().is_empty()
            && finding.reason.len() <= 2048
            && finding.fixed_version.len() <= 256,
        "invalid discovery explanation or fixed version"
    );
    let component = &report
        .components
        .get(finding.component_index)
        .context("unknown discovered component")?
        .component;
    let package = component
        .package
        .as_ref()
        .context("discovered component has no PURL")?;
    let version = known_version(component.version.as_deref())
        .context("discovered component has no installed version")?;
    Ok(generated::Rule {
        id: format!("ai:discovery:{index}"),
        origin: "ai_discovery",
        package: package.clone(),
        version: Some(version.to_owned()),
        basis: finding.cve.clone(),
        cves: vec![finding.cve.clone()],
        action: Action::DenyAll,
        description: finding.reason.clone(),
        source: finding.source.clone(),
    })
}
