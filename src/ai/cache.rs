use super::{
    AiConfig, INSTRUCTIONS, LEGACY_INSTRUCTIONS, Proposal, RESEARCH_GUIDANCE, Reply, ReviewTrigger,
    ReviewedBatch, batches, legacy_output_schema, models::Target, output_schema, research,
};
use crate::policy::Report;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Default, Serialize)]
pub struct Stats {
    pub hits: usize,
    pub misses: usize,
    pub deduplicated_components: usize,
    pub oldest_checked_at: Option<u64>,
    pub next_refresh_at: Option<u64>,
    pub models: BTreeSet<String>,
    pub error: Option<String>,
}

#[derive(Default, Deserialize, Serialize)]
struct Data {
    scope: Value,
    entries: BTreeMap<String, Entry>,
}

#[derive(Deserialize, Serialize)]
struct Entry {
    checked_at: u64,
    target: Target,
    reply: Reply,
    sources: BTreeSet<String>,
}

pub(super) struct Store {
    data: Data,
    ttl: u64,
    keys: BTreeMap<usize, String>,
    aliases: BTreeMap<usize, Vec<usize>>,
    pub missing: BTreeSet<usize>,
    read_only: bool,
}

pub(super) fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub(super) async fn clear(path: &Path) -> Result<()> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => anyhow::bail!("cannot clear AI review cache"),
    })
    .await?
}

fn scope(config: &AiConfig) -> Value {
    let mut current = pre_cve_now_scope(config);
    current["version"] = json!(3);
    current["research_guidance"] = json!(RESEARCH_GUIDANCE);
    current
}

fn pre_cve_now_scope(config: &AiConfig) -> Value {
    json!({"version":2,"instructions":INSTRUCTIONS,"schema":output_schema(),
        "provider":config.provider,"model":config.model,"reasoning":config.reasoning,
        "openai_url":config.url.as_str(),"anthropic_url":config.anthropic_url.as_str()})
}

fn legacy_scope(config: &AiConfig) -> Value {
    let mut previous = pre_cve_now_scope(config);
    previous["version"] = json!(1);
    previous["instructions"] = json!(LEGACY_INSTRUCTIONS);
    previous["schema"] = legacy_output_schema();
    previous
}

fn component_key(report: &Report, index: usize) -> Result<String> {
    let item = &report.components[index];
    let rules: Vec<_> = report
        .active_rules
        .iter()
        .filter(|rule| item.active_rules.contains(&rule.id))
        .collect();
    Ok(serde_json::to_string(
        &json!({"package":item.component.package,"version":item.component.version,
        "name":item.component.package.is_none().then_some(&item.component.name),"rules":rules}),
    )?)
}

fn component_reply(reply: &Reply, index: usize, destination: usize) -> Reply {
    let enhancements: Vec<Proposal> = reply
        .enhancements
        .iter()
        .filter(|p| p.component_index == index)
        .cloned()
        .map(|mut p| {
            p.component_index = destination;
            p
        })
        .collect();
    let discoveries: Vec<_> = reply
        .discoveries
        .iter()
        .filter(|d| d.component_index == index)
        .cloned()
        .map(|mut d| {
            d.component_index = destination;
            d
        })
        .collect();
    Reply {
        summary: "Reused a completed component review; see cache timestamps for its age.".into(),
        sources: discoveries
            .iter()
            .flat_map(|d| {
                std::iter::once(d.source.clone())
                    .chain(d.emergency.as_ref().map(|e| e.source.clone()))
            })
            .collect(),
        enhancements,
        discoveries,
        usage: research::Usage::default(),
    }
}

impl Store {
    pub async fn load(path: &Path, config: &AiConfig, trigger: ReviewTrigger) -> Result<Self> {
        let path = path.to_owned();
        if matches!(trigger, ReviewTrigger::Refresh) {
            clear(path.as_path()).await?;
        }
        let enabled = config.cache_ttl_secs > 0;
        let expected = scope(config);
        let mut data = tokio::task::spawn_blocking(move || -> Result<Data> {
            if !enabled {
                return Ok(Data::default());
            }
            match crate::read_bounded(&path) {
                Ok(bytes) => serde_json::from_slice(&bytes)
                    .context("invalid AI review cache; use POST /v1/refresh to rebuild it"),
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
                {
                    Ok(Data::default())
                }
                Err(_) => {
                    anyhow::bail!("cannot read AI review cache; use POST /v1/refresh to rebuild it")
                }
            }
        })
        .await??;
        ensure!(
            data.entries.len() <= 50_000,
            "AI cache exceeds 50,000 entries"
        );
        // Old findings retain their age, but old broad enhancements never become new restrictions.
        if data.scope == legacy_scope(config) {
            for entry in data.entries.values_mut() {
                entry.reply.enhancements.clear();
                for finding in &mut entry.reply.discoveries {
                    finding.restriction = None;
                    finding.emergency = None;
                    finding.coverage_note = "Legacy cached finding: advisory only; no narrow mitigation was reviewed. Re-evaluate at normal expiry or request an explicit refresh.".into();
                }
            }
            data.scope = expected.clone();
        } else if data.scope == pre_cve_now_scope(config) {
            // This additive source change keeps v2's enforcement contract and original review age.
            // Reassess this migration before future research-guidance or validation changes.
            data.scope = expected.clone();
        }
        let data = if data.scope == expected {
            data
        } else {
            Data {
                scope: expected,
                entries: BTreeMap::new(),
            }
        };
        Ok(Self {
            data,
            ttl: config.cache_ttl_secs,
            keys: BTreeMap::new(),
            aliases: BTreeMap::new(),
            missing: BTreeSet::new(),
            read_only: matches!(trigger, ReviewTrigger::Preview { cache_only: true }),
        })
    }

    pub fn reuse(&mut self, report: &Report, stats: &mut Stats) -> Result<Vec<ReviewedBatch>> {
        let now = now()?;
        let mut replies = Vec::new();
        let mut representatives = BTreeMap::new();
        for index in 0..report.components.len() {
            let key = component_key(report, index)?;
            self.keys.insert(index, key.clone());
            if let Some(entry) = self.data.entries.get(&key).filter(|entry| {
                self.ttl > 0
                    && now
                        .checked_sub(entry.checked_at)
                        .is_some_and(|age| age < self.ttl)
            }) {
                let mut reply = component_reply(&entry.reply, 0, index);
                ensure!(
                    reply
                        .discoveries
                        .iter()
                        .all(|d| entry.sources.contains(&d.source)
                            && d.emergency
                                .as_ref()
                                .is_none_or(|e| entry.sources.contains(&e.source))),
                    "cached discovery lacks source evidence; use POST /v1/refresh"
                );
                reply.sources = entry.sources.clone();
                replies.push(ReviewedBatch {
                    batch: batches::cached(report, index),
                    reply,
                    target: entry.target.clone(),
                });
                stats.hits += 1;

                stats.oldest_checked_at = Some(
                    stats
                        .oldest_checked_at
                        .map_or(entry.checked_at, |old| old.min(entry.checked_at)),
                );
                let expires = entry.checked_at.saturating_add(self.ttl);
                stats.next_refresh_at = Some(
                    stats
                        .next_refresh_at
                        .map_or(expires, |old| old.min(expires)),
                );
            } else if let Some(&first) = representatives.get(&key) {
                self.aliases.entry(first).or_default().push(index);
                stats.deduplicated_components += 1;
            } else {
                representatives.insert(key, index);
                self.missing.insert(index);
            }
        }
        stats.misses = self.missing.len();
        Ok(replies)
    }

    pub fn expand_aliases(&self, report: &Report, replies: &mut Vec<ReviewedBatch>) {
        let mut aliases = Vec::new();
        for (first, indexes) in &self.aliases {
            if let Some(completed) = replies.iter().find(|r| r.batch.includes_component(*first)) {
                for &index in indexes {
                    aliases.push(ReviewedBatch {
                        batch: batches::cached(report, index),
                        reply: component_reply(&completed.reply, *first, index),
                        target: completed.target.clone(),
                    });
                }
            }
        }
        replies.extend(aliases);
    }

    pub async fn finish(
        &mut self,
        path: &Path,
        replies: &[ReviewedBatch],
        review: &mut super::Review,
    ) {
        for completed in replies {
            let prefix = match completed.target.provider {
                super::Provider::Openai => "openai",
                super::Provider::Anthropic => "anthropic",
            };
            review
                .cache
                .models
                .insert(format!("{prefix}/{}", completed.target.model));
        }
        if self.ttl == 0 || self.read_only || !matches!(review.status, super::Status::Complete) {
            return;
        }
        if !self.missing.is_empty()
            && let Ok(at) = now()
        {
            review.cache.oldest_checked_at =
                Some(review.cache.oldest_checked_at.map_or(at, |old| old.min(at)));
            let expires = at.saturating_add(self.ttl);
            review.cache.next_refresh_at = Some(
                review
                    .cache
                    .next_refresh_at
                    .map_or(expires, |old| old.min(expires)),
            );
        }
        if matches!(review.status, super::Status::Complete)
            && let Err(error) = self.save(path, replies).await
        {
            review.cache.error = Some(error.to_string());
        }
    }

    async fn save(&mut self, path: &Path, replies: &[ReviewedBatch]) -> Result<Option<u64>> {
        if self.ttl == 0 || self.missing.is_empty() {
            return Ok(None);
        }
        let checked_at = now()?;
        for &index in &self.missing {
            let completed = replies
                .iter()
                .find(|r| r.batch.includes_component(index))
                .context("AI cache component review missing")?;
            let reply = component_reply(&completed.reply, index, 0);
            self.data.entries.insert(
                self.keys
                    .get(&index)
                    .context("AI cache component key missing")?
                    .clone(),
                Entry {
                    checked_at,
                    target: completed.target.clone(),
                    sources: reply.sources.clone(),
                    reply,
                },
            );
        }
        self.data.entries.retain(|_, e| {
            checked_at
                .checked_sub(e.checked_at)
                .is_some_and(|age| age < self.ttl)
        });
        if self.data.entries.len() > 50_000 {
            let current: BTreeSet<_> = self.keys.values().collect();
            let mut old: Vec<_> = self
                .data
                .entries
                .iter()
                .filter(|(key, _)| !current.contains(key))
                .map(|(key, e)| (e.checked_at, key.clone()))
                .collect();
            old.sort();
            for (_, key) in old.into_iter().take(self.data.entries.len() - 50_000) {
                self.data.entries.remove(&key);
            }
        }
        let bytes = serde_json::to_vec(&self.data)?;
        ensure!(
            bytes.len() <= crate::sbom::MAX_SBOM_BYTES,
            "AI review cache exceeds 64 MiB; new results were not cached"
        );
        let path: PathBuf = path.to_owned();
        tokio::task::spawn_blocking(move || crate::persist(&path, &bytes)).await??;
        Ok(Some(checked_at.saturating_add(self.ttl)))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Review, Status};
    use super::*;

    #[tokio::test]
    async fn legacy_reviews_retain_age_and_findings_but_never_broad_actions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.json");
        let config = AiConfig::default();
        let policy = policy("2.14.1");
        let checked = now().unwrap();
        let key = component_key(&policy.report, 0).unwrap();
        let document = json!({"scope":legacy_scope(&config),"entries":{key:{"checked_at":checked,
            "target":{"provider":"openai","model":"old-model","reasoning":"default","rank":null},
            "sources":["https://vendor.example/advisory"],
            "reply":{"summary":"old finding","enhancements":[{"component_index":0,"basis":"log4shell-lookups","action":"deny_all","patterns":[],"reason":"legacy quarantine"}],
                "discoveries":[{"component_index":0,"cve":"CVE-2026-12345","source":"https://vendor.example/advisory","reason":"old evidence","fixed_version":"2.26.0"}]}}}});
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        let before = std::fs::read(&path).unwrap();
        let mut store = Store::load(&path, &config, ReviewTrigger::Preview { cache_only: true })
            .await
            .unwrap();
        let mut stats = Stats::default();
        let replies = store.reuse(&policy.report, &mut stats).unwrap();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.oldest_checked_at, Some(checked));
        assert!(replies[0].reply.enhancements.is_empty());
        assert!(replies[0].reply.discoveries[0].restriction.is_none());
        assert!(replies[0].reply.discoveries[0].emergency.is_none());
        assert!(
            replies[0].reply.discoveries[0]
                .coverage_note
                .contains("Legacy")
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    fn policy(version: &str) -> crate::policy::Policy {
        let document = json!({"format":"filtr-1","packages":[{"purl":format!("pkg:maven/org.apache.logging.log4j/log4j-core@{version}")}]});
        crate::policy::Policy::compile(
            crate::sbom::parse(document.to_string().as_bytes()).unwrap(),
            &crate::policy::Catalog::bundled().unwrap(),
        )
        .unwrap()
    }

    fn pre_source_cache(config: &AiConfig, checked: u64) -> Value {
        let key = component_key(&policy("2.14.1").report, 0).unwrap();
        json!({"scope":pre_cve_now_scope(config),"entries":{key:{"checked_at":checked,
            "target":{"provider":"openai","model":"existing-model","reasoning":"default","rank":2},
            "sources":["https://vendor.example/advisory"],
            "reply":{"summary":"Existing completed review.",
                "enhancements":[{"component_index":0,"basis":"log4shell-lookups","action":"tokens",
                    "patterns":["existing-marker"],"reason":"Existing evidence."}],
                "discoveries":[{"component_index":0,"cve":"CVE-2026-12345",
                    "source":"https://vendor.example/advisory","reason":"Existing affected-version evidence.",
                    "fixed_version":"2.26.0","coverage_note":"Existing protection limits.",
                    "restriction":{"methods":["POST"],"path_prefix":"/affected",
                        "headers":[{"name":"x-test-vector","kind":"exact","value":"enabled"}],
                        "body_patterns":["existing-signature"]},
                    "emergency":{"critical":true,"remotely_exploitable":true,
                        "authentication_required":false,"actively_exploited":true,"affects_http1_upstream":true,
                        "source":"https://vendor.example/advisory","reason":"Existing emergency assessment."}}]}}}})
    }

    #[tokio::test]
    async fn v2_source_migration_preserves_entries_age_and_read_only_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.json");
        let config = AiConfig::default();
        let policy = policy("2.14.1");
        let checked = now().unwrap() - 120;
        let document = pre_source_cache(&config, checked);
        assert_eq!(document["scope"]["version"], 2);
        assert!(document["scope"].get("research_guidance").is_none());
        let original: Data = serde_json::from_value(document.clone()).unwrap();
        let before = serde_json::to_vec_pretty(&document).unwrap();
        std::fs::write(&path, &before).unwrap();
        let mut store = Store::load(&path, &config, ReviewTrigger::Preview { cache_only: true })
            .await
            .unwrap();
        assert_eq!(store.data.scope, scope(&config));
        assert_eq!(
            serde_json::to_value(&store.data.entries).unwrap(),
            serde_json::to_value(&original.entries).unwrap()
        );
        let mut stats = Stats::default();
        let replies = store.reuse(&policy.report, &mut stats).unwrap();
        assert_eq!((stats.hits, stats.misses), (1, 0));
        assert_eq!(stats.oldest_checked_at, Some(checked));
        assert_eq!(stats.next_refresh_at, Some(checked + config.cache_ttl_secs));
        let original = original.entries.values().next().unwrap();
        assert_eq!(
            serde_json::to_value(&replies[0].reply.enhancements).unwrap(),
            serde_json::to_value(&original.reply.enhancements).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&replies[0].reply.discoveries).unwrap(),
            serde_json::to_value(&original.reply.discoveries).unwrap()
        );
        let mut review = Review {
            status: Status::Complete,
            cache: stats,
            ..Default::default()
        };
        store.finish(&path, &replies, &mut review).await;
        assert_eq!(review.cache.oldest_checked_at, Some(checked));
        assert_eq!(
            review.cache.next_refresh_at,
            Some(checked + config.cache_ttl_secs)
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn v2_source_migration_does_not_revalidate_expired_or_future_reviews() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.json");
        let config = AiConfig::default();
        let policy = policy("2.14.1");
        let current = now().unwrap();
        for checked in [current - config.cache_ttl_secs, current + 3600] {
            let before = serde_json::to_vec(&pre_source_cache(&config, checked)).unwrap();
            std::fs::write(&path, &before).unwrap();
            let mut store =
                Store::load(&path, &config, ReviewTrigger::Preview { cache_only: true })
                    .await
                    .unwrap();
            let mut stats = Stats::default();
            assert!(store.reuse(&policy.report, &mut stats).unwrap().is_empty());
            assert_eq!((stats.hits, stats.misses), (0, 1));
            assert!(stats.oldest_checked_at.is_none());
            assert!(stats.next_refresh_at.is_none());
            assert_eq!(
                store.data.entries.values().next().unwrap().checked_at,
                checked
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
    }

    #[tokio::test]
    async fn source_migration_requires_exact_old_and_current_scopes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.json");
        let config = AiConfig::default();
        let policy = policy("2.14.1");
        let changes = [
            (
                "instructions",
                json!(format!("{INSTRUCTIONS} Changed policy.")),
            ),
            ("schema", json!({"changed":true})),
            ("provider", json!("anthropic")),
            ("model", json!("another-model")),
            ("reasoning", json!("high")),
            ("openai_url", json!("https://another-openai.example/")),
            ("anthropic_url", json!("https://another-anthropic.example/")),
            ("version", json!(4)),
            (
                "research_guidance",
                json!(format!("{RESEARCH_GUIDANCE} Changed research.")),
            ),
        ];
        for base in [pre_cve_now_scope(&config), scope(&config)] {
            for (field, value) in &changes {
                let mut document = pre_source_cache(&config, now().unwrap());
                document["scope"] = base.clone();
                document["scope"][field] = value.clone();
                let before = serde_json::to_vec(&document).unwrap();
                std::fs::write(&path, &before).unwrap();
                let mut store =
                    Store::load(&path, &config, ReviewTrigger::Preview { cache_only: true })
                        .await
                        .unwrap();
                let mut stats = Stats::default();
                assert!(
                    store.reuse(&policy.report, &mut stats).unwrap().is_empty(),
                    "{field}"
                );
                assert_eq!((stats.hits, stats.misses), (0, 1), "{field}");
                assert_eq!(std::fs::read(&path).unwrap(), before, "{field}");
            }
        }
    }

    #[tokio::test]
    async fn identical_components_share_one_review_and_remap_all_aliases() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.json");
        let config = AiConfig::default();
        let mut policy = policy("2.14.1");
        policy
            .report
            .components
            .push(policy.report.components[0].clone());
        let mut store = Store::load(&path, &config, ReviewTrigger::Startup)
            .await
            .unwrap();
        let mut stats = Stats::default();
        store.reuse(&policy.report, &mut stats).unwrap();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.deduplicated_components, 1);
        let reply = serde_json::from_value(
            json!({"summary":"Reviewed.","enhancements":[],"discoveries":[]}),
        )
        .unwrap();
        let mut replies = vec![ReviewedBatch {
            batch: batches::cached(&policy.report, 0),
            reply,
            target: Target::backup(),
        }];
        store.expand_aliases(&policy.report, &mut replies);
        assert_eq!(replies.len(), 2);
        assert!(replies[1].batch.includes_component(1));
        store
            .finish(
                &path,
                &replies,
                &mut Review {
                    status: Status::Complete,
                    ..Default::default()
                },
            )
            .await;
        assert_eq!(store.data.entries.len(), 1);
        let mut loaded = Store::load(&path, &config, ReviewTrigger::Startup)
            .await
            .unwrap();
        assert_eq!(
            loaded
                .reuse(&policy.report, &mut Stats::default())
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn persistent_entries_expire_and_invalidate_for_changed_versions_rules_and_models() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.json");
        let config = AiConfig::default();
        assert_eq!(config.cache_ttl_secs, 86400);
        let policy = policy("2.14.1");
        let mut store = Store::load(&path, &config, ReviewTrigger::Startup)
            .await
            .unwrap();
        assert!(
            store
                .reuse(&policy.report, &mut Stats::default())
                .unwrap()
                .is_empty()
        );
        let reply = serde_json::from_value(
            json!({"summary":"No additional finding.","enhancements":[],"discoveries":[]}),
        )
        .unwrap();
        let replies = vec![ReviewedBatch {
            batch: batches::cached(&policy.report, 0),
            reply,
            target: Target::backup(),
        }];
        store
            .finish(
                &path,
                &replies,
                &mut Review {
                    status: Status::Complete,
                    ..Default::default()
                },
            )
            .await;
        let mut loaded = Store::load(&path, &config, ReviewTrigger::Startup)
            .await
            .unwrap();
        assert_eq!(
            loaded
                .reuse(&policy.report, &mut Stats::default())
                .unwrap()
                .len(),
            1
        );
        let mut patched = policy.clone();
        patched.report.components[0].component.version = Some("2.14.2".into());
        assert!(
            Store::load(&path, &config, ReviewTrigger::Startup)
                .await
                .unwrap()
                .reuse(&patched.report, &mut Stats::default())
                .unwrap()
                .is_empty()
        );
        let mut changed = policy.clone();
        changed.report.active_rules[0]
            .description
            .push_str(" Changed mitigation.");
        assert!(
            Store::load(&path, &config, ReviewTrigger::Startup)
                .await
                .unwrap()
                .reuse(&changed.report, &mut Stats::default())
                .unwrap()
                .is_empty()
        );
        let other_model = AiConfig {
            model: Some("openai/another-model".into()),
            ..config.clone()
        };
        assert!(
            Store::load(&path, &other_model, ReviewTrigger::Startup)
                .await
                .unwrap()
                .reuse(&policy.report, &mut Stats::default())
                .unwrap()
                .is_empty()
        );
        let entry = loaded.data.entries.values_mut().next().unwrap();
        entry.checked_at = now().unwrap() - 86400;
        std::fs::write(&path, serde_json::to_vec(&loaded.data).unwrap()).unwrap();
        assert!(
            Store::load(&path, &config, ReviewTrigger::Startup)
                .await
                .unwrap()
                .reuse(&policy.report, &mut Stats::default())
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn corrupted_cache_requires_explicit_clear_and_partial_reviews_are_not_cached() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.json");
        std::fs::write(&path, "bad cache").unwrap();
        let config = AiConfig::default();
        assert!(
            Store::load(&path, &config, ReviewTrigger::Startup)
                .await
                .is_err()
        );
        let mut store = Store::load(&path, &config, ReviewTrigger::Refresh)
            .await
            .unwrap();
        assert!(!path.exists());
        let policy = policy("2.14.1");
        store.reuse(&policy.report, &mut Stats::default()).unwrap();
        store
            .finish(
                &path,
                &[],
                &mut Review {
                    status: Status::Partial,
                    ..Default::default()
                },
            )
            .await;
        assert!(!path.exists());
    }
}
