use super::{AiConfig, Provider, ReviewTrigger};
use crate::policy::Report;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{path::Path, time::Duration};

pub(super) const LEADERBOARD_URL: &str =
    "https://vercel.com/ai-gateway/leaderboards/deepsecbench/results.json";
pub(super) const BACKUP_MODEL: &str = "gpt-5.6-luna";

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Target {
    pub provider: Provider,
    pub model: String,
    pub reasoning: String,
    pub rank: Option<u32>,
}

impl Target {
    pub fn backup() -> Self {
        Self {
            provider: Provider::Openai,
            model: BACKUP_MODEL.into(),
            reasoning: "xhigh".into(),
            rank: None,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct Leaderboard {
    results: Vec<Entry>,
}

#[derive(Deserialize, Serialize)]
struct Entry {
    rank: u32,
    #[serde(rename = "modelId")]
    model_id: String,
    reasoning: String,
}

#[derive(Deserialize, Serialize)]
struct Snapshot {
    inventory: Value,
    leaderboard: Leaderboard,
}

pub(super) fn override_target(config: &AiConfig) -> Result<Option<Target>> {
    let Some(value) = &config.model else {
        return Ok(None);
    };
    let (provider, model) = match value.split_once('/') {
        Some(("openai", model)) => (Provider::Openai, model),
        Some(("anthropic", model)) => (Provider::Anthropic, model),
        Some(_) => anyhow::bail!("AI model prefix must be openai/ or anthropic/"),
        None => {
            let provider = config
                .provider
                .or_else(
                    || match (config.api_key.is_some(), config.anthropic_api_key.is_some()) {
                        (true, false) => Some(Provider::Openai),
                        (false, true) => Some(Provider::Anthropic),
                        _ => None,
                    },
                )
                .context(
                    "a bare AI model requires FILTR_AI_PROVIDER when the provider is ambiguous",
                )?;
            (provider, value.as_str())
        }
    };
    ensure!(
        config.provider.is_none_or(|chosen| chosen == provider),
        "AI model prefix conflicts with configured provider"
    );
    ensure!(
        config.key(provider).is_some(),
        "the overridden model's provider has no API key"
    );
    ensure!(
        !model.is_empty()
            && model.len() <= 200
            && model
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "invalid AI model ID"
    );
    Ok(Some(Target {
        provider,
        model: model.to_owned(),
        reasoning: config.reasoning.clone().unwrap_or_else(|| "default".into()),
        rank: None,
    }))
}

pub(super) async fn select(
    http: &reqwest::Client,
    config: &AiConfig,
    report: &Report,
    path: &Path,
    trigger: ReviewTrigger,
) -> Result<Target> {
    if let Some(target) = override_target(config)? {
        return Ok(target);
    }
    let inventory = serde_json::to_value(&report.components)?;
    if matches!(trigger, ReviewTrigger::SbomUpdate) {
        return refresh(http, config, inventory, path).await;
    }
    let path = path.to_owned();
    let snapshot: Snapshot = tokio::task::spawn_blocking(move || {
        let bytes = crate::read_bounded(&path)?;
        ensure!(
            bytes.len() <= crate::sbom::MAX_SBOM_BYTES,
            "saved leaderboard exceeds 64 MiB"
        );
        serde_json::from_slice(&bytes).context("invalid saved leaderboard JSON")
    })
    .await?
    .context("saved leaderboard unavailable; upload an SBOM to refresh it")?;
    ensure!(
        matches!(trigger, ReviewTrigger::Preview { .. }) || snapshot.inventory == inventory,
        "saved leaderboard belongs to a different inventory or static catalogue; upload an SBOM to refresh it"
    );
    choose(&snapshot.leaderboard, config)
}

async fn refresh(
    http: &reqwest::Client,
    config: &AiConfig,
    inventory: Value,
    path: &Path,
) -> Result<Target> {
    let response = http
        .get(config.leaderboard_url.clone())
        .timeout(Duration::from_secs(config.ai_timeout_secs.min(5)))
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("leaderboard request failed or timed out"))?;
    let board: Leaderboard = crate::network::read_json(response, 256 * 1024, "Leaderboard").await?;
    let target = choose(&board, config)?;
    let snapshot = serde_json::to_vec(&Snapshot {
        inventory,
        leaderboard: board,
    })?;
    ensure!(
        snapshot.len() <= crate::sbom::MAX_SBOM_BYTES,
        "leaderboard snapshot exceeds 64 MiB"
    );
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || crate::persist(&path, &snapshot)).await??;
    Ok(target)
}

fn choose(board: &Leaderboard, config: &AiConfig) -> Result<Target> {
    ensure!(
        board.results.len() <= 1000,
        "leaderboard exceeds 1000 entries"
    );
    let (entry, provider, model) = board
        .results
        .iter()
        .filter_map(|entry| {
            let (prefix, model) = entry.model_id.split_once('/')?;
            let provider = match prefix {
                "openai" => Provider::Openai,
                "anthropic" => Provider::Anthropic,
                _ => return None,
            };
            (config.key(provider).is_some()
                && config.provider.is_none_or(|chosen| chosen == provider))
            .then_some((entry, provider, model))
        })
        .min_by_key(|(entry, _, _)| entry.rank)
        .context("leaderboard has no model for the configured primary provider")?;
    ensure!(entry.rank > 0, "invalid leaderboard rank");
    ensure!(
        !model.is_empty()
            && model.len() <= 200
            && model
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "invalid leaderboard model ID"
    );
    ensure!(
        matches!(
            entry.reasoning.as_str(),
            "none" | "low" | "medium" | "high" | "xhigh" | "max"
        ) && !(provider == Provider::Anthropic && entry.reasoning == "none"),
        "unsupported leaderboard reasoning level"
    );
    Ok(Target {
        provider,
        // The gateway uses dots in Claude versions; the direct Anthropic API uses hyphens.
        model: if provider == Provider::Anthropic {
            model.replace('.', "-")
        } else {
            model.into()
        },
        reasoning: config
            .reasoning
            .clone()
            .unwrap_or_else(|| entry.reasoning.clone()),
        rank: Some(entry.rank),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn board(entries: serde_json::Value) -> Leaderboard {
        serde_json::from_value(serde_json::json!({"results": entries})).unwrap()
    }

    #[test]
    fn overrides_require_unambiguous_valid_provider_models() {
        let mut config = AiConfig {
            api_key: Some("test-openai".into()),
            anthropic_api_key: Some("test-anthropic".into()),
            model: Some("budget-model".into()),
            ..Default::default()
        };
        assert!(override_target(&config).is_err());
        config.provider = Some(Provider::Anthropic);
        assert_eq!(
            override_target(&config).unwrap().unwrap().reasoning,
            "default"
        );
        config.model = Some("openai/budget-model".into());
        assert!(override_target(&config).is_err());
        config.provider = None;
        assert_eq!(
            override_target(&config).unwrap().unwrap().provider,
            Provider::Openai
        );
        for value in [
            "openai/",
            "other/model",
            "openai/unsafe model",
            "openai/model/path",
        ] {
            config.model = Some(value.into());
            assert!(override_target(&config).is_err());
        }
        config.model = Some("anthropic/budget-model".into());
        config.anthropic_api_key = None;
        assert!(override_target(&config).is_err());
    }

    #[test]
    fn chooses_lowest_rank_among_configured_providers_not_array_order() {
        let mut config = AiConfig {
            api_key: Some("openai".into()),
            anthropic_api_key: Some("anthropic".into()),
            ..Default::default()
        };
        let entries = serde_json::json!([
            {"rank":8,"modelId":"openai/gpt-5.6-luna","reasoning":"xhigh"},
            {"rank":4,"modelId":"anthropic/claude-opus-5.5","reasoning":"max"},
            {"rank":1,"modelId":"openai/gpt-6-sol","reasoning":"xhigh"},
            {"rank":2,"modelId":"openai/gpt-6-sol","reasoning":"medium"}
        ]);
        let selected = choose(&board(entries.clone()), &config).unwrap();
        assert_eq!(selected.model, "gpt-6-sol");
        assert_eq!(selected.reasoning, "xhigh");
        config.provider = Some(Provider::Anthropic);
        let selected = choose(&board(entries.clone()), &config).unwrap();
        assert_eq!(selected.model, "claude-opus-5-5");
        config.anthropic_api_key = None;
        assert!(choose(&board(entries), &config).is_err());
    }

    #[test]
    fn malformed_winners_are_errors_instead_of_silent_downgrades() {
        let config = AiConfig {
            api_key: Some("key".into()),
            ..Default::default()
        };
        for entry in [
            serde_json::json!({"rank":0,"modelId":"openai/gpt-6-sol","reasoning":"xhigh"}),
            serde_json::json!({"rank":1,"modelId":"openai/../../unexpected","reasoning":"xhigh"}),
            serde_json::json!({"rank":1,"modelId":"openai/gpt-6-sol","reasoning":"execute"}),
        ] {
            assert!(choose(&board(serde_json::json!([entry])), &config).is_err());
        }
    }
}
