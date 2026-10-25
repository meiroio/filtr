use crate::network;
use anyhow::{Context, Result, ensure};
use axum::{body::Bytes, http::HeaderValue};
use clap::Args;
use serde_json::{Value, json};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

#[derive(Args)]
#[group(id = "webhook")]
pub struct Config {
    /// Receive remediation changes as JSON POST requests.
    #[arg(long, env = "FILTR_WEBHOOK_URL", hide_env_values = true)]
    pub webhook_url: Option<reqwest::Url>,
    /// Optional bearer token sent only to the configured webhook URL.
    #[arg(long, env = "FILTR_WEBHOOK_TOKEN", hide_env_values = true)]
    pub webhook_token: Option<String>,
    #[arg(long, env = "FILTR_WEBHOOK_TIMEOUT_SECS", default_value_t = 10)]
    pub webhook_timeout_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            webhook_url: None,
            webhook_token: None,
            webhook_timeout_secs: 10,
        }
    }
}

impl Config {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            (1..=60).contains(&self.webhook_timeout_secs),
            "webhook timeout must be between 1 and 60 seconds"
        );
        if let Some(url) = &self.webhook_url {
            ensure!(
                matches!(url.scheme(), "https" | "http")
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none(),
                "webhook URL must use HTTP(S), without credentials or a fragment"
            );
        }
        if let Some(token) = &self.webhook_token {
            ensure!(
                self.webhook_url.is_some(),
                "webhook token requires a webhook URL"
            );
            ensure!(
                !token.trim().is_empty() && token.len() <= 4096,
                "webhook token must contain 1–4096 bytes"
            );
            HeaderValue::from_str(&format!("Bearer {token}"))
                .context("invalid webhook authorization header")?;
        }
        Ok(())
    }
}

pub(crate) struct Notifier {
    sender: mpsc::Sender<(Value, &'static str)>,
}

impl Notifier {
    pub(crate) fn new(config: &Config, upstream: &reqwest::Url) -> Result<Option<Self>> {
        let Some(url) = config.webhook_url.clone() else {
            return Ok(None);
        };
        let client = network::service_client(config.webhook_timeout_secs)?;
        let mut authorization = config
            .webhook_token
            .as_ref()
            .map(|token| HeaderValue::from_str(&format!("Bearer {token}")))
            .transpose()?;
        if let Some(header) = &mut authorization {
            header.set_sensitive(true);
        }
        let upstream = upstream.to_string();
        let (sender, mut receiver) = mpsc::channel::<(Value, &'static str)>(8);
        tokio::spawn(async move {
            let mut previous = Value::Null;
            let mut sequence = 0_u64;
            while let Some((report, trigger)) = receiver.recv().await {
                let key = json!({
                    "blockers": report["blockers"],
                    "inventory_gaps": report["inventory_gaps"],
                    "ai_status": report["ai_review"]["status"],
                    "uncovered_vulnerabilities": report["uncovered_vulnerabilities"],
                    "traffic": report["traffic"],
                });
                if key == previous {
                    continue;
                }
                previous = key;
                sequence += 1;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default();
                let event_id = format!("{}-{}-{sequence}", std::process::id(), now.as_nanos());
                let payload = json!({
                    "version": 1,
                    "event": "filtr.remediation_updated",
                    "id": event_id,
                    "occurred_at": now.as_secs(),
                    "trigger": trigger,
                    "upstream": upstream,
                    "remediation": report,
                });
                let Ok(bytes) = serde_json::to_vec(&payload) else {
                    tracing::error!(event_id, "cannot serialize webhook; notification dropped");
                    continue;
                };
                let bytes = Bytes::from(bytes);
                deliver(&client, &url, authorization.as_ref(), &event_id, bytes).await;
            }
        });
        Ok(Some(Self { sender }))
    }

    pub(crate) fn notify(&self, report: Value, trigger: &'static str) {
        if self.sender.try_send((report, trigger)).is_err() {
            tracing::warn!("webhook queue unavailable; notification dropped");
        }
    }
}

async fn deliver(
    client: &reqwest::Client,
    url: &reqwest::Url,
    authorization: Option<&HeaderValue>,
    event_id: &str,
    payload: Bytes,
) {
    for attempt in 1..=3 {
        let mut request = client
            .post(url.clone())
            .header("content-type", "application/json")
            .header("x-filtr-event-id", event_id)
            .body(payload.clone());
        if let Some(authorization) = authorization {
            request = request.header("authorization", authorization);
        }
        match request.send().await {
            Ok(response) if response.status().is_success() => return,
            Ok(response) => tracing::warn!(
                event_id,
                attempt,
                status = response.status().as_u16(),
                "webhook rejected"
            ),
            // Reqwest errors can contain a secret URL; never log the error or response body.
            Err(_) => tracing::warn!(event_id, attempt, "webhook request failed"),
        }
        if attempt < 3 {
            tokio::time::sleep(Duration::from_secs(attempt)).await;
        }
    }
    tracing::warn!(event_id, "webhook delivery exhausted; notification dropped");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_webhook_configuration_without_exposing_secrets() {
        for url in [
            "file:///tmp/hook",
            "https://user:secret@example.com/hook",
            "https://example.com/hook#secret",
        ] {
            let config = Config {
                webhook_url: Some(url.parse().unwrap()),
                ..Default::default()
            };
            let error = config.validate().unwrap_err().to_string();
            assert!(!error.contains("secret"));
        }
        for token in ["", "secret\r\nInjected: true"] {
            let config = Config {
                webhook_url: Some("https://example.com/hook".parse().unwrap()),
                webhook_token: Some(token.into()),
                ..Default::default()
            };
            assert!(config.validate().is_err());
        }
        assert!(
            Config {
                webhook_token: Some("secret".into()),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Config {
                webhook_timeout_secs: 0,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Config {
                webhook_url: Some("http://sre:8080/hooks/filtr".parse().unwrap()),
                ..Default::default()
            }
            .validate()
            .is_ok()
        );
    }
}
