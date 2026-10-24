use super::{AiConfig, INSTRUCTIONS, Provider, Reply, models::Target, output_schema};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::json;

pub(super) async fn request(
    http: &reqwest::Client,
    config: &AiConfig,
    target: &Target,
    input: &str,
) -> Result<(String, Reply)> {
    let response = send_request(http, config, target, input).await?;
    let (id, text) = match target.provider {
        Provider::Openai => {
            let response: OpenaiResponse =
                crate::osv::read_json(response, 1024 * 1024, "OpenAI").await?;
            ensure!(
                response.status == "completed",
                "OpenAI response was not completed"
            );
            let content = response
                .output
                .into_iter()
                .filter(|item| item.kind == "message")
                .flat_map(|item| item.content);
            (response.id, collect_text(content, "output_text")?)
        }
        Provider::Anthropic => {
            let response: AnthropicResponse =
                crate::osv::read_json(response, 1024 * 1024, "Anthropic").await?;
            let reason = match response.stop_reason.as_str() {
                "end_turn" => "end_turn",
                "max_tokens" => "output token limit",
                "refusal" => "refusal",
                "pause_turn" => "paused turn",
                _ => "unexpected stop reason",
            };
            ensure!(
                response.stop_reason == "end_turn",
                "Anthropic response did not complete normally: {reason}"
            );
            (response.id, collect_text(response.content, "text")?)
        }
    };
    ensure!(id.len() <= 512, "AI response identifier exceeds limit");
    let reply: Reply = serde_json::from_str(&text).context("invalid AI enhancement JSON")?;
    ensure!(
        reply.summary.len() <= 4096 && reply.enhancements.len() <= 32,
        "AI review exceeds summary or rule limit"
    );
    Ok((id, reply))
}

async fn send_request(
    http: &reqwest::Client,
    config: &AiConfig,
    target: &Target,
    input: &str,
) -> Result<reqwest::Response> {
    let started = std::time::Instant::now();
    for attempt in 0..3 {
        let response = build_request(http, config, target, input)?
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("AI provider request failed or timed out"))?;
        if attempt == 2
            || !(response.status().as_u16() == 429 || response.status().is_server_error())
        {
            return Ok(response);
        }
        let delay = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(2 << attempt)
            .clamp(1, 30);
        if started.elapsed() + std::time::Duration::from_secs(delay)
            >= std::time::Duration::from_secs(config.ai_timeout_secs)
        {
            return Ok(response);
        }
        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
    }
    unreachable!()
}

fn build_request(
    http: &reqwest::Client,
    config: &AiConfig,
    target: &Target,
    input: &str,
) -> Result<reqwest::RequestBuilder> {
    let key = config
        .key(target.provider)
        .context("provider credentials missing")?;
    let request = match target.provider {
        Provider::Openai => http
            .post(config.url.join("v1/responses")?)
            .bearer_auth(key)
            .body(serde_json::to_vec(&json!({
                "model": target.model, "reasoning": {"effort": target.reasoning},
                "store": false, "max_output_tokens": 16384, "instructions": INSTRUCTIONS,
                "input": [{"role": "user", "content": input}],
                "text": {"format": {"type":"json_schema", "name":"filtr_enhancements", "strict":true, "schema": output_schema()}}
            }))?),
        Provider::Anthropic => http
            .post(config.anthropic_url.join("v1/messages")?)
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01")
            .body(serde_json::to_vec(&json!({
                "model": target.model, "max_tokens": 16384,
                "system": INSTRUCTIONS, "thinking": {"type":"adaptive"},
                "messages": [{"role":"user", "content": input}],
                "output_config": {"effort": target.reasoning, "format": {"type":"json_schema", "schema": output_schema()}}
            }))?),
    };
    Ok(request.header("content-type", "application/json"))
}

fn collect_text(content: impl IntoIterator<Item = Content>, text_kind: &str) -> Result<String> {
    let mut text = String::new();
    for block in content {
        ensure!(block.kind != "refusal", "AI provider refused the review");
        if block.kind == text_kind {
            text.push_str(block.text.as_deref().context("AI output text missing")?);
        }
    }
    Ok(text)
}

#[derive(Deserialize)]
struct OpenaiResponse {
    id: String,
    status: String,
    output: Vec<Output>,
}

#[derive(Deserialize)]
struct Output {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    content: Vec<Content>,
}

#[derive(Deserialize)]
struct Content {
    #[serde(rename = "type")]
    kind: String,
    text: Option<String>,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    id: String,
    stop_reason: String,
    content: Vec<Content>,
}
