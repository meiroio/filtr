use super::{AiConfig, INSTRUCTIONS, Provider, Reply, models::Target, output_schema, research};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(super) async fn request(
    http: &reqwest::Client,
    config: &AiConfig,
    target: &Target,
    input: &str,
) -> Result<(String, Reply)> {
    let mut body = request_body(target, input);
    let mut sources = BTreeSet::new();
    let mut usage = research::Usage::default();
    for _ in 0..4 {
        let response = send_request(http, config, target, &body).await?;
        let response: Value =
            crate::network::read_json(response, 1024 * 1024, "AI provider").await?;
        usage.add(&research::Usage::read(&response, target.provider));
        sources.extend(research::sources(&response, target.provider)?);
        ensure!(sources.len() <= 1024, "AI search source limit exceeded");
        if target.provider == Provider::Anthropic && response["stop_reason"] == "pause_turn" {
            body["messages"]
                .as_array_mut()
                .context("AI request messages must be an array")?
                .push(json!({"role":"assistant", "content":response["content"]}));
            continue;
        }
        let (id, payload) = reply_payload(&response, target.provider)?;
        let mut reply: Reply =
            serde_json::from_value(payload).context("invalid AI enhancement JSON")?;
        ensure!(
            reply.summary.len() <= 4096
                && reply.enhancements.len() <= 32
                && reply.discoveries.len() <= 32,
            "AI review exceeds summary or rule limit"
        );
        reply.sources = sources;
        reply.usage = usage;
        return Ok((id, reply));
    }
    anyhow::bail!("AI web research exceeded continuation limit")
}

fn reply_payload(response: &Value, provider: Provider) -> Result<(String, Value)> {
    let id = response["id"]
        .as_str()
        .context("AI response identifier missing")?;
    ensure!(id.len() <= 512, "AI response identifier exceeds limit");
    let text = match provider {
        Provider::Openai => {
            ensure!(
                response["status"] == "completed",
                "OpenAI response was not completed"
            );
            let content = response["output"]
                .as_array()
                .context("OpenAI output missing")?
                .iter()
                .filter(|item| item["type"] == "message")
                .flat_map(|item| item["content"].as_array().into_iter().flatten());
            collect_text(content, "output_text")?
        }
        Provider::Anthropic => {
            let content = response["content"]
                .as_array()
                .context("Anthropic content missing")?;
            let tools: Vec<_> = content
                .iter()
                .filter(|item| item["type"] == "tool_use")
                .collect();
            if response["stop_reason"] == "tool_use" {
                ensure!(
                    tools.len() == 1 && tools[0]["name"] == "submit_review",
                    "expected exactly one submit_review reporting call (received {} client calls)",
                    tools.len()
                );
                return Ok((id.to_owned(), tools[0]["input"].clone()));
            }
            ensure!(
                response["stop_reason"] == "end_turn",
                "Anthropic response did not complete normally"
            );
            ensure!(tools.is_empty(), "uncompleted AI review tool invocation");
            collect_text(content.iter(), "text")?
        }
    };
    Ok((
        id.to_owned(),
        serde_json::from_str(&text).context("invalid AI enhancement JSON")?,
    ))
}

async fn send_request(
    http: &reqwest::Client,
    config: &AiConfig,
    target: &Target,
    body: &Value,
) -> Result<reqwest::Response> {
    let started = std::time::Instant::now();
    for attempt in 0..3 {
        let response = build_request(http, config, target, body)?
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
    body: &Value,
) -> Result<reqwest::RequestBuilder> {
    let key = config
        .key(target.provider)
        .context("provider credentials missing")?;
    let request = match target.provider {
        Provider::Openai => http.post(config.url.join("v1/responses")?).bearer_auth(key),
        Provider::Anthropic => http
            .post(config.anthropic_url.join("v1/messages")?)
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01"),
    };
    Ok(request
        .header("content-type", "application/json")
        .body(serde_json::to_vec(body)?))
}

fn request_body(target: &Target, input: &str) -> Value {
    let mut body = match target.provider {
        Provider::Openai => json!({
            "model":target.model, "reasoning":{"effort":target.reasoning}, "store":false,
            "max_output_tokens":16384, "instructions":INSTRUCTIONS,
            "tools":[{"type":"web_search"}], "max_tool_calls":5,
            "include":["web_search_call.action.sources"],
            "input":[{"role":"user", "content":input}],
            "text":{"format":{"type":"json_schema", "name":"filtr_enhancements", "strict":true, "schema":output_schema()}}
        }),
        Provider::Anthropic => json!({
            "model":target.model, "max_tokens":16384, "cache_control":{"type":"ephemeral"},
            "system":[{"type":"text", "text":INSTRUCTIONS, "cache_control":{"type":"ephemeral"}}],
            "thinking":{"type":"adaptive"}, "output_config":{"effort":target.reasoning},
            "tool_choice":{"type":"auto", "disable_parallel_tool_use":true},
            "tools":[{"type":"web_search_20250305", "name":"web_search", "max_uses":5},
                {"name":"submit_review", "description":"Submit the completed dependency security review after web research. This only reports data; it does not execute actions.", "strict":true, "input_schema":output_schema()}],
            "messages":[{"role":"user", "content":input}]
        }),
    };
    if matches!(target.reasoning.as_str(), "default" | "none")
        && let Some(object) = body.as_object_mut()
    {
        object.remove("reasoning");
        object.remove("thinking");
        object.remove("output_config");
    }
    body
}

fn collect_text<'a>(
    content: impl IntoIterator<Item = &'a Value>,
    text_kind: &str,
) -> Result<String> {
    let mut text = String::new();
    for block in content {
        ensure!(block["type"] != "refusal", "AI provider refused the review");
        if block["type"] == text_kind {
            text.push_str(block["text"].as_str().context("AI output text missing")?);
        }
    }
    Ok(text)
}
