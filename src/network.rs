use anyhow::{Context, Result, ensure};
use serde::de::DeserializeOwned;
use std::time::Duration;

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
pub(crate) fn service_client(timeout_secs: u64) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(timeout_secs))
        .build()?)
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
    fn provider_endpoints_require_https_or_loopback() {
        for url in [
            "https://api.anthropic.com/",
            "http://127.0.0.1:9999/",
            "http://[::1]:9999/",
        ] {
            assert!(validate_service_config(&url.parse().unwrap(), 30, "AI").is_ok());
        }
        for url in [
            "http://example.com/",
            "https://user:secret@example.com/",
            "https://example.com/path",
            "https://example.com/?secret=token",
            "https://example.com/#fragment",
            "file:///tmp/provider",
        ] {
            assert!(validate_service_config(&url.parse().unwrap(), 30, "AI").is_err());
        }
        assert!(
            validate_service_config(&"https://example.com/".parse().unwrap(), 0, "AI").is_err()
        );
    }
}
