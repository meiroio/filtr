//! Forwarding metadata has a separate trust boundary from the upstream address.
use anyhow::{Result, ensure};
use axum::http::{HeaderMap, HeaderValue, header, uri::Authority};
use clap::Args;
use std::net::IpAddr;

#[derive(Args, Default)]
#[group(id = "Forwarding")]
pub struct Config {
    /// Exact socket-peer IPs allowed to supply one client IP and HTTP scheme.
    #[arg(long, env = "FILTR_TRUSTED_PROXIES", value_delimiter = ',')]
    pub trusted_proxies: Vec<IpAddr>,
    /// Accepted public hostnames, without ports. Empty accepts any valid Host.
    #[arg(long, env = "FILTR_ALLOWED_HOSTS", value_delimiter = ',')]
    pub allowed_hosts: Vec<String>,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.trusted_proxies.len() <= 64 && self.allowed_hosts.len() <= 128,
            "too many forwarding settings"
        );
        for host in &self.allowed_hosts {
            let authority = authority(host)?;
            ensure!(
                authority.port().is_none(),
                "allowed hosts must not contain ports"
            );
        }
        Ok(())
    }
}

fn authority(value: &str) -> Result<Authority> {
    ensure!(
        !value.is_empty()
            && !value.ends_with(':')
            && value.len() <= 255
            && value.is_ascii()
            && !value.contains(['@', ',', '/', '\\', '%', '?', '#'])
            && !value.bytes().any(|b| b.is_ascii_whitespace()),
        "invalid public host"
    );
    let host: Authority = value.parse()?;
    let suffix = if value.starts_with('[') {
        value
            .split_once(']')
            .map(|(_, suffix)| suffix)
            .unwrap_or(":invalid")
    } else {
        value.split_once(':').map_or("", |(_, suffix)| suffix)
    };
    if !suffix.is_empty() {
        let port = suffix.strip_prefix(':').unwrap_or(suffix);
        ensure!(
            !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit())
                && port.parse::<u16>().is_ok(),
            "invalid public host port"
        );
    }
    ensure!(
        !host.host().is_empty() && (host.port().is_none() || host.port_u16().is_some()),
        "invalid public host port"
    );
    Ok(host)
}

fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().map(|v| v.to_str()).transpose()?;
    ensure!(values.next().is_none(), "duplicate forwarding field");
    Ok(value)
}

pub(crate) struct Metadata {
    host: Option<HeaderValue>,
    client: HeaderValue,
    scheme: HeaderValue,
    port: HeaderValue,
}

impl Metadata {
    pub(crate) fn read(config: &Config, headers: &HeaderMap, peer: IpAddr) -> Result<Self> {
        let host = single(headers, "host")?;
        if let Some(host) = host {
            let parsed = authority(host)?;
            ensure!(
                config.allowed_hosts.is_empty()
                    || config
                        .allowed_hosts
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(parsed.host())),
                "public host is not allowed"
            );
        } else {
            ensure!(config.allowed_hosts.is_empty(), "public host is required");
        }
        let mut client = peer;
        let mut scheme = "http";
        if config.trusted_proxies.contains(&peer) {
            if let Some(value) = single(headers, "x-forwarded-for")? {
                client = value.parse()?;
            }
            if let Some(value) = single(headers, "x-forwarded-proto")? {
                ensure!(
                    matches!(value, "http" | "https"),
                    "invalid forwarded scheme"
                );
                scheme = value;
            }
            if let Some(value) = single(headers, "x-forwarded-host")? {
                ensure!(
                    host.is_some_and(|h| h.eq_ignore_ascii_case(value)),
                    "forwarded host mismatch"
                );
            }
        }
        Ok(Self {
            host: host.map(HeaderValue::from_str).transpose()?,
            client: client.to_string().parse()?,
            port: host
                .and_then(|h| h.parse::<Authority>().ok())
                .and_then(|h| h.port_u16())
                .unwrap_or(if scheme == "https" { 443 } else { 80 })
                .to_string()
                .parse()?,
            scheme: scheme.parse()?,
        })
    }

    pub(crate) fn apply(self, headers: &mut HeaderMap) {
        let names: Vec<_> = headers
            .keys()
            .filter(|name| {
                name.as_str().starts_with("x-forwarded-")
                    || matches!(name.as_str(), "forwarded" | "x-real-ip" | "host")
            })
            .cloned()
            .collect();
        for name in names {
            headers.remove(name);
        }
        if let Some(host) = self.host {
            headers.insert("x-forwarded-host", host.clone());
            headers.insert(header::HOST, host);
        }
        headers.insert("x-real-ip", self.client.clone());
        headers.insert("x-forwarded-for", self.client);
        headers.insert("x-forwarded-proto", self.scheme);
        headers.insert("x-forwarded-port", self.port);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_is_limited_to_exact_peers_and_single_valid_values() {
        let peer = "127.0.0.1".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("host", "Example.com:443".parse().unwrap());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-for", "192.0.2.1".parse().unwrap());
        Metadata::read(&Config::default(), &headers, peer)
            .unwrap()
            .apply(&mut headers);
        assert_eq!(headers["x-forwarded-proto"], "http");
        assert_eq!(headers["x-forwarded-for"], "127.0.0.1");
        assert_eq!(headers["host"], "Example.com:443");
        let config = Config {
            trusted_proxies: vec![peer],
            allowed_hosts: vec!["example.com".into()],
        };
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-for", "192.0.2.1".parse().unwrap());
        Metadata::read(&config, &headers, peer)
            .unwrap()
            .apply(&mut headers);
        assert_eq!(headers["x-forwarded-proto"], "https");
        assert_eq!(headers["x-real-ip"], "192.0.2.1");
        for value in ["ftp", "https,http", "HTTPS"] {
            headers.insert("x-forwarded-proto", value.parse().unwrap());
            assert!(Metadata::read(&config, &headers, peer).is_err());
        }
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.append("x-forwarded-for", "192.0.2.2".parse().unwrap());
        assert!(Metadata::read(&config, &headers, peer).is_err());
    }

    #[test]
    fn host_allowlist_and_forwarded_host_cannot_change_the_target_identity() {
        let peer = "127.0.0.1".parse().unwrap();
        let config = Config {
            trusted_proxies: vec![peer],
            allowed_hosts: vec!["example.com".into()],
        };
        for host in [
            "evil.example",
            "example.com@evil.example",
            "example.com:bad",
            "example.com/path",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("host", host.parse().unwrap());
            assert!(Metadata::read(&config, &headers, peer).is_err());
        }
        let mut headers = HeaderMap::new();
        headers.insert("host", "example.com".parse().unwrap());
        headers.insert("x-forwarded-host", "evil.example".parse().unwrap());
        assert!(Metadata::read(&config, &headers, peer).is_err());
    }
}
