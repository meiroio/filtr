use anyhow::{Context, Result, bail, ensure};
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;

pub const MAX_SBOM_BYTES: usize = 64 * 1024 * 1024;
const MAX_COMPONENTS: usize = 50_000;

#[derive(Clone, Debug, Serialize)]
pub struct Component {
    pub name: String,
    pub package: Option<String>,
    pub version: Option<String>,
    // Display-only provenance must not change AI inputs or existing cache/snapshot identities.
    #[serde(skip)]
    pub sources: Vec<Source>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Source {
    pub name: String,
    pub image: Option<String>,
    pub image_id: Option<String>,
}

#[derive(Deserialize)]
struct Property {
    name: String,
    #[serde(default)]
    value: String,
}

#[derive(Deserialize)]
struct CdxComponent {
    #[serde(rename = "type")]
    kind: Option<String>,
    name: String,
    version: Option<String>,
    purl: Option<String>,
    #[serde(default)]
    components: Vec<CdxComponent>,
    #[serde(default)]
    properties: Vec<Property>,
}

#[derive(Deserialize)]
struct CdxMetadata {
    component: Option<CdxComponent>,
    #[serde(default)]
    properties: Vec<Property>,
}

impl CdxMetadata {
    fn images(&self) -> Vec<Source> {
        self.properties
            .iter()
            .find(|property| property.name == "filtr:inventory:provenance")
            .and_then(|property| serde_json::from_str(&property.value).ok())
            .unwrap_or_default()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDx {
    spec_version: String,
    #[serde(default)]
    components: Vec<CdxComponent>,
    metadata: Option<CdxMetadata>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxRef {
    reference_type: String,
    reference_locator: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxPackage {
    name: String,
    version_info: Option<String>,
    #[serde(default)]
    external_refs: Vec<SpdxRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SimplePackage {
    purl: String,
    version: Option<String>,
}

pub fn package_identity(purl: &str) -> Result<(String, Option<String>)> {
    let mut parsed = PackageUrl::from_str(purl).context("invalid package URL")?;
    let mut version = parsed.version().map(str::to_owned);
    if matches!(parsed.ty(), "deb" | "rpm")
        && let (Some(epoch), Some(version)) = (parsed.qualifiers().get("epoch"), &mut version)
    {
        ensure!(
            !epoch.is_empty() && epoch.len() <= 16 && epoch.bytes().all(|b| b.is_ascii_digit()),
            "invalid package epoch"
        );
        if !version.contains(':') {
            *version = format!("{epoch}:{version}");
        }
    }
    if !matches!(parsed.ty(), "deb" | "apk" | "rpm") {
        parsed.clear_qualifiers();
    }
    parsed.without_version().without_subpath();
    Ok((parsed.to_string(), version))
}

fn component(name: String, purl: Option<&str>, mut version: Option<String>) -> Result<Component> {
    ensure!(
        !name.trim().is_empty() && name.len() <= 512,
        "invalid component name"
    );
    let Some(purl) = purl else {
        return Ok(Component {
            name,
            package: None,
            version,
            sources: Vec::new(),
        });
    };
    let (package, purl_version) = package_identity(purl)?;
    if package == "pkg:golang/stdlib" {
        version = version.map(|v| v.strip_prefix("go").unwrap_or(&v).to_owned());
    }
    if let (Some(left), Some(right)) = (&version, &purl_version) {
        ensure!(
            left == right,
            "component version conflicts with package URL version"
        );
    }
    Ok(Component {
        name,
        package: Some(package),
        version: version.or(purl_version),
        sources: Vec::new(),
    })
}

fn flatten_cdx(
    items: Vec<CdxComponent>,
    output: &mut Vec<Component>,
    images: &[Source],
) -> Result<()> {
    for item in items {
        ensure!(output.len() < MAX_COMPONENTS, "too many components");
        if item.kind.as_deref() != Some("file") {
            let mut component = component(item.name, item.purl.as_deref(), item.version)?;
            let names: std::collections::BTreeSet<_> = item
                .properties
                .iter()
                .filter(|p| p.name == "filtr:inventory:source" && !p.value.trim().is_empty())
                .map(|p| &p.value)
                .collect();
            component.sources = names
                .into_iter()
                .map(|name| {
                    images
                        .iter()
                        .find(|image| &image.name == name)
                        .cloned()
                        .unwrap_or_else(|| Source {
                            name: name.clone(),
                            image: None,
                            image_id: None,
                        })
                })
                .collect();
            output.push(component);
        }
        flatten_cdx(item.components, output, images)?;
    }
    Ok(())
}

/// Extracts dependency inventory, rather than validating the entire SBOM schema.
pub fn parse(bytes: &[u8]) -> Result<Vec<Component>> {
    ensure!(bytes.len() <= MAX_SBOM_BYTES, "SBOM exceeds 64 MiB");
    let value: Value = serde_json::from_slice(bytes).context("SBOM must be valid JSON")?;
    let mut output = Vec::new();
    if value.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX") {
        let document: CycloneDx = serde_json::from_value(value)?;
        ensure!(
            ["1.4", "1.5", "1.6", "1.7"].contains(&document.spec_version.as_str()),
            "supported CycloneDX versions: 1.4–1.7"
        );
        let images = document
            .metadata
            .as_ref()
            .map(CdxMetadata::images)
            .unwrap_or_default();
        if let Some(item) = document.metadata.and_then(|m| m.component) {
            flatten_cdx(vec![item], &mut output, &images)?;
        }
        flatten_cdx(document.components, &mut output, &images)?;
    } else if value.get("spdxVersion").is_some() {
        ensure!(
            matches!(value["spdxVersion"].as_str(), Some("SPDX-2.2" | "SPDX-2.3")),
            "supported SPDX versions: 2.2 and 2.3"
        );
        let packages: Vec<SpdxPackage> = serde_json::from_value(
            value
                .get("packages")
                .cloned()
                .context("SPDX packages missing")?,
        )?;
        ensure!(packages.len() <= MAX_COMPONENTS, "too many components");
        for item in packages {
            let purls: Vec<_> = item
                .external_refs
                .iter()
                .filter(|r| r.reference_type == "purl")
                .collect();
            ensure!(
                purls.len() <= 1,
                "multiple package URLs for one SPDX package"
            );
            output.push(component(
                item.name,
                purls.first().map(|r| r.reference_locator.as_str()),
                item.version_info,
            )?);
        }
    } else if value.get("format").and_then(Value::as_str) == Some("filtr-1") {
        let packages: Vec<SimplePackage> =
            serde_json::from_value(value.get("packages").cloned().context("packages missing")?)?;
        ensure!(packages.len() <= MAX_COMPONENTS, "too many components");
        for item in packages {
            output.push(component(
                item.purl.clone(),
                Some(&item.purl),
                item.version,
            )?);
        }
    } else {
        bail!("expected CycloneDX JSON, SPDX 2.x JSON, or format: filtr-1");
    }
    ensure!(!output.is_empty(), "SBOM contains no components");
    Ok(output)
}

#[cfg(test)]
mod tests {
    #[test]
    fn display_provenance_preserves_ai_identity_and_all_source_images() {
        let metadata = serde_json::json!([
            {"name":"app","image":"example/app:1","image_id":"sha256:example"}
        ])
        .to_string();
        let document = serde_json::json!({
            "bomFormat":"CycloneDX", "specVersion":"1.6",
            "metadata":{"properties":[{"name":"filtr:inventory:provenance","value":metadata}]},
            "components":[{"name":"a","purl":"pkg:npm/a@1.0.0","properties":[
                {"name":"filtr:inventory:source","value":"app"},
                {"name":"filtr:inventory:source","value":"other"},
                {"name":"filtr:inventory:source","value":"app"}
            ]}]
        });
        let parsed = super::parse(&serde_json::to_vec(&document).unwrap()).unwrap();
        assert_eq!(parsed[0].sources.len(), 2);
        assert_eq!(parsed[0].sources[0].image.as_deref(), Some("example/app:1"));
        assert!(parsed[0].sources[1].image.is_none());
        let plain =
            super::parse(br#"{"format":"filtr-1","packages":[{"purl":"pkg:npm/a@1.0.0"}]}"#)
                .unwrap();
        // Simple input uses the PURL as its display name; compare the same inventory fields.
        let mut plain = plain;
        plain[0].name = "a".into();
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            serde_json::to_value(&plain).unwrap()
        );
    }

    #[test]
    fn accepts_equivalent_go_stdlib_versions_and_explicit_rpm_epochs() {
        let bytes = br#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"stdlib","version":"go1.26.2","purl":"pkg:golang/stdlib@1.26.2"},{"name":"findutils","version":"1:4.8.0-7.el9","purl":"pkg:rpm/redhat/findutils@4.8.0-7.el9?epoch=1&distro=rhel-9.7"}]}"#;
        let components = super::parse(bytes).unwrap();
        assert_eq!(components[0].version.as_deref(), Some("1.26.2"));
        assert_eq!(components[1].version.as_deref(), Some("1:4.8.0-7.el9"));
        assert!(
            super::parse(
                &String::from_utf8(bytes.to_vec())
                    .unwrap()
                    .replace("go1.26.2", "go1.25.0")
                    .into_bytes()
            )
            .is_err()
        );
        assert!(
            super::parse(
                &String::from_utf8(bytes.to_vec())
                    .unwrap()
                    .replace("1:4.8.0", "2:4.8.0")
                    .into_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn file_components_are_not_packages_and_nested_dependencies_are_retained() {
        let bytes = br#"{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"file","name":"image.tar"}},"components":[{"type":"file","name":"bun.lock","components":[{"type":"library","name":"react","purl":"pkg:npm/react@19.3.1"}]}]}"#;
        let components = super::parse(bytes).unwrap();
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].name, "react");
    }

    #[test]
    fn linux_package_identity_retains_distribution_and_source_information() {
        let (package, version) = super::package_identity(
            "pkg:deb/ubuntu/libc6@2.43-2ubuntu2.4?arch=arm64&distro=ubuntu-26.04&upstream=glibc",
        )
        .unwrap();
        assert_eq!(version.as_deref(), Some("2.43-2ubuntu2.4"));
        assert!(package.contains("distro=ubuntu-26.04"));
        assert!(package.contains("upstream=glibc"));
        assert_ne!(
            package,
            super::package_identity("pkg:deb/ubuntu/libc6@2.43-2ubuntu2.4?distro=ubuntu-24.04")
                .unwrap()
                .0
        );
    }

    use super::*;

    #[test]
    fn parses_nested_cyclonedx_and_metadata() {
        let components = parse(br#"{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"app"}},"components":[{"name":"parent","components":[{"name":"log4j","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar"}]}]}"#).unwrap();
        assert_eq!(components.len(), 3);
        assert_eq!(
            components[2].package.as_deref(),
            Some("pkg:maven/org.apache.logging.log4j/log4j-core")
        );
        assert_eq!(components[2].version.as_deref(), Some("2.14.1"));
        assert!(components[0].package.is_none());
    }

    #[test]
    fn parses_spdx_purl() {
        let components = parse(br#"{"spdxVersion":"SPDX-2.3","packages":[{"name":"rsc","versionInfo":"19.1.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/react-server-dom-webpack@19.1.0"}]}]}"#).unwrap();
        assert_eq!(components[0].version.as_deref(), Some("19.1.0"));
    }

    #[test]
    fn rejects_empty_malformed_and_conflicting_versions() {
        for bytes in [br#"{}"#.as_slice(), br#"{"format":"filtr-1","packages":[]}"#, br#"{"format":"filtr-1","packages":[{"purl":"not-a-purl"}]}"#, br#"{"format":"filtr-1","packages":[{"purl":"pkg:npm/react@19.0.0","version":"19.1.0"}]}"#] {
            assert!(parse(bytes).is_err());
        }
    }
}
