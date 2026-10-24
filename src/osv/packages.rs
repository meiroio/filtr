use packageurl::PackageUrl;
use serde_json::json;

pub(super) fn query(
    package: &str,
    version: &str,
) -> std::result::Result<serde_json::Value, &'static str> {
    let purl: PackageUrl<'_> = package.parse().map_err(|_| "invalid_purl")?;
    if matches!(
        purl.ty(),
        "cargo" | "composer" | "gem" | "golang" | "maven" | "npm" | "nuget" | "pypi"
    ) {
        return Ok(json!({"package":{"purl":package},"version":version}));
    }
    if !matches!(purl.ty(), "apk" | "deb" | "rpm") {
        return Err("unsupported_purl_type");
    }
    let distro = purl.qualifiers().get("distro").ok_or("missing_distro")?;
    let release = distro
        .rsplit_once('-')
        .map(|(_, v)| v)
        .ok_or("unsupported_distro")?;
    let numbers: Vec<_> = release.split('.').collect();
    if !numbers
        .iter()
        .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("unsupported_distro");
    }
    let ecosystem = match (purl.ty(), purl.namespace(), numbers.as_slice()) {
        ("apk", Some("alpine"), [major, minor, ..]) if distro.starts_with("alpine-") => {
            format!("Alpine:v{major}.{minor}")
        }
        ("deb", Some("debian"), [major, ..]) if distro.starts_with("debian-") => {
            format!("Debian:{major}")
        }
        ("deb", Some("ubuntu"), [year, "04"])
            if distro.starts_with("ubuntu-") && matches!(*year, "20" | "22" | "24" | "26") =>
        {
            format!("Ubuntu:{release}:LTS")
        }
        _ => return Err("unsupported_distro"),
    };
    let upstream = purl
        .qualifiers()
        .get("upstream")
        .map(|v| v.as_ref())
        .unwrap_or(purl.name());
    let (name, source_version) = upstream.split_once('@').unwrap_or((upstream, version));
    if name.is_empty()
        || name.len() > 512
        || source_version.is_empty()
        || source_version.len() > 512
        || upstream.chars().any(char::is_whitespace)
    {
        return Err("invalid_source_package");
    }
    Ok(json!({"package":{"ecosystem":ecosystem,"name":name},"version":source_version}))
}

#[cfg(test)]
mod tests {
    #[test]
    fn linux_queries_use_distribution_release_and_source_package() {
        for (purl, version, ecosystem, name, source_version) in [
            (
                "pkg:deb/ubuntu/libc6?distro=ubuntu-26.04&upstream=glibc",
                "2.43-2ubuntu2.4",
                "Ubuntu:26.04:LTS",
                "glibc",
                "2.43-2ubuntu2.4",
            ),
            (
                "pkg:deb/debian/libssl3?distro=debian-12&upstream=openssl%403.0.17-1",
                "3.0.17-1+b1",
                "Debian:12",
                "openssl",
                "3.0.17-1",
            ),
            (
                "pkg:apk/alpine/libssl3?distro=alpine-3.24.2&upstream=openssl",
                "3.5.5-r0",
                "Alpine:v3.24",
                "openssl",
                "3.5.5-r0",
            ),
        ] {
            assert_eq!(
                super::query(purl, version).unwrap(),
                serde_json::json!({"package":{"ecosystem":ecosystem,"name":name},"version":source_version})
            );
        }
        assert_eq!(
            super::query("pkg:deb/ubuntu/libc6", "1"),
            Err("missing_distro")
        );
        assert_eq!(
            super::query("pkg:rpm/redhat/glibc?distro=rhel-9.7", "1"),
            Err("unsupported_distro")
        );
        assert_eq!(
            super::query("pkg:apk/alpine/libssl3?distro=debian-12", "1"),
            Err("unsupported_distro")
        );
    }
}
