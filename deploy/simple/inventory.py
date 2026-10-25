"""Inventory data only: never load PHP code, Composer plugins or project scripts."""
import json
from itertools import islice
from pathlib import Path
import re
import shlex
from urllib.parse import quote, urlencode

from common import InstallError, read, run


def distribution(root=Path("/")):
    values = {}
    for line in read(root / "etc/os-release", 65536).decode().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            parts = shlex.split(value)
            values[key] = parts[0] if len(parts) == 1 else ""
    identity, version = values.get("ID"), values.get("VERSION_ID", "")
    minimum = {"debian": (12,), "ubuntu": (22, 4)}
    try:
        supported = identity in minimum and tuple(map(int, version.split("."))) >= minimum[identity]
    except ValueError:
        supported = False
    if not supported:
        raise InstallError("simple mode supports Debian 12+ and Ubuntu 22.04+ only")
    return identity, version


def deb_components(output, distro):
    components = []
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 6:
            raise InstallError("unexpected dpkg-query output")
        name, version, arch, source, source_version, status = fields
        if status != "installed":
            continue
        if not all((name, version, arch)):
            raise InstallError("incomplete installed Debian package identity")
        name = name.split(":", 1)[0]
        qualifiers = {"arch": arch, "distro": "-".join(distro)}
        if source and source_version:
            qualifiers["upstream"] = f"{source}@{source_version}"
        purl = f"pkg:deb/{distro[0]}/{quote(name, safe='')}@{quote(version, safe='')}?{urlencode(qualifiers)}"
        components.append({"type": "library", "name": name, "version": version, "purl": purl,
                           "properties": [{"name": "filtr:inventory:source", "value": "host:dpkg"}]})
    if not components:
        raise InstallError("no installed OS packages discovered")
    return components


def gap(name, reason):
    return {"type": "application", "name": name[:512],
            "properties": [{"name": "filtr:inventory:gap", "value": reason}]}


def composer_components(document_root):
    components, gaps = [], []
    # Common public/ and web/ layouts; do not recursively walk a server or home directories.
    candidates = [document_root]
    if document_root.name in {"public", "web"}:
        candidates.append(document_root.parent)
    application = next((p for p in candidates if (p / "composer.lock").is_file()
                        or (p / "vendor/composer/installed.json").is_file()), None)
    if application is None:
        return components, gaps
    installed = application / "vendor/composer/installed.json"
    if not installed.is_file():
        return [], [gap(f"Composer installation at {application}",
                       "Lockfile exists but installed package metadata is missing; deployed dependencies unverified")]
    if not installed.resolve().is_relative_to(application.resolve()):
        return [], [gap("External Composer metadata", "Installed metadata resolves outside the application; supply a separate verified inventory")]
    data = json.loads(read(installed))
    if not isinstance(data, (dict, list)):
        raise InstallError("invalid Composer installed metadata")
    packages = data if isinstance(data, list) else data.get("packages", [])
    if not isinstance(packages, list) or len(packages) > 50000:
        raise InstallError("invalid or oversized Composer installed metadata")
    for package in packages:
        if not isinstance(package, dict):
            raise InstallError("invalid Composer package record")
        name, version = package.get("name", ""), package.get("version", "")
        if not re.fullmatch(r"[a-z0-9_.-]+/[a-z0-9_.-]+", name) or not isinstance(version, str) or not version or len(version) > 256:
            gaps.append(gap("Unidentified Composer package", "Missing installed name or exact version"))
            continue
        # Development branches/references are not an exact released version.
        if version.startswith("dev-") or version.endswith("-dev"):
            gaps.append(gap(f"Composer {name} ({version})", "Development reference needs an exact version assessment"))
            continue
        components.append({"type": "library", "name": name, "version": version,
                           "purl": f"pkg:composer/{name}@{quote(version, safe='')}",
                           "properties": [{"name": "filtr:inventory:source", "value": str(installed)}]})
    return components, gaps


def wordpress_header(candidate, root, directory, slug):
    if not candidate.is_file() or candidate.suffix not in (".php", ".css"):
        return None
    if not candidate.resolve().is_relative_to(root.resolve()):
        return gap(f"External WordPress metadata: {slug}", "Metadata resolves outside the application")
    with candidate.open("rb") as stream:
        text = stream.read(8192).decode("utf-8", "replace")
    title = re.search(r"(?im)^\s*(?:/\*|\*)?\s*(?:Plugin|Theme) Name:\s*(.+)", text)
    version = re.search(r"(?im)^\s*(?:/\*|\*)?\s*Version:\s*([^\s*]+)", text)
    if not title:
        return None
    if not version or not title[1].strip() or len(title[1].strip()) > 512 or len(version[1]) > 256:
        return gap(f"WordPress {directory}/{slug}", "Missing or invalid installed title/version header")
    return {"type": "library", "name": title[1].strip(), "version": version[1],
            "purl": f"pkg:generic/wordpress-{directory}/{quote(slug, safe='')}@{quote(version[1], safe='')}",
            "properties": [{"name": "filtr:inventory:source", "value": str(candidate)}]}


def wordpress_extension(entry, root, directory, marker, budget):
    if not entry.resolve().is_relative_to(root.resolve()):
        return [], [gap(f"External WordPress {directory}/{entry.name}", "Symlink resolves outside the application; scan that artifact separately")], 0
    files = sorted(islice(entry.glob(marker), 257)) if entry.is_dir() else [entry]
    selected = files[:min(256, budget)]
    components, gaps = [], []
    if len(files) > len(selected):
        gaps.append(gap(f"WordPress {directory}/{entry.name}", "Bounded header scan omitted candidates; scan the complete artifact separately"))
    for candidate in selected:
        result = wordpress_header(candidate, root, directory, entry.stem)
        if result is not None:
            (components if "purl" in result else gaps).append(result)
    if not components and not gaps:
        gaps.append(gap(f"WordPress {directory}/{entry.name}", "No identifiable plugin/theme header; custom code needs review"))
    return components, gaps, len(selected)


def wordpress_components(document_root):
    version_file = document_root / "wp-includes/version.php"
    if not version_file.is_file():
        return [], []
    if not version_file.resolve().is_relative_to(document_root.resolve()):
        return [], [gap("External WordPress core metadata", "Core metadata resolves outside the selected application")]
    components, gaps = [], []
    match = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", read(version_file, 65536).decode())
    if match:
        version = match[1]
        components.append({"type": "application", "name": "WordPress", "version": version,
                           "purl": f"pkg:generic/wordpress@{quote(version, safe='')}"})
    else:
        gaps.append(gap("WordPress core", "Could not read the installed core version"))
    scanned = 0
    for directory, marker in [("plugins", "*.php"), ("themes", "style.css"), ("mu-plugins", "*.php")]:
        base = document_root / "wp-content" / directory
        if not base.is_dir():
            continue
        if not base.resolve().is_relative_to(document_root.resolve()):
            gaps.append(gap(f"External WordPress {directory}", "Extension directory resolves outside the application; scan it separately"))
            continue
        entries = sorted(islice(base.iterdir(), 4097))
        if len(entries) > 4096:
            raise InstallError("too many WordPress extensions")
        for entry in entries:
            if entry.name.startswith(".") or entry.name == "index.php" or (entry.is_file() and entry.suffix != ".php"):
                continue
            if scanned >= 8192:
                gaps.append(gap("WordPress discovery budget", "Bounded scan exhausted; scan remaining artifacts separately"))
                return components, gaps
            found, missing, count = wordpress_extension(entry, document_root, directory, marker, 8192 - scanned)
            scanned += count
            components.extend(found)
            gaps.extend(missing)
    gaps.append(gap("WordPress bundled dependencies", "Plugin/theme headers do not inventory their bundled libraries; merge an application/image scan"))
    return components, gaps


def host_packages(distro):
    output = run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${db:Status-Status}\n"])
    return deb_components(output, distro)


def discover(document_root, distro=None, runtime_paths=()):
    distro = distro or distribution()
    components = host_packages(distro)
    gaps = []
    for runtime in runtime_paths:
        if runtime.endswith(".sock"):
            match = re.search(r"php([0-9.]+)-fpm\.sock$", runtime)
            runtime = f"/usr/sbin/php-fpm{match[1]}" if match else runtime
        try:
            run(["dpkg-query", "-S", runtime])
        except InstallError:
            gaps.append(gap(f"Unmanaged PHP runtime: {runtime}", "Enabled PHP module/FPM binary is not owned by a Debian package; supply its exact build inventory"))
    for scanner in (composer_components, wordpress_components):
        found, missing = scanner(document_root)
        components.extend(found)
        gaps.extend(missing)
    gaps.append(gap(f"Application code at {document_root}",
                    "Custom code, manually installed libraries and external services are not exhaustively identified by this host discovery"))
    return document(components, gaps, distro)


def document(components, gaps, distro, properties=()):
    unique = {}
    for component in components + gaps:
        unique.setdefault(component.get("purl", component["name"]), component)
    if len(unique) > 50000:
        raise InstallError("inventory exceeds Filtr's 50,000-component limit")
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"properties": [{"name": "filtr:inventory:distribution", "value": "-".join(distro)},
                {"name": "filtr:inventory:scope", "value": "Installed host dpkg packages and selected site's readable application metadata"}] + list(properties)},
            "components": list(unique.values())}
    return sbom, [c["name"] for c in gaps]
