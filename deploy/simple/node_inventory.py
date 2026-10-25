"""Read installed npm trees, including nested, scoped, workspace and pnpm packages."""
import json
from pathlib import Path
import re
from urllib.parse import quote

from common import InstallError, read, run
import inventory

NAME = re.compile(r"(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+")
VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?")


def entries(directory):
    if not directory.is_dir():
        return
    for index, entry in enumerate(directory.iterdir()):
        if index >= 50000:
            raise InstallError("npm directory exceeds bounded discovery; provide a verified artifact SBOM")
        yield entry


def package(path, root):
    metadata = path / "package.json"
    if not metadata.is_file() or not metadata.resolve().is_relative_to(root):
        return None, inventory.gap(f"Unidentified Node package at {path}", "Missing or external installed package.json")
    data = json.loads(read(metadata, 1024 * 1024))
    if not isinstance(data, dict):
        raise InstallError("invalid installed npm package metadata")
    if data.get("private") is True:
        return None, inventory.gap(f"Private Node package at {path}", "Supply private package/fork identity and build inventory; do not assume the public npm namespace")
    name, version = data.get("name"), data.get("version")
    if not isinstance(name, str) or not NAME.fullmatch(name) or len(name) > 214 or not isinstance(version, str) or not VERSION.fullmatch(version) or len(version) > 256:
        return None, inventory.gap(f"Unversioned Node package at {path}", "An exact installed npm name/version is required")
    purl = f"pkg:npm/{quote(name, safe='/')}@{quote(version, safe='')}"
    return {"type": "library", "name": name, "version": version, "purl": purl,
            "properties": [{"name": "filtr:inventory:source", "value": str(metadata)}]}, None


class InstalledTree:
    def __init__(self, root):
        self.root = root.resolve()
        self.pending = [self.root / "node_modules"]
        self.visited = set()
        self.components = {}
        self.gaps = []
        self.scanned_entries = 0
        self.package_paths = set()

    def enqueue(self, path):
        if len(self.pending) + len(self.visited) >= 100000:
            raise InstallError("Node dependency discovery exhausted its bounded path budget")
        self.pending.append(path)

    def allowed(self, path):
        if path.resolve().is_relative_to(self.root):
            return True
        self.gaps.append(inventory.gap(f"External Node dependency {path.name}", "Dependency path is outside --app-dir; include its inventory separately"))
        return False

    def scan_store(self, path):
        for store in entries(path):
            if store.is_dir():
                self.enqueue(store if store.name == "node_modules" else store / "node_modules")

    def scan_entry(self, path, directory):
        self.scanned_entries += 1
        if self.scanned_entries > 200000:
            raise InstallError("Node dependency discovery exhausted its installed-entry budget")
        if not self.allowed(path):
            return
        if path.name == ".pnpm":
            self.scan_store(path)
            return
        if path.name.startswith("@") and directory.name == "node_modules":
            self.enqueue(path)
            return
        if path.name.startswith(".") or not path.is_dir():
            return
        actual = path.resolve()
        if actual in self.package_paths:
            return
        self.package_paths.add(actual)
        component, missing = package(actual, self.root)
        if missing:
            self.gaps.append(missing)
        if component:
            self.components.setdefault(component["purl"], component)
        self.enqueue(actual / "node_modules")
        if len(self.components) + len(self.gaps) > 50000:
            raise InstallError("Node packages/gaps exceed Filtr inventory limits")

    def scan_directory(self, directory):
        directory = directory.resolve()
        if directory in self.visited or not self.allowed(directory):
            return
        self.visited.add(directory)
        for path in entries(directory):
            self.scan_entry(path, directory)

    def collect(self):
        if not self.pending[0].is_dir():
            return [], [inventory.gap("Node installed dependencies", "node_modules is missing; lockfiles, Yarn PnP and bundled applications need a separate deployed-artifact SBOM")]
        while self.pending:
            self.scan_directory(self.pending.pop())
        return [self.components[key] for key in sorted(self.components)], sorted(self.gaps, key=lambda g: g["name"])


def installed(root):
    return InstalledTree(root).collect()


def runtime_component(runtime, host):
    version = runtime["versions"]["node"]
    executable = runtime["executable"]
    if not executable.endswith(" (deleted)"):
        try:
            ownership = run(["dpkg-query", "-S", executable])
            for component in host:
                if ownership.startswith(component["name"] + ":") and re.search(r"(?:^|:)" + re.escape(version) + r"(?:[+~-]|$)", component["version"]):
                    return [], []  # Keep the vendor package/build identity and its backports.
        except InstallError:
            pass
    component = {"type": "platform", "name": "Node.js", "version": version,
                 "purl": f"pkg:generic/nodejs@{quote(version, safe='')}",
                 "properties": [{"name": "filtr:inventory:source", "value": executable}]}
    gaps = [inventory.gap("Node runtime build provenance", "Unpackaged/replaced runtime: upstream version is known; supply vendor/build SBOM for backports and bundled libraries")]
    return [component], gaps


def discover(runtime, distro):
    root = Path(runtime["app_dir"])
    manifest = root / "package.json"
    if not manifest.is_file() or not manifest.resolve().is_relative_to(root):
        raise InstallError("--app-dir needs a readable local package.json")
    host = inventory.host_packages(distro)
    packages, gaps = installed(root)
    if not any(p["name"] == "express" for p in packages):
        raise InstallError("no installed Express package found; use the deployed application/workspace root")
    components, runtime_gaps = runtime_component(runtime, host)
    gaps.extend(runtime_gaps)
    gaps.append(inventory.gap(f"Node application/build inventory at {root}", "Custom code, native addon internals, bundled libraries and external services require additional artifact inventories"))
    properties = [{"name": "filtr:node:versions", "value": json.dumps(runtime["versions"], sort_keys=True)},
                  {"name": "filtr:node:executable", "value": runtime["executable"]}]
    return inventory.document(host + components + packages, gaps, distro, properties)
