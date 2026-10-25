#!/usr/bin/python3
"""Filtr's Debian/Ubuntu Apache/PHP and Node/Express installer."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shlex
import signal
import socket
import stat
import sys

# The distribution contains these adjacent modules. Ignore user PYTHONPATH/site packages.
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
import apache
from common import InstallError, atomic, json_bytes, read, run, safe_destination
import inventory
import node_express
import service
from transaction import Transaction

STATE = Path("/var/lib/filtr-simple")
DATA = Path("/var/lib/filtr")
ENV = Path("/etc/filtr/filtr.env")
UNIT = Path("/etc/systemd/system/filtr-simple.service")
BINARY = Path("/usr/local/bin/filtr")
LIB = Path("/usr/local/lib/filtr-simple")
ENTRY = Path("/usr/local/sbin/filtr-simple")
ENABLE = Path("/etc/systemd/system/multi-user.target.wants/filtr-simple.service")
MODULES = ("proxy", "proxy_http", "headers", "setenvif", "remoteip")
ENV_KEYS = {"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "FILTR_AI_PROVIDER", "FILTR_AI_MODEL",
            "FILTR_AI_REASONING", "FILTR_AI_CACHE_TTL_SECS", "FILTR_AI_TIMEOUT_SECS",
            "FILTR_AI_REVIEW_TIMEOUT_SECS", "FILTR_WEBHOOK_URL", "FILTR_WEBHOOK_TOKEN",
            "FILTR_WEBHOOK_TIMEOUT_SECS", "FILTR_AUTO_BLOCK_CRITICAL", "FILTR_MAX_BODY_BYTES",
            "FILTR_MAX_IN_FLIGHT", "FILTR_TIMEOUT_SECS"}


def options():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=["apache-php", "node-express"], default="apache-php")
    parser.add_argument("--site", help="enabled Apache ServerName or Nginx server_name")
    parser.add_argument("--app-service", help="existing unprivileged Node systemd .service")
    parser.add_argument("--app-dir", type=Path, help="Node app/workspace root; defaults to service WorkingDirectory")
    parser.add_argument("--web-server", choices=["nginx", "apache"], help="Node TLS frontend; default nginx")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--dry-run", action="store_true", help="discover and print plan; no writes, downloads or AI calls")
    actions.add_argument("--discover-only", type=Path, metavar="SBOM.json")
    actions.add_argument("--rollback", action="store_true", help="restore the journal's original configuration")
    actions.add_argument("--refresh-inventory", action="store_true", help="rediscover installed versions and upload; reuse AI cache")
    parser.add_argument("--binary", type=Path, default=Path(__file__).resolve().parents[1] / "filtr")
    parser.add_argument("--binary-sha256", help="expected SHA-256 for a separately supplied local binary")
    parser.add_argument("--env-file", type=Path, help="private optional AI/model/webhook settings; never executed as shell")
    parser.add_argument("--listen-port", type=int, default=8080)
    parser.add_argument("--backend-port", type=int, help="PHP: free port (default 8081); Node: existing port (auto-detected)")
    parser.add_argument("--admin-port", type=int, default=9090)
    parser.add_argument("--health-path", default="/")
    parser.add_argument("--ca-file", help="additional trusted CA file for a private HTTPS site's installation probe")
    return parser.parse_args()


def optional_env(path):
    if path is None:
        return {}
    if path.stat().st_mode & 0o077:
        raise InstallError("--env-file must be private (chmod 600)")
    values = {}
    for line in read(path, 65536).decode().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.removeprefix("export ").partition("=")
        key = key.strip()
        if not separator or key not in ENV_KEYS or key in values:
            raise InstallError("unsupported or duplicate setting in --env-file; use documented AI/webhook variables only")
        fields = shlex.split(value, comments=True)
        if len(fields) > 1:
            raise InstallError("quote values containing whitespace in --env-file")
        values[key] = fields[0] if fields else ""
        if any(ord(c) < 32 or ord(c) > 126 for c in values[key]):
            raise InstallError("optional settings must use printable ASCII values")
    return values


def verified_binary(path, expected):
    if not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
        raise InstallError("prebuilt binary is missing or too large; extract a release or provide --binary")
    if expected is None:
        manifest = path.parent / "SHA256SUMS"
        if manifest.is_file():
            for line in read(manifest, 65536).decode().splitlines():
                fields = line.split()
                if len(fields) == 2 and fields[1].lstrip("*") == path.name:
                    expected = fields[0]
    if not expected or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
        raise InstallError("binary needs its release SHA256SUMS or --binary-sha256")
    content = read(path, 128 * 1024 * 1024)
    if hashlib.sha256(content).hexdigest() != expected.lower():
        raise InstallError("prebuilt binary checksum mismatch")
    # A wrong architecture/libc fails before changing Apache.
    run([str(path.resolve()), "--version"])
    return content


def module_links():
    links = {}
    base = Path("/etc/apache2")
    for module in MODULES:
        for suffix in ("load", "conf"):
            available = base / "mods-available" / f"{module}.{suffix}"
            enabled = base / "mods-enabled" / available.name
            if available.is_file() and not enabled.exists():
                links[enabled] = available
            elif suffix == "load" and not available.is_file():
                raise InstallError(f"Apache module {module} is missing; install distribution apache2 packages")
    return links


def check_ports(ports, reserved=()):
    all_ports = tuple(ports) + tuple(reserved)
    if len(set(all_ports)) != len(all_ports) or any(not 1024 <= port <= 65535 for port in all_ports):
        raise InstallError("listen/backend/admin ports must be distinct unprivileged ports")
    for port in ports:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", port))


def refresh():
    record = json.loads(read(STATE / "transaction.json"))
    if record.get("status") != "installed":
        raise InstallError("no active simple-mode installation")
    metadata = record["metadata"]
    config = optional_saved_env()
    if metadata.get("profile") == "node-express":
        sbom, gaps = node_express.rediscover(metadata, inventory.distribution())
    else:
        sbom, gaps = inventory.discover(Path(metadata["document_root"]), runtime_paths=apache.php_runtime())
    if json.loads(read(DATA / "sbom.json", 64 * 1024 * 1024)) == sbom:
        print(json.dumps({"unchanged": True, "components": len(sbom["components"]), "discovery_gaps": gaps,
                          "report": str(STATE / "last-upload.json"), "ai": "no upload or new AI calls requested"}))
        return
    response = service.api(int(config["FILTR_ADMIN_LISTEN"].rsplit(":", 1)[1]),
                           config["FILTR_ADMIN_TOKEN"], "POST", "/v1/sbom", json_bytes(sbom))
    atomic(STATE / "last-upload.json", json_bytes(response))
    print(json.dumps({"components": len(sbom["components"]), "discovery_gaps": gaps,
                      "report": str(STATE / "last-upload.json"), "ai": "cache reused; misses/expired reviews may incur charges"}))


def optional_saved_env():
    # Generated values are JSON-quoted; never source an environment file.
    values = {}
    for line in read(ENV, 65536).decode().splitlines():
        key, value = line.split("=", 1)
        values[key] = json.loads(value)
    return values


def apply(args, plan, sbom, settings, binary, links):
    occupied_library = LIB.is_symlink() or (LIB.exists() and (not LIB.is_dir() or any(LIB.iterdir())))
    if occupied_library or any(p.exists() or p.is_symlink() for p in (UNIT, BINARY, ENV, ENTRY, ENABLE)):
        raise InstallError("existing Filtr installation/configuration found; simple mode will not overwrite it")
    if (DATA / "sbom.json").exists():
        raise InstallError("existing Filtr SBOM data found; preserve/archive it before a fresh simple-mode installation")
    changes = plan["changes"]
    changes[BINARY] = binary
    changes[UNIT] = service.unit(plan.get("web_server", "apache"))
    changes[ENTRY] = b'#!/bin/sh\nexec /usr/bin/python3 -I /usr/local/lib/filtr-simple/main.py "$@"\n'
    for path in Path(__file__).parent.glob("*.py"):
        changes[LIB / path.name] = read(path)
    token = secrets.token_hex(64)
    settings.setdefault("FILTR_MAX_BODY_BYTES", "8388608")
    settings.setdefault("FILTR_MAX_IN_FLIGHT", "64")
    settings.setdefault("FILTR_TIMEOUT_SECS", "30")
    settings.update(FILTR_LISTEN=f"127.0.0.1:{args.listen_port}", FILTR_ADMIN_LISTEN=f"127.0.0.1:{args.admin_port}",
                    FILTR_UPSTREAM=plan.get("upstream", f"http://127.0.0.1:{args.backend_port}"), FILTR_SBOM=str(DATA / "sbom.json"),
                    FILTR_ADMIN_TOKEN=token, FILTR_TRUSTED_PROXIES="127.0.0.1", FILTR_ALLOWED_HOSTS=",".join(plan["hosts"]))
    changes[ENV] = "".join(f"{key}={json.dumps(value)}\n" for key, value in sorted(settings.items())).encode()
    links[ENABLE] = UNIT
    for path in list(changes) + list(links):
        safe_destination(path)
    transaction = Transaction(STATE)
    transaction.begin(list(changes) + list(links), {k: v for k, v in plan.items() if k != "changes"})
    try:
        try:
            account = pwd.getpwnam("filtr-simple")
        except KeyError:
            run(["useradd", "--system", "--user-group", "--home-dir", str(DATA), "--no-create-home",
                 "--shell", "/usr/sbin/nologin", "filtr-simple"])
            account = pwd.getpwnam("filtr-simple")
        if account.pw_uid == 0 or account.pw_gid == 0:
            raise InstallError("filtr-simple must be an unprivileged account and group")
        if DATA.is_symlink() or (DATA.exists() and (DATA.stat().st_uid != account.pw_uid or any(DATA.iterdir()))):
            raise InstallError("existing nonempty or differently owned /var/lib/filtr; use a separate instance")
        DATA.mkdir(mode=0o700, exist_ok=True)
        DATA.chmod(0o700)
        os.chown(DATA, account.pw_uid, account.pw_gid)
        for path, content in changes.items():
            mode = 0o755 if path in (BINARY, ENTRY) else 0o644
            gid = 0
            if path.exists() and not path.is_symlink():
                original = path.stat()
                mode, gid = stat.S_IMODE(original.st_mode), original.st_gid
            if path == ENV:
                mode, gid = 0o640, account.pw_gid
            if path == Path("/etc/apache2/conf-enabled/filtr-simple-backend.conf"):
                mode, gid = 0o600, 0
            atomic(path, content, mode, gid=gid)
        for path, target in links.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(target)
        service.check_web_server(plan.get("web_server", "apache"))
        run(["systemctl", "daemon-reload"])
        transaction.record["service_attempted"] = True
        transaction.save()
        run(["systemctl", "start", "filtr-simple.service"])
        service.wait_admin(args.admin_port, token)
        response = service.api(args.admin_port, token, "POST", "/v1/sbom", json_bytes(sbom))
        atomic(STATE / "last-upload.json", json_bytes(response))
        service.reload_web_server(plan.get("web_server", "apache"))
        status, emergency_blocked = service.confirm_flow(args.admin_port, token, args.site,
                                                         plan["public_port"], args.health_path, args.ca_file)
        transaction.finish()
    except BaseException:
        try:
            transaction.rollback(check_conflicts=False)
        except Exception as error:
            raise InstallError(f"installation failed and automatic rollback needs attention; journal: {transaction.journal}") from error
        raise
    print(json.dumps({"installed": True, "site": args.site, "health_status": status, "emergency_blocked": emergency_blocked,
                      "report": str(STATE / "last-upload.json"), "rollback": "sudo filtr-simple --rollback",
                      "credentials": str(ENV)}))


def main():
    args = options()
    if args.profile == "node-express" and os.geteuid() != 0:
        raise InstallError("Node discovery requires sudo to inspect the selected running service")
    if not args.dry_run and os.geteuid() != 0:
        raise InstallError("run as root; --dry-run is also available without root if configuration is readable")
    if args.rollback or args.refresh_inventory:
        with mutation_lock():
            if args.rollback:
                Transaction(STATE).rollback()
                print("Original web server configuration restored. Private SBOM/cache/report data and service account retained.")
            else:
                refresh()
        return
    if not args.site or not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?", args.site):
        raise InstallError("--site must be an explicit enabled DNS hostname")
    args.site = args.site.lower()
    if not args.health_path.startswith("/") or any(ord(c) < 33 or ord(c) > 126 for c in args.health_path):
        raise InstallError("--health-path must be an ASCII request path")
    distro = inventory.distribution()
    runtime = []
    if args.profile == "node-express":
        plan, sbom, gaps = node_express.prepare(args, distro)
        if not args.discover_only:
            check_ports((args.listen_port, args.admin_port), (args.backend_port,))
    else:
        if args.app_service or args.app_dir or args.web_server not in (None, "apache"):
            raise InstallError("Node service/options require --profile node-express")
        args.backend_port = args.backend_port or 8081
        run(["systemctl", "is-active", "--quiet", "apache2"])
        run(["apache2ctl", "configtest"])
        if not args.discover_only:
            check_ports((args.listen_port, args.backend_port, args.admin_port))
        runtime = apache.php_runtime()
        plan = apache.plan(args.site, args.listen_port, args.backend_port)
        plan.update(profile="apache-php", web_server="apache")
        sbom, gaps = inventory.discover(Path(plan["document_root"]), distro, runtime)
    settings = optional_env(args.env_file)
    links = module_links() if plan["web_server"] == "apache" else {}
    if args.discover_only:
        atomic(args.discover_only, json_bytes(sbom))
        print(json.dumps({"sbom": str(args.discover_only), "components": len(sbom["components"]), "gaps": gaps}))
    elif args.dry_run:
        print(json.dumps({"dry_run": True, "site": args.site, "hosts": plan["hosts"], "distribution": "-".join(distro),
            "application_root": plan["document_root"], "components": len(sbom["components"]),
            "profile": args.profile, "runtime_evidence": plan.get("runtime_evidence", {"php_handlers": runtime}),
            "discovery_gaps": gaps,
            "web_server": plan["web_server"], "configuration_files": list(map(str, plan["changes"])),
            "modules_to_enable": [str(p) for p in links],
            "service": str(UNIT), "binary": str(BINARY), "settings": str(ENV), "state": str(STATE),
            "flow": f"{plan['web_server']}:{plan['public_port']} -> Filtr:127.0.0.1:{args.listen_port} -> {plan.get('upstream', f'Apache/PHP:127.0.0.1:{args.backend_port}')}",
            "optional_settings": sorted(settings), "ai_calls": 0, "binary_required_for_apply": str(args.binary)}, indent=2))
    else:
        binary = verified_binary(args.binary, args.binary_sha256)
        baseline = service.probe(args.site, plan["public_port"], args.health_path, args.ca_file)
        if not 200 <= baseline < 400:
            raise InstallError("existing website health check failed; choose a working --health-path")
        with mutation_lock():
            apply(args, plan, sbom, settings, binary, links)


def mutation_lock():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if STATE.is_symlink() or STATE.stat().st_uid != 0 or STATE.stat().st_mode & 0o077:
        raise InstallError("/var/lib/filtr-simple must be a private root-owned directory")
    stream = (STATE / "lock").open("a")
    try:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        stream.close()
        raise InstallError("another simple-mode operation is running") from error
    return stream


def interrupted(_signum, _frame):
    raise InstallError("installation interrupted")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except Exception as error:
        # Parser/OS errors may contain private file contents. Show only curated errors.
        print(str(error) if isinstance(error, InstallError) else f"Operation failed ({type(error).__name__}); check prerequisites, readable metadata and private service logs", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Operation interrupted; inspect the rollback journal if an apply had started", file=sys.stderr)
        sys.exit(130)
