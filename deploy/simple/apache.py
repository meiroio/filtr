"""A deliberately bounded Apache profile, not a general configuration rewriter."""
from dataclasses import dataclass
from pathlib import Path
import os
import re
import shlex

from common import InstallError, read, run


@dataclass
class Vhost:
    address: str
    lines: list
    source: Path

    def values(self, directive):
        return [tokens[1:] for line in self.lines if (tokens := words(line))
                and tokens[0].lower() == directive.lower()]


def words(line):
    try:
        return shlex.split(line, comments=True)
    except ValueError as error:
        raise InstallError("unsupported Apache quoting") from error


def parse_vhosts(text, source):
    blocks, current, depth = [], None, 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            if current:
                current.lines.append(line)
            continue
        match = re.fullmatch(r"<VirtualHost\s+([^>]+)>", stripped, re.I)
        if match:
            if current or depth:
                raise InstallError("nested virtual hosts are unsupported")
            current = Vhost(match[1], [], source)
        elif stripped.lower() == "</virtualhost>":
            if current is None or depth:
                raise InstallError("unbalanced Apache sections")
            blocks.append(current)
            current = None
        elif current:
            if stripped.startswith("</"):
                depth -= 1
            elif stripped.startswith("<") and not stripped.endswith("/>"):
                depth += 1
            if depth < 0:
                raise InstallError("unbalanced Apache section")
            current.lines.append(line)
        elif not re.fullmatch(r"</?IfModule(?:\s+!?mod_ssl\.c)?>", stripped, re.I):
            raise InstallError(f"unsupported directives outside VirtualHost in {source.name}")
    if current or depth or not blocks:
        raise InstallError("incomplete virtual host file")
    return blocks


def hostnames(block):
    names = [v for values in block.values("ServerName") + block.values("ServerAlias") for v in values]
    if not names or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", n)
                        or len(n) > 253 for n in names):
        raise InstallError("profile requires explicit DNS ServerName/ServerAlias without wildcard or port")
    return [n.lower() for n in names]


def port(block):
    match = re.fullmatch(r"(?:\*|_default_|0\.0\.0\.0):(80|443)", block.address)
    if not match:
        raise InstallError("profile supports one *:80 and/or *:443 address per virtual host")
    return int(match[1])


def redirect_only(block, site):
    # Preserve a simple HTTP -> canonical HTTPS redirect without touching PHP.
    directives = [words(line) for line in block.lines if words(line)]
    allowed = {"servername", "serveralias", "serveradmin", "redirect", "errorlog", "customlog", "loglevel"}
    redirects = block.values("Redirect")
    plain = (port(block) == 80 and len(redirects) == 1
            and redirects[0] in [["permanent", "/", f"https://{site}/"], ["301", "/", f"https://{site}/"]]
            and all(d[0].lower() in allowed for d in directives))
    if plain:
        return True
    # Certbot's usual generated redirect. Convert it to an unconditional canonical
    # redirect, so an unknown Host cannot fall through to PHP on the public vhost.
    conditions = block.values("RewriteCond")
    rules = block.values("RewriteRule")
    names = set(hostnames(block))
    certbot_allowed = allowed | {"documentroot", "rewriteengine", "rewritecond", "rewriterule",
                                "<directory", "</directory>", "require", "allowoverride", "options"}
    return (port(block) == 80 and block.values("RewriteEngine") == [["on"]]
            and len(rules) == 1 and rules[0] == ["^", "https://%{SERVER_NAME}%{REQUEST_URI}", "[END,NE,R=permanent]"]
            and bool(conditions) and all(len(c) in (2, 3) and c[0] == "%{SERVER_NAME}"
                and c[1].startswith("=") and c[1][1:].lower() in names
                and (len(c) == 2 or c[2] == "[OR]") for c in conditions)
            and {c[1][1:].lower() for c in conditions} == names
            and all(d[0].lower() in certbot_allowed for d in directives))


def redirect_frontend(block):
    lines = [line for line in block.lines if (tokens := words(line)) and tokens[0].lower()
             in {"servername", "serveralias", "serveradmin", "errorlog", "customlog", "loglevel"}]
    canonical = block.values("ServerName")[0][0]
    lines.append(f"    Redirect permanent / https://{canonical}/")
    return f"<VirtualHost {block.address}>\n" + "\n".join(lines) + "\n</VirtualHost>\n"


def selected_sites(site, apache=Path("/etc/apache2")):
    apache = apache.resolve()
    selected = {}
    for enabled in sorted((apache / "sites-enabled").glob("*.conf")):
        source = enabled.resolve()
        if not source.is_relative_to(apache / "sites-available"):
            raise InstallError("enabled sites must resolve inside /etc/apache2/sites-available")
        text = read(source, 1024 * 1024).decode()
        # Unrelated sites may use configuration features outside our supported profile.
        if not re.search(r"(?im)^\s*Server(?:Name|Alias)\s+.*\b" + re.escape(site) + r"(?:\s|$)", text):
            continue
        blocks = parse_vhosts(text, source)
        if any(site not in hostnames(block) for block in blocks):
            raise InstallError("selected site shares a file with another hostname; split the file first")
        selected[source] = blocks
    if not selected:
        raise InstallError("no enabled virtual host matches --site")
    blocks = [b for group in selected.values() for b in group]
    if len(blocks) > 2 or len({port(b) for b in blocks}) != len(blocks):
        raise InstallError("profile supports one HTTP host and one HTTPS host for the selected site")
    return selected


def check_htaccess(root):
    pending, directories, entries = [root], 0, 0
    while pending:
        directory = pending.pop()
        directories += 1
        if directories > 4096:
            raise InstallError("application exceeds bounded .htaccess discovery; use manual integration")
        with os.scandir(directory) as children:
            for entry in children:
                entries += 1
                if entries > 50000:
                    raise InstallError("application exceeds bounded path discovery; use manual integration")
                if entry.is_symlink() and entry.is_dir():
                    raise InstallError("symlinked application directories require reviewed manual integration")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                elif entry.name == ".htaccess":
                    if entry.is_symlink():
                        raise InstallError("symlinked .htaccess requires manual integration")
                    if re.search(r"%\{(?:HTTPS|SERVER_PORT)\}", read(entry.path, 1024 * 1024).decode(), re.I):
                        raise InstallError("HTTPS/SERVER_PORT redirects in .htaccess need adaptation to trusted X-Forwarded-Proto")


def check_application(block):
    roots = block.values("DocumentRoot")
    if len(roots) != 1 or len(roots[0]) != 1:
        raise InstallError("application virtual host must have exactly one DocumentRoot")
    root = Path(roots[0][0])
    if not root.is_absolute() or not root.is_dir() or root == Path("/"):
        raise InstallError("DocumentRoot must be an existing absolute application directory")
    for line in block.lines:
        tokens = words(line)
        if not tokens:
            continue
        name = tokens[0].lower()
        if name in {"sslverifyclient", "sslrequire", "sslrequiressl", "sslusername"} or (
                name == "require" and any("ssl" in token.lower() for token in tokens[1:])) or (
                name == "ssloptions" and any("fakebasicauth" in token.lower() for token in tokens[1:])):
            raise InstallError("client-certificate/SSL authorization needs a reviewed manual integration")
        if name.startswith("proxy") or name in {"redirect", "redirectmatch", "rewritecond", "rewriterule",
                                               "macro", "use", "virtualdocumentroot", "sethandler"}:
            # Unix-socket PHP-FPM SetHandler inside FilesMatch is handled separately below.
            if name == "sethandler" and len(tokens) == 2 and re.fullmatch(
                    r"proxy:unix:/run/php/php[0-9.]+-fpm\.sock\|fcgi://localhost/?", tokens[1]):
                continue
            raise InstallError(f"unsupported application directive: {tokens[0]}; use a reviewed manual integration")
        if name in {"include", "includeoptional"} and tokens[1:] != ["/etc/letsencrypt/options-ssl-apache.conf"]:
            raise InstallError("site-level includes require a reviewed manual integration")
        if "${" in line.replace("${APACHE_LOG_DIR}", "") or line.rstrip().endswith("\\"):
            raise InstallError("Apache variable expansion and continued lines are unsupported")
    check_htaccess(root)
    parent_override = root.parent / ".htaccess"
    if parent_override.is_symlink():
        raise InstallError("symlinked parent .htaccess requires manual integration")
    if parent_override.is_file() and re.search(r"%\{(?:HTTPS|SERVER_PORT)\}", read(parent_override, 1024 * 1024).decode(), re.I):
        raise InstallError("parent .htaccess HTTPS redirects require manual adaptation")
    return root


def frontend(block, listen):
    # Keep public certificates, names and logging; PHP/application directives stay private.
    keep = {"servername", "serveralias", "serveradmin", "errorlog", "customlog", "loglevel", "protocols"}
    lines, depth = [], 0
    for line in block.lines:
        stripped = line.strip()
        if stripped.startswith("</"):
            depth -= 1
        tokens = words(line)
        if depth == 0 and tokens:
            name = tokens[0].lower()
            if name in keep or name.startswith("ssl") or name == "header" or (
                    name == "include" and tokens[1:] == ["/etc/letsencrypt/options-ssl-apache.conf"]):
                lines.append(line)
        if stripped.startswith("<") and not stripped.startswith("</"):
            depth += 1
    scheme = "https" if port(block) == 443 else "http"
    lines.extend([
        "    ProxyRequests Off", "    ProxyPreserveHost On", "    ProxyAddHeaders Off",
        "    RequestHeader unset Forwarded", "    RequestHeader unset X-Real-IP",
        "    RequestHeader unset X-Forwarded-For", "    RequestHeader unset X-Forwarded-Host",
        "    RequestHeader unset X-Forwarded-Proto",
        '    RequestHeader set X-Forwarded-For "expr=%{REMOTE_ADDR}"',
        f'    RequestHeader set X-Forwarded-Proto "{scheme}"',
        # Host is preserved independently; do not trust a client-supplied forwarded host.
        f'    ProxyPass "/" "http://127.0.0.1:{listen}/" connectiontimeout=3 timeout=30',
        f'    ProxyPassReverse "/" "http://127.0.0.1:{listen}/"',
    ])
    return f"<VirtualHost {block.address}>\n" + "\n".join(lines) + "\n</VirtualHost>\n"


def plan(site, listen, backend, apache=Path("/etc/apache2")):
    selected = selected_sites(site, apache)
    blocks = [b for group in selected.values() for b in group]
    applications = [b for b in blocks if not redirect_only(b, site)]
    if len(applications) != 1:
        raise InstallError("profile supports one application virtual host; an optional HTTP host must redirect to HTTPS")
    application = applications[0]
    root = check_application(application)
    names = sorted(set(n for b in blocks for n in hostnames(b)))
    changes = {}
    for path, group in selected.items():
        changes[path] = ("# Managed by Filtr simple mode; rollback restores the original.\n" + "\n".join(
            redirect_frontend(b)
            if redirect_only(b, site) else frontend(b, listen) for b in group)).encode()
    backend_lines = []
    for line in application.lines:
        tokens = words(line)
        if tokens and (tokens[0].lower().startswith("ssl") or (
                tokens[0].lower() == "include" and tokens[1:] == ["/etc/letsencrypt/options-ssl-apache.conf"])):
            continue
        backend_lines.append(line)
    backend_lines.extend(['    SetEnvIf X-Forwarded-Proto "^https$" HTTPS=on',
                          '    RemoteIPHeader X-Forwarded-For', '    RemoteIPInternalProxy 127.0.0.1'])
    changes[apache / "conf-enabled/filtr-simple-backend.conf"] = (
        f"Listen 127.0.0.1:{backend}\n<VirtualHost 127.0.0.1:{backend}>\n" +
        "\n".join(backend_lines) + "\n</VirtualHost>\n").encode()
    return {"site": site, "hosts": names, "document_root": str(root),
            "public_port": port(application), "changes": changes}


def php_runtime(apache=Path("/etc/apache2")):
    modules = run(["apache2ctl", "-M"])
    evidence = []
    if "php_module" in modules:
        for path in (apache / "mods-enabled").glob("php*.load"):
            for line in read(path, 65536).decode().splitlines():
                tokens = words(line)
                if len(tokens) == 3 and tokens[0].lower() == "loadmodule" and tokens[1] == "php_module":
                    evidence.append(tokens[2])
    for base in (apache / "conf-enabled", apache / "sites-enabled"):
        for path in base.glob("*.conf"):
            text = read(path, 1024 * 1024).decode()
            evidence.extend(re.findall(r"/run/php/php[0-9.]+-fpm\.sock", text))
    if not evidence:
        raise InstallError("cannot identify enabled mod_php or a standard /run/php/phpVERSION-fpm.sock handler")
    return sorted(set(evidence))


def node_plan(site, listen, backend, apache=Path("/etc/apache2")):
    from nginx import check_origin
    selected = selected_sites(site, apache)
    changes, names, ports = {}, set(), []
    allowed = {"servername", "serveralias", "serveradmin", "documentroot", "errorlog", "customlog", "loglevel",
               "protocols", "header", "include", "proxypass", "proxypassreverse", "proxypreservehost", "proxyrequests", "requestheader"}
    for path, blocks in selected.items():
        output = []
        for block in blocks:
            names.update(hostnames(block))
            if redirect_only(block, site):
                output.append(redirect_frontend(block))
                continue
            passes = block.values("ProxyPass")
            reverse = block.values("ProxyPassReverse")
            if len(passes) != 1 or len(reverse) != 1 or len(passes[0]) != 2 or passes[0][0] != "/" or reverse != passes:
                raise InstallError("Apache Node profile needs one matching root ProxyPass/ProxyPassReverse")
            check_origin(passes[0][1], backend)
            for line in block.lines:
                tokens = words(line)
                if tokens and tokens[0].lower() not in allowed and not tokens[0].lower().startswith("ssl"):
                    raise InstallError("complex Apache Node vhost needs manual integration")
                if tokens and tokens[0].lower() == "include" and tokens[1:] != ["/etc/letsencrypt/options-ssl-apache.conf"]:
                    raise InstallError("custom Apache includes need manual integration")
                if tokens and tokens[0].lower() == "requestheader" and (
                        len(tokens) < 3 or tokens[2].lower() not in {
                            "host", "forwarded", "x-real-ip", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port"}):
                    raise InstallError("custom Apache request-header transformations need manual integration")
            ports.append(port(block))
            output.append(frontend(block, listen))
        changes[path] = "\n".join(output).encode()
    if not ports or len(set(ports)) != len(ports):
        raise InstallError("Apache Node profile needs one application vhost per public protocol")
    return {"site": site, "hosts": sorted(names), "public_port": max(ports), "web_server": "apache", "changes": changes}
