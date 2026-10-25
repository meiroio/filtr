"""Conservative edits to one fixed-origin Nginx reverse-proxy site."""
from dataclasses import dataclass, field
from pathlib import Path
import re
import shlex
from urllib.parse import urlsplit

from common import InstallError, read

TOKEN = re.compile(r'''\s+|\#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[{};]|[^\s{};#"']+''')
CANONICAL = {"host", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-port", "x-real-ip", "forwarded", "connection"}


@dataclass
class Directive:
    name: str
    args: list
    start: int
    end: int
    children: list = field(default_factory=list)

    def named(self, name):
        return [child for child in self.children if child.name == name]


def parse(text):
    tokens = []
    position = 0
    for match in TOKEN.finditer(text):
        if match.start() != position:
            raise InstallError("unsupported Nginx syntax")
        position = match.end()
        value = match[0]
        if not value.isspace() and not value.startswith("#"):
            tokens.append((value, match.start(), match.end()))
    if position != len(text) or len(tokens) > 100000:
        raise InstallError("Nginx site exceeds supported syntax/size")
    index = 0

    def block(depth=0):
        nonlocal index
        if depth > 16:
            raise InstallError("Nginx site has too many nested sections")
        result = []
        while index < len(tokens) and tokens[index][0] != "}":
            start, values = tokens[index][1], []
            while index < len(tokens) and tokens[index][0] not in (";", "{", "}"):
                token = tokens[index][0]
                values.append(shlex.split(token)[0] if token.startswith(("'", '"')) else token)
                index += 1
            if not values or index >= len(tokens) or tokens[index][0] == "}":
                raise InstallError("incomplete Nginx directive")
            children = []
            if tokens[index][0] == "{":
                index += 1
                children = block(depth + 1)
                if index >= len(tokens) or tokens[index][0] != "}":
                    raise InstallError("unbalanced Nginx sections")
            end = tokens[index][2]
            index += 1
            result.append(Directive(values[0], values[1:], start, end, children))
        return result

    result = block()
    if index != len(tokens):
        raise InstallError("unbalanced Nginx sections")
    return result


def names(server):
    directives = server.named("server_name")
    if len(directives) != 1 or not directives[0].args:
        raise InstallError("Nginx site needs explicit server_name")
    values = directives[0].args
    if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value) or len(value) > 253 for value in values):
        raise InstallError("wildcard/regex/default server names require manual integration")
    return [value.lower() for value in values]


def public_port(server):
    ports = set()
    for item in server.named("listen"):
        if not item.args or item.args[0] not in ("80", "443", "[::]:80", "[::]:443"):
            raise InstallError("Nginx profile supports standard 80/443 listeners")
        ports.add(443 if item.args[0].endswith("443") else 80)
        if any(value not in ("ssl", "http2", "default_server") for value in item.args[1:]):
            raise InstallError("custom Nginx listener options require manual integration")
    if len(ports) != 1:
        raise InstallError("each Nginx server needs one public protocol/port")
    return ports.pop()


def check_origin(value, backend):
    parsed = urlsplit(value)
    if (parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1")
            or parsed.port != backend or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise InstallError("existing proxy_pass must target the selected loopback Node port directly")
    return parsed.path


def tls_includes(server):
    for directive in server.named("include"):
        if directive.args != ["/etc/letsencrypt/options-ssl-nginx.conf"]:
            raise InstallError("arbitrary Nginx site includes require manual integration")
        included = parse(read(directive.args[0], 1024 * 1024).decode())
        if any(item.children or not item.name.startswith("ssl_") for item in included):
            raise InstallError("TLS include contains non-TLS directives")


def route_edits(server, text, listen, backend):
    tls_includes(server)
    if any(server.named(name) for name in ("if", "rewrite", "return", "proxy_pass", "error_page")):
        raise InstallError("Nginx app server rewrites/alternate routes require manual integration")
    locations = server.named("location")
    if len(locations) != 1 or locations[0].args != ["/"]:
        raise InstallError("Node profile supports one location /; split/regex routes need manual integration")
    location = locations[0]
    if any(item.children for item in location.children) or any(location.named(name) for name in ("include", "rewrite", "return", "try_files", "error_page")):
        raise InstallError("complex Nginx location needs manual integration")
    passes = location.named("proxy_pass")
    if len(passes) != 1 or len(passes[0].args) != 1:
        raise InstallError("Nginx location must have one fixed proxy_pass")
    tail = check_origin(passes[0].args[0], backend)
    edits = [(passes[0].start, passes[0].end, f"proxy_pass http://127.0.0.1:{listen}{tail};")]
    headers = location.named("proxy_set_header")
    inherited = []
    for directive in server.named("proxy_set_header") + headers:
        if len(directive.args) != 2 or directive.args[0].lower() == "upgrade":
            raise InstallError("WebSocket/custom proxy headers require manual integration")
    if not headers:
        inherited = [text[item.start:item.end] for item in server.named("proxy_set_header") if item.args[0].lower() not in CANONICAL]
    replace = {"proxy_http_version", "proxy_request_buffering", "proxy_cache", "proxy_intercept_errors"}
    for item in location.children:
        if item.name in replace or (item.name == "proxy_set_header" and item.args[0].lower() in CANONICAL):
            edits.append((item.start, item.end, ""))
    canonical = ["proxy_set_header Host $http_host;", "proxy_set_header X-Forwarded-Host $http_host;",
        "proxy_set_header X-Forwarded-For $remote_addr;", "proxy_set_header X-Real-IP $remote_addr;",
        "proxy_set_header X-Forwarded-Proto $scheme;", "proxy_set_header X-Forwarded-Port $server_port;",
        'proxy_set_header Forwarded "";', 'proxy_set_header Connection "";', "proxy_http_version 1.1;",
        "proxy_request_buffering on;", "proxy_cache off;", "proxy_intercept_errors off;"]
    edits.append((location.end - 1, location.end - 1, "\n        " + "\n        ".join(inherited + canonical) + "\n    "))
    return edits


def plan(site, listen, backend, nginx=Path("/etc/nginx")):
    nginx = nginx.resolve()
    changes, hostnames, application_ports = {}, set(), []
    for enabled in sorted((nginx / "sites-enabled").iterdir()):
        if not enabled.is_file():
            continue
        source = enabled.resolve()
        if not source.is_relative_to(nginx / "sites-available"):
            raise InstallError("Nginx enabled sites must resolve inside sites-available")
        text = read(source, 1024 * 1024).decode()
        if not re.search(r"(?m)^\s*server_name\s+[^;]*\b" + re.escape(site) + r"(?:\s|;)", text):
            continue
        servers = parse(text)
        if any(item.name != "server" or site not in names(item) for item in servers):
            raise InstallError("selected Nginx file must contain only this site's server blocks")
        edits = []
        for server in servers:
            hostnames.update(names(server))
            port = public_port(server)
            returns = server.named("return")
            if port == 80 and not server.named("location") and len(returns) == 1 and len(returns[0].args) == 2 and returns[0].args[0] in ("301", "308") and returns[0].args[1] in (f"https://{site}$request_uri", "https://$host$request_uri", "https://$server_name$request_uri"):
                continue
            application_ports.append(port)
            edits.extend(route_edits(server, text, listen, backend))
        for start, end, replacement in sorted(edits, reverse=True):
            text = text[:start] + replacement + text[end:]
        changes[source] = text.encode()
    if not application_ports or len(application_ports) > 2 or len(set(application_ports)) != len(application_ports):
        raise InstallError("need one selected Nginx HTTP and/or HTTPS application server")
    return {"site": site, "hosts": sorted(hostnames), "public_port": max(application_ports),
            "web_server": "nginx", "changes": changes}
