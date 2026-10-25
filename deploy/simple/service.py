"""Local administration and website probes; credentials never enter argv or logs."""
import http.client
import json
from pathlib import Path
import socket
import ssl
import time

from common import InstallError, read, run


def api(port, token, method, path, body=None, timeout=960):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers={
            "Authorization": "Bearer " + token, "Content-Type": "application/json"})
        response = connection.getresponse()
        data = response.read(64 * 1024 * 1024 + 1)
        if response.status != 200 or len(data) > 64 * 1024 * 1024:
            raise InstallError(f"Filtr admin request failed ({response.status}); inspect its service log")
        return json.loads(data) if data else None
    finally:
        connection.close()


def wait_admin(port, token):
    for _ in range(60):
        try:
            return api(port, token, "GET", "/v1/status", timeout=2)
        except (OSError, http.client.HTTPException):
            time.sleep(0.25)
    raise InstallError("Filtr service did not become responsive")


def probe(site, port, path, ca_file=None):
    if port == 443:
        connection = http.client.HTTPSConnection(site, port, timeout=15,
                                                context=ssl.create_default_context(cafile=ca_file))
    else:
        connection = http.client.HTTPConnection(site, port, timeout=15)
    # Connect locally while retaining the site's TLS SNI and certificate validation.
    connection._create_connection = lambda address, timeout, source_address=None: socket.create_connection(
        ("127.0.0.1", port), timeout, source_address)
    try:
        connection.request("GET", path, headers={"Host": site, "Connection": "close"})
        response = connection.getresponse()
        response.read(65536)
        return response.status
    finally:
        connection.close()


def check_web_server(web_server):
    if web_server not in ("apache", "nginx"):
        raise InstallError("unsupported saved web server")
    run(["nginx", "-t"] if web_server == "nginx" else ["apache2ctl", "configtest"])


def nginx_workers():
    master = int(read("/run/nginx.pid", 64).strip())
    children = read(f"/proc/{master}/task/{master}/children", 65536).split()
    active = set()
    for child in children:
        pid = int(child)
        try:
            with Path(f"/proc/{pid}/cmdline").open("rb") as stream:
                title = stream.read(1024)
        except (FileNotFoundError, ProcessLookupError):
            continue
        if b"nginx: worker process" in title and b"shutting down" not in title:
            active.add(pid)
    return active


def reload_web_server(web_server):
    if web_server not in ("apache", "nginx"):
        raise InstallError("unsupported saved web server")
    before = nginx_workers() if web_server == "nginx" else set()
    if web_server == "nginx" and not before:
        raise InstallError("cannot identify active Nginx workers using its standard pid file")
    run(["systemctl", "reload", "nginx" if web_server == "nginx" else "apache2"])
    if web_server == "nginx":
        for _ in range(100):
            active = nginx_workers()
            if active and not active.intersection(before):
                return
            time.sleep(0.1)
        raise InstallError("Nginx workers did not adopt the reload; inspect its service log")


def confirm_flow(admin_port, token, site, public_port, path, ca_file=None):
    # Nginx/Apache graceful reload commands can return before new workers accept.
    before = api(admin_port, token, "GET", "/v1/status")["counters"]
    for _ in range(40):
        status = probe(site, public_port, path, ca_file)
        current = api(admin_port, token, "GET", "/v1/status")
        after = current["counters"]
        blocked = current["traffic"]["effective"] == "blocked"
        confirmed = (status == 403 and after["blocked"] > before["blocked"] if blocked
                     else 200 <= status < 400 and after["proxied"] > before["proxied"])
        if confirmed:
            return status, blocked
        time.sleep(0.1)
    raise InstallError(f"website health check did not traverse Filtr successfully (HTTP {status})")


def unit(web_server="apache"):
    dependency = "nginx.service" if web_server == "nginx" else "apache2.service"
    return ("""[Unit]
Description=Filtr simple mode HTTP firewall
After=network-online.target WEB_SERVER
Wants=network-online.target

[Service]
Type=simple
User=filtr-simple
Group=filtr-simple
EnvironmentFile=/etc/filtr/filtr.env
ExecStart=/usr/local/bin/filtr
WorkingDirectory=/var/lib/filtr
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/filtr
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
""".replace("WEB_SERVER", dependency)).encode()
