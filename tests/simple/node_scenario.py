"""Real Express + nginx/Apache integration. No provider credentials or AI calls."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import ssl
import subprocess
import sys
import tarfile
import time


def command(*args, success=True):
    result = subprocess.run(args, capture_output=True, text=True)
    assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
    return result


def snapshot(base):
    return {str(path): os.readlink(path) if path.is_symlink() else hashlib.sha256(path.read_bytes()).hexdigest()
            for path in Path(base).rglob("*") if path.is_file()}


def request(path="/", headers=None):
    client = http.client.HTTPSConnection("localhost", 443, context=ssl.create_default_context(cafile="/tmp/site.crt"), timeout=10)
    client.request("GET", path, headers={"Host": "localhost", **(headers or {})})
    response = client.getresponse()
    result = response.status, {key.lower(): value for key, value in response.getheaders()}, response.read()
    client.close()
    return result


def main():
    Path("/package").mkdir()
    with tarfile.open(next(Path("/release").glob("*.tar.gz"))) as archive:
        archive.extractall("/package", filter="data") if sys.version_info >= (3, 12) else archive.extractall("/package")
    command("sh", "-c", "cd /package && sha256sum -c SHA256SUMS")
    application = Path("/srv/app/server.js")
    application.write_text('''const express = require('express');
const app = express();
app.set('trust proxy', 'loopback');
app.get('/redirect', (req, res) => res.redirect(`${req.protocol}://${req.get('host')}/destination`));
app.get('/cookie', (req, res) => { res.cookie('session','test',{secure:req.secure,httpOnly:true}); res.send('ok'); });
app.get('/.env', (req,res) => res.send('must be filtered'));
app.get('/', (req, res) => res.json({hostname:req.hostname, host:req.get('host'), scheme:req.protocol, secure:req.secure, ip:req.ip}));
app.listen(3000, process.env.TEST_PUBLIC_BIND ? '0.0.0.0' : '127.0.0.1');
''')
    user = pwd.getpwnam("app")
    env = {"PATH": "/usr/bin:/bin"}
    if os.environ.get("TEST_PUBLIC_BIND"):
        env["TEST_PUBLIC_BIND"] = "1"
    with open("/tmp/node-app.log", "wb") as log:
        node = subprocess.Popen(["/usr/local/bin/node", str(application)], cwd="/srv/app", env=env,
                                user=user.pw_uid, group=user.pw_gid, extra_groups=[], stdout=log, stderr=log)
    Path("/tmp/node-app.pid").write_text(str(node.pid))
    Path("/srv/app/must-not-load.js").write_text("require('fs').writeFileSync('/tmp/unsafe-startup-hook','loaded');")
    os.environ["NODE_OPTIONS"] = "--require /srv/app/must-not-load.js"
    time.sleep(0.5)
    assert node.poll() is None
    command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "/tmp/site.key",
            "-out", "/tmp/site.crt", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost")
    web_server = os.environ.get("TEST_WEB_SERVER", "nginx")
    if web_server == "nginx":
        Path("/etc/nginx/sites-enabled/default").unlink(missing_ok=True)
        site = Path("/etc/nginx/sites-available/node")
        site.write_text('''server {
listen 80;
server_name localhost;
return 301 https://$host$request_uri;
}
server {
listen 443 ssl;
server_name localhost;
ssl_certificate /tmp/site.crt;
ssl_certificate_key /tmp/site.key;
proxy_set_header X-Custom "retained header";
location / {
proxy_pass http://127.0.0.1:3000;
}
}
''')
        Path("/etc/nginx/sites-enabled/node").symlink_to(site)
        command("nginx")
        base = "/etc/nginx"
    else:
        command("a2enmod", "ssl", "proxy", "proxy_http")
        command("a2dissite", "000-default")
        site = Path("/etc/apache2/sites-available/node.conf")
        site.write_text('''<VirtualHost *:443>
ServerName localhost
SSLEngine on
SSLCertificateFile /tmp/site.crt
SSLCertificateKeyFile /tmp/site.key
ProxyPreserveHost On
ProxyPass / http://127.0.0.1:3000/
ProxyPassReverse / http://127.0.0.1:3000/
</VirtualHost>
''')
        command("a2ensite", "node")
        command("apache2ctl", "start")
        base = "/etc/apache2"
    time.sleep(0.5)
    assert request()[0] == 200
    original = snapshot(base)
    app_hash = hashlib.sha256(application.read_bytes()).hexdigest()
    arguments = ["--profile", "node-express", "--site", "localhost", "--app-service", "example.service",
                 "--web-server", web_server, "--ca-file", "/tmp/site.crt"]
    if os.environ.get("TEST_PUBLIC_BIND"):
        error = command("/package/filtr-install", *arguments, "--dry-run", success=False)
        assert "loopback" in error.stderr
        assert snapshot(base) == original and not Path("/var/lib/filtr-simple").exists()
        print("PASS publicly reachable Node origin rejected without changes")
        return
    plan = json.loads(command("/package/filtr-install", *arguments, "--dry-run").stdout)
    assert plan["profile"] == "node-express" and plan["ai_calls"] == 0
    assert plan["runtime_evidence"]["version"]
    assert not Path("/tmp/unsafe-startup-hook").exists()
    assert snapshot(base) == original and not Path("/var/lib/filtr-simple").exists()
    command("/package/filtr-install", *arguments, "--discover-only", "/tmp/real-node-sbom.json")
    sbom = json.loads(Path("/tmp/real-node-sbom.json").read_text())
    identities = {(c["name"], c.get("version")) for c in sbom["components"]}
    assert ("express", "5.1.0") in identities
    assert any(c.get("purl", "").startswith("pkg:generic/nodejs@") for c in sbom["components"])
    lock = json.loads(Path("/srv/app/package-lock.json").read_text())
    for relative, expected in lock["packages"].items():
        if relative:
            package = json.loads(Path("/srv/app", relative, "package.json").read_text())
            assert (package["name"], expected["version"]) in identities
    if os.environ.get("TEST_FAILURE"):
        Path("/tmp/fail-reload-once").touch()
        command("/package/filtr-install", *arguments, success=False)
        assert snapshot(base) == original and request()[0] == 200
        assert node.poll() is None and hashlib.sha256(application.read_bytes()).hexdigest() == app_hash
        print("PASS Node automatic rollback after reload failure; app/service unchanged")
        return
    result = json.loads(command("/package/filtr-install", *arguments).stdout)
    assert result["installed"]
    status, _, body = request(headers={"X-Forwarded-For": "192.0.2.99", "X-Forwarded-Proto": "http", "X-Forwarded-Host": "evil.example"})
    details = json.loads(body)
    assert status == 200 and details == {"hostname": "localhost", "host": "localhost", "scheme": "https", "secure": True, "ip": "127.0.0.1"}, details
    assert request("/redirect")[1]["location"] == "https://localhost/destination"
    assert "secure" in request("/cookie")[1]["set-cookie"].lower()
    assert request("/.env")[0] == 403
    assert request(headers={"Host": "evil.example"})[0] == 400
    assert node.poll() is None and hashlib.sha256(application.read_bytes()).hexdigest() == app_hash
    report = json.loads(Path("/var/lib/filtr-simple/last-upload.json").read_text())
    assert report["policy"]["ai"]["status"] == "not_configured"
    unchanged = json.loads(command("/usr/local/sbin/filtr-simple", "--refresh-inventory").stdout)
    assert unchanged["unchanged"]
    command("systemd-analyze", "verify", "/etc/systemd/system/filtr-simple.service")
    if os.environ.get("TEST_DIRECT_ROLLBACK"):
        command("python3", "-I", "-c", "import sys;sys.path.insert(0,'/package/simple');import main;sys.argv=['filtr-simple','--rollback'];main.main()")
    else:
        command("/usr/local/sbin/filtr-simple", "--rollback")
    assert snapshot(base) == original and request()[0] == 200 and node.poll() is None
    print(f"PASS {web_server}/Express: exact installed SBOM, live runtime, dry-run, HTTPS/host/IP anti-spoofing, cookie/redirect, filtering, zero-call refresh, rollback; app unchanged")


try:
    main()
except Exception:
    for path in (Path("/tmp/filtr-service.log"), Path("/tmp/node-app.log"), Path("/var/log/nginx/error.log")):
        if path.is_file():
            print(path.read_text()[-3000:], file=sys.stderr)
    raise
