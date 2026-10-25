"""End-to-end packaging/discovery/proxy/rollback checks on an isolated Apache host."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time


def command(*args, success=True):
    result = subprocess.run(args, capture_output=True, text=True)
    assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
    return result


def config_snapshot():
    result = {}
    for path in Path("/etc/apache2").rglob("*"):
        if path.is_file():
            result[str(path)] = (os.readlink(path) if path.is_symlink() else hashlib.sha256(path.read_bytes()).hexdigest())
    return result


def request(path, headers=None, https=None, method="GET", body=None):
    import ssl
    if https is None:
        https = not os.environ.get("TEST_HTTP_ONLY")
    context = ssl.create_default_context(cafile="/tmp/site.crt")
    connection = (http.client.HTTPSConnection("localhost", 443, context=context, timeout=5)
                  if https else http.client.HTTPConnection("127.0.0.1", 80, timeout=5))
    connection.request(method, path, body=body, headers={"Host": "localhost", **(headers or {})})
    response = connection.getresponse()
    body = response.read()
    result = response.status, {k.lower(): v for k, v in response.getheaders()}, body
    connection.close()
    return result


def main():
    package = next(Path("/release").glob("*.tar.gz"))
    Path("/package").mkdir()
    with tarfile.open(package) as archive:
        archive.extractall("/package", filter="data") if sys.version_info >= (3, 12) else archive.extractall("/package")
    command("sh", "-c", "cd /package && sha256sum -c SHA256SUMS")
    command("a2enmod", "ssl")
    if os.environ.get("TEST_PHP") == "fpm":
        module = next(Path("/etc/apache2/mods-enabled").glob("php*.load")).stem
        version = module.removeprefix("php")
        command("a2dismod", module)
        command("a2enmod", "proxy_fcgi", "setenvif")
        command("a2enconf", f"php{version}-fpm")
        Path("/run/php").mkdir(exist_ok=True)
        command(f"/usr/sbin/php-fpm{version}", "--daemonize")
    command("a2dissite", "000-default")
    command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "/tmp/site.key",
            "-out", "/tmp/site.crt", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost")
    root = Path("/var/www/simple")
    root.mkdir()
    (root / "index.php").write_text('''<?php
header('Content-Type: application/json');
echo json_encode(['host'=>$_SERVER['HTTP_HOST'], 'https'=>$_SERVER['HTTPS'] ?? '',
'client'=>$_SERVER['REMOTE_ADDR'], 'forwarded'=>$_SERVER['HTTP_X_FORWARDED_FOR'] ?? '',
'scheme'=>$_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '']);
''')
    (root / "login.php").write_text('''<?php
$secure = ($_SERVER['HTTPS'] ?? '') === 'on';
setcookie('session', 'test', ['secure'=>$secure, 'httponly'=>true]);
header('Location: '.($secure ? 'https' : 'http').'://'.$_SERVER['HTTP_HOST'].'/dashboard');
''')
    (root / "upload.php").write_text('''<?php
if (!isset($_FILES['file'])) { http_response_code(400); exit; }
echo file_get_contents($_FILES['file']['tmp_name']);
''')
    challenge = root / ".well-known/acme-challenge"
    challenge.mkdir(parents=True)
    (challenge / "test-token").write_text("challenge-token")
    # Composer installed metadata is read, never executed. Keep exact installed version.
    (root / "vendor/composer").mkdir(parents=True)
    (root / "vendor/composer/installed.json").write_text(json.dumps({"packages": [
        {"name": "example/library", "version": "1.2.3"}]}))
    site = Path("/etc/apache2/sites-available/simple.conf")
    site.write_text('''<VirtualHost *:80>
ServerName localhost
Redirect permanent / https://localhost/
</VirtualHost>
<VirtualHost *:443>
ServerName localhost
DocumentRoot /var/www/simple
SSLEngine on
SSLCertificateFile /tmp/site.crt
SSLCertificateKeyFile /tmp/site.key
ErrorLog ${APACHE_LOG_DIR}/simple-error.log
<Directory /var/www/simple>
Require all granted
AllowOverride All
</Directory>
</VirtualHost>
''')
    command("a2ensite", "simple")
    if os.environ.get("TEST_HTTP_ONLY"):
        site.write_text('''<VirtualHost *:80>
ServerName localhost
DocumentRoot /var/www/simple
<Directory /var/www/simple>
Require all granted
AllowOverride All
</Directory>
</VirtualHost>
''')
    command("apache2ctl", "start")
    time.sleep(0.5)
    assert request("/index.php")[0] == 200
    installer = "/package/filtr-install"
    arguments = ["--site", "localhost", "--ca-file", "/tmp/site.crt"]
    before = config_snapshot()
    dry = json.loads(command(installer, *arguments, "--dry-run").stdout)
    assert dry["dry_run"] and dry["ai_calls"] == 0 and dry["components"] > 100
    assert config_snapshot() == before and not Path("/var/lib/filtr-simple").exists()
    command(installer, *arguments, "--discover-only", "/tmp/discovered.json")
    sbom = json.loads(Path("/tmp/discovered.json").read_text())
    assert any(c.get("purl", "").startswith("pkg:composer/example/library@1.2.3") for c in sbom["components"])
    assert any(c["name"].startswith("libapache2-mod-php") for c in sbom["components"])
    if os.environ.get("TEST_FAILURE") == "reload":
        Path("/tmp/fail-reload-once").touch()
        command(installer, *arguments, success=False)
        assert config_snapshot() == before
        assert request("/index.php")[0] == 200
        print("PASS automatic rollback after Apache reload failure")
        return
    if os.environ.get("TEST_BLOCKED"):
        Path("/tmp/block-before-reload").touch()
    installed = json.loads(command(installer, *arguments).stdout)
    assert installed["installed"]
    assert Path("/etc/apache2/conf-enabled/filtr-simple-backend.conf").stat().st_mode & 0o777 == 0o600
    if os.environ.get("TEST_BLOCKED"):
        assert installed["emergency_blocked"] and request("/")[0] == 403
        sys.path.insert(0, "/package/simple")
        import service
        config = dict((line.split("=", 1)[0], json.loads(line.split("=", 1)[1]))
                      for line in Path("/etc/filtr/filtr.env").read_text().splitlines())
        service.api(9090, config["FILTR_ADMIN_TOKEN"], "POST", "/v1/traffic",
                    json.dumps({"mode": "filter", "reason": "Test targeted recovery"}).encode())
    status, _, body = request("/index.php", {"X-Forwarded-Proto": "http", "X-Forwarded-For": "192.0.2.99",
                                            "X-Forwarded-Host": "evil.example"})
    details = json.loads(body)
    secure = not os.environ.get("TEST_HTTP_ONLY")
    scheme = "https" if secure else "http"
    assert status == 200 and details["host"] == "localhost" and details["https"] == ("on" if secure else ""), details
    assert details["scheme"] == scheme and details["client"] == "127.0.0.1", details
    # mod_remoteip consumes X-Forwarded-For after applying it to REMOTE_ADDR.
    assert details["forwarded"] in ("", "127.0.0.1"), details
    status, headers, _ = request("/login.php")
    assert status == 302 and headers["location"] == f"{scheme}://localhost/dashboard"
    assert ("secure" in headers["set-cookie"].lower()) == secure
    multipart = b'--test-boundary\r\nContent-Disposition: form-data; name="file"; filename="test.txt"\r\nContent-Type: text/plain\r\n\r\nhello upload\r\n--test-boundary--\r\n'
    upload_headers = {"Content-Type": "multipart/form-data; boundary=test-boundary"}
    assert request("/upload.php", upload_headers, method="POST", body=multipart)[2] == b"hello upload"
    # Existing NUL-body protection remains active, including inside binary uploads.
    assert request("/upload.php", upload_headers, method="POST", body=multipart.replace(b"hello upload", b"binary\0payload"))[0] == 403
    assert request("/.well-known/acme-challenge/test-token")[2] == b"challenge-token"
    assert request("/", {"Host": "evil.example"})[0] == 400
    assert request("/.env")[0] == 403
    assert request("/")[0] == 200
    assert request("/", https=False)[0] == (301 if secure else 200)
    command("systemd-analyze", "verify", "/etc/systemd/system/filtr-simple.service")
    report = json.loads(Path("/var/lib/filtr-simple/last-upload.json").read_text())
    assert report["inventory"]["gaps"]
    refreshed = json.loads(command("/usr/local/sbin/filtr-simple", "--refresh-inventory").stdout)
    assert refreshed["components"] > 100 and refreshed["unchanged"]
    # Refresh changes mutable policy/cache data, not the rollback-managed routing files.
    command("/usr/local/sbin/filtr-simple", "--rollback")
    assert config_snapshot() == before
    assert request("/index.php")[0] == 200
    print("PASS discovery, zero-write dry-run, HTTPS/host/client anti-spoofing, PHP redirect/cookie, blocking, refresh, explicit rollback")


try:
    main()
except Exception:
    for path in (Path("/tmp/filtr-service.log"), Path("/var/log/apache2/simple-error.log")):
        if path.is_file():
            print(path.read_text()[-4000:], file=sys.stderr)
    raise
