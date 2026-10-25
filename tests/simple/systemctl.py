#!/usr/bin/python3
"""Container-only systemd adapter. Apache and Filtr are real processes."""
import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
import sys

args = sys.argv[1:]
if args == ["is-active", "--quiet", "example.service"]:
    sys.exit(0 if Path("/tmp/node-app.pid").exists() else 1)
if args == ["is-active", "--quiet", "nginx"]:
    sys.exit(0 if Path("/run/nginx.pid").exists() else 1)
if len(args) == 4 and args[:2] == ["show", "example.service"] and args[3] == "--value":
    if args[2] == "--property=MainPID":
        print(Path("/tmp/node-app.pid").read_text().strip())
        sys.exit(0)
    if args[2] == "--property=WorkingDirectory":
        print("/srv/app")
        sys.exit(0)
if args == ["reload", "nginx"]:
    if Path("/tmp/fail-reload-once").exists():
        Path("/tmp/fail-reload-once").unlink()
        sys.exit(1)
    sys.exit(subprocess.call(["nginx", "-s", "reload"]))
if args == ["is-active", "--quiet", "apache2"]:
    sys.exit(0 if Path("/var/run/apache2/apache2.pid").exists() else 1)
if args == ["daemon-reload"]:
    sys.exit(0)
if args == ["reload", "apache2"]:
    if Path("/tmp/fail-reload-once").exists():
        Path("/tmp/fail-reload-once").unlink()
        sys.exit(1)
    if Path("/tmp/block-before-reload").exists():
        import http.client
        Path("/tmp/block-before-reload").unlink()
        config = dict((line.split("=", 1)[0], json.loads(line.split("=", 1)[1]))
                      for line in Path("/etc/filtr/filtr.env").read_text().splitlines())
        client = http.client.HTTPConnection("127.0.0.1", 9090)
        client.request("POST", "/v1/traffic", body=json.dumps({"mode": "block_all", "reason": "Installer safety test"}),
                       headers={"Authorization": "Bearer " + config["FILTR_ADMIN_TOKEN"], "Content-Type": "application/json"})
        assert client.getresponse().status == 200
        client.close()
    sys.exit(subprocess.call(["apache2ctl", "graceful"]))
if args == ["start", "filtr-simple.service"]:
    env = {"PATH": "/usr/bin:/bin", "RUST_LOG": "filtr=info"}
    for line in Path("/etc/filtr/filtr.env").read_text().splitlines():
        key, value = line.split("=", 1)
        env[key] = json.loads(value)
    user = pwd.getpwnam("filtr-simple")
    def demote():
        os.setgroups([])
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)
    with open("/tmp/filtr-service.log", "wb") as log:
        process = subprocess.Popen(["/usr/local/bin/filtr"], env=env, cwd="/var/lib/filtr",
                                   stdout=log, stderr=log, preexec_fn=demote, start_new_session=True)
    Path("/tmp/filtr.pid").write_text(str(process.pid))
    sys.exit(0)
if args == ["stop", "filtr-simple.service"]:
    pid = Path("/tmp/filtr.pid")
    if pid.exists():
        try:
            os.kill(int(pid.read_text()), signal.SIGTERM)
        except ProcessLookupError:
            pass
        pid.unlink()
    sys.exit(0)
sys.exit("unsupported systemctl fixture operation")
