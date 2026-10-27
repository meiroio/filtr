#!/usr/bin/env python3
"""Check an existing Docker proxy without uploads, refreshes or policy changes."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent.parent
ADMIN_GET = r'''
printf 'header = "Authorization: Bearer %s"\n' "$FILTR_ADMIN_TOKEN" |
  curl --config - --noproxy '*' --silent --show-error --max-time 15 \
    --write-out '\n%{http_code}' "http://127.0.0.1:9090$1"
'''
ADMIN_REQUEST = r'''
request_path=$1
request_method=$2
request_body=
umask 077
trap 'if [ -n "$request_body" ]; then rm -f -- "$request_body"; fi' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
if [ "$request_method" = POST ]; then
  request_body=$(mktemp /data/.filtr-demo.XXXXXX)
  cat > "$request_body"
fi
set -- --config - --noproxy '*' --silent --show-error --max-time 120 \
  --write-out '\n%{http_code}' --request "$request_method" \
  "http://127.0.0.1:9090$request_path"
if [ -n "$request_body" ]; then
  set -- "$@" --header 'Content-Type: application/json' --data-binary "@$request_body"
fi
printf 'header = "Authorization: Bearer %s"\n' "$FILTR_ADMIN_TOKEN" | curl "$@"
'''


def origin(value):
    url = urlsplit(value)
    if (url.scheme not in ["http", "https"] or not url.hostname or url.username
            or url.password or url.query or url.fragment or url.path not in ["", "/"]):
        raise argparse.ArgumentTypeError(
            "URL must be an HTTP(S) origin without credentials, path or query")
    return value.rstrip("/")


def command(args, timeout=25):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}); check Docker/curl connectivity")
    return result.stdout.rstrip("\n")


def admin_request(container, path, output_file, body_file=None):
    """Keep credentials inside Docker and save admin responses privately."""
    request = ["docker", "exec", "-i", container, "sh", "-ec", ADMIN_REQUEST, "sh", path,
               "POST" if body_file is not None else "GET"]
    with (body_file.open("rb") if body_file is not None else open(os.devnull, "rb")) as source:
        result = subprocess.run(request, stdin=source, capture_output=True, timeout=130)
    if result.returncode:
        raise RuntimeError(f"Docker admin request failed ({result.returncode}); check Docker/curl connectivity")
    body, code = result.stdout.decode("utf-8").rstrip("\n").rsplit("\n", 1)
    output_file.write_text(body + "\n" if body else "null\n")
    return int(code), json.loads(body) if body else None


def admin(container, path, output):
    response = command(["docker", "exec", container, "sh", "-ec", ADMIN_GET, "sh", path])
    body, code = response.rsplit("\n", 1)
    if code != "200":
        raise RuntimeError(f"Admin GET {path}: expected 200, received {code}")
    data = json.loads(body) if body else None
    (output / (path.rsplit("/", 1)[-1] + ".json")).write_text(
        body + "\n" if body else "null\n")
    return data


def probe(url, path, expected, body_file):
    code = command([
        "curl", "--noproxy", "*", "--silent", "--show-error", "--max-time", "15",
        "--http1.1", "--path-as-is", "--output", str(body_file),
        "--write-out", "%{http_code}", url + path,
    ])
    passed = code == str(expected)
    # Distinguish Filtr's path rejection from an origin's unrelated 403.
    if passed and expected == 403:
        passed = json.loads(body_file.read_text()).get("error") == "restricted-target"
    print(f"{'PASS' if passed else 'FAIL'} GET {path}: HTTP {code} (expected {expected})")
    return {"path": path, "http_status": int(code), "passed": passed}


def check(args, output):
    version = command(["docker", "exec", args.container, "filtr", "--version"])
    print(f"Container: {args.container}; {version}")
    print(f"Public listener: {args.url}")
    for path in ["/livez", "/healthz"]:
        admin(args.container, path, output)
        print(f"PASS admin GET {path}: HTTP 200")

    # A 404 identifies older local builds without attempting any POST.
    traffic = command([
        "docker", "exec", args.container, "sh", "-ec", ADMIN_GET, "sh", "/v1/traffic",
    ])
    traffic_body, traffic_code = traffic.rsplit("\n", 1)
    if traffic_code not in ["200", "404"]:
        raise RuntimeError(f"Admin GET /v1/traffic: unexpected HTTP {traffic_code}")
    if traffic_code == "200":
        (output / "traffic.json").write_text(traffic_body + "\n")
    else:
        print("NOTE /v1/traffic is unavailable on this build; no traffic controls tested")

    before = admin(args.container, "/v1/status", output)
    (output / "status.json").rename(output / "status-before.json")
    remediation = admin(args.container, "/v1/remediation", output)
    if not before.get("ready") or remediation.get("quarantined"):
        raise RuntimeError("Policy is not ready or traffic is fully blocked; inspect the saved reports")

    cases = [("/", 200), ("/.env", 403), ("/.git/config", 403),
             ("/%2e%2e/etc/passwd", 403), ("/", 200)]
    probes = [probe(args.url, path, code, output / f"public-{i}.body")
              for i, (path, code) in enumerate(cases)]
    after = admin(args.container, "/v1/status", output)
    (output / "status.json").rename(output / "status-after.json")
    delta = {key: after["counters"][key] - before["counters"][key]
             for key in ["seen", "proxied", "blocked", "upstream_errors"]}
    counters_ok = (delta["seen"] >= 5 and delta["proxied"] >= 2
                   and delta["blocked"] >= 3 and delta["upstream_errors"] == 0)
    print(f"{'PASS' if counters_ok else 'FAIL'} counter changes: {json.dumps(delta, sort_keys=True)}")
    ai_unchanged = before["policy"].get("ai") == after["policy"].get("ai")
    print(f"Installed AI review metadata unchanged: {str(ai_unchanged).lower()}")
    print("No uploads, previews, refreshes, traffic-mode changes or restarts were requested.")
    policy = after["policy"]
    passed = all(p["passed"] for p in probes) and counters_ok
    return {
        "checked_at": datetime.now(timezone.utc).isoformat(), "passed": passed,
        "container": args.container, "version": version, "url": args.url,
        "traffic_api_available": traffic_code == "200", "probes": probes,
        "counter_delta": delta, "ai_metadata_unchanged": ai_unchanged,
        "components": len(policy.get("components", [])),
        "ai_status": policy.get("ai", {}).get("status"),
        "remediation_summary": remediation.get("summary"),
        "quarantined": remediation.get("quarantined"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", default="filtr-betterpipes-filtr-1")
    parser.add_argument("--url", type=origin, default="http://127.0.0.1:18080")
    parser.add_argument("--report-root", type=Path, default=ROOT / "data/demo-check")
    args = parser.parse_args()
    os.umask(0o077)
    args.report_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = Path(tempfile.mkdtemp(prefix=f"check-{stamp}-", dir=args.report_root)).resolve()
    print(f"Private reports: {output}")
    try:
        result = check(args, output)
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"FAIL {error}")
        return 1
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"{'PASS' if result['passed'] else 'FAIL'} overall")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
