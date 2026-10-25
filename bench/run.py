#!/usr/bin/env python3
"""Compare the published proxy with the demo origin on an isolated Docker network."""
import argparse
from datetime import datetime, timezone
import functools
import json
import os
from pathlib import Path
import secrets
import statistics
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
BASELINE_IMAGE = "ghcr.io/meiroio/filtr:0.1.0@sha256:5333b0a0101a08ee902c90e68bc36fa44eba1ec9948be050f65648837a52bc03"


def command(args, *, prefix=(), **kwargs):
    result = subprocess.run([*prefix, *args], text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"Benchmark command failed ({result.returncode}): {result.stderr[-2000:]}")
    return result.stdout


def api(compose, path, upload=False, service="filtr"):
    body = " --data-binary @/data/candidate.json -H 'Content-Type: application/json'" if upload else ""
    script = (
        'printf \'header = "Authorization: Bearer %s"\\n\' "$FILTR_ADMIN_TOKEN" | '
        "curl --config - --noproxy '*' --fail --silent --show-error --max-time 15 "
        f"http://127.0.0.1:9090{path}{body}"
    )
    return json.loads(compose(["exec", "-T", service, "sh", "-ec", script]))


def install_policy(compose, service="filtr"):
    for _ in range(75):
        try:
            compose(["exec", "-T", service, "filtr-probe", "live"])
            break
        except RuntimeError:
            time.sleep(0.2)
    else:
        raise RuntimeError("Filtr did not start within 15 seconds")
    fixture = (ROOT / "examples/sbom.cdx.json").read_text()
    compose(["exec", "-T", service, "sh", "-ec", "cat > /data/candidate.json"], input=fixture)
    api(compose, "/v1/sbom", upload=True, service=service)
    compose(["exec", "-T", service, "filtr-probe", "ready"])
    payload = '{"data":"' + "a" * (65536 - 11) + '"}'
    compose(["exec", "-T", service, "sh", "-ec", "cat > /data/body.json"], input=payload)
    response = json.loads(compose([
        "exec", "-T", service, "curl", "--noproxy", "*", "--fail", "--silent", "--show-error",
        "-H", "Content-Type: application/json", "--data-binary", "@/data/body.json",
        "http://127.0.0.1:8080/bench",
    ]))
    if response.get("body_bytes") != 65536:
        raise RuntimeError("Preflight did not forward the complete request body")
    status = api(compose, "/v1/status", service=service)
    if status["policy"]["ai"]["status"] != "not_configured":
        raise RuntimeError("Benchmark must run without AI credentials")
    return status


def load(compose, workload, duration, connections):
    name, target, extra, expected = workload
    result = json.loads(compose([
        "run", "--rm", "--no-deps", "-T", "loadgen", "--no-tui",
        "--output-format", "json", "--http-version", "1.1", "--worker-threads", "2",
        "-c", str(connections), "-z", f"{duration}s", "-w", "-t", "5s",
        "--host", "bench.example", *extra, f"http://{target}/bench",
    ]))
    codes = result["statusCodeDistribution"]
    if result["errorDistribution"] or set(codes) != {str(expected)} or not sum(codes.values()):
        raise RuntimeError(f"Unexpected responses for {name}: {codes}; {result['errorDistribution']}")
    return result


def summarize(runs):
    return {
        "requests_per_second": statistics.median(r["summary"]["requestsPerSec"] for r in runs),
        "p50_ms": 1000 * statistics.median(r["latencyPercentiles"]["p50"] for r in runs),
        "p99_ms": 1000 * statistics.median(r["latencyPercentiles"]["p99"] for r in runs),
        "rps_min": min(r["summary"]["requestsPerSec"] for r in runs),
        "rps_max": max(r["summary"]["requestsPerSec"] for r in runs),
        "responses": sum(sum(r["statusCodeDistribution"].values()) for r in runs),
    }


def measure(compose, args, output):
    post = ["-m", "POST", "-T", "application/json", "-D"]
    workloads = [
        ("direct_get", "origin:3000", [], 200),
        ("filtr_get", "filtr:8080", [], 200),
        ("direct_post_1k", "origin:3000", [*post, "/input/body-1024.json"], 200),
        ("filtr_post_1k", "filtr:8080", [*post, "/input/body-1024.json"], 200),
        ("direct_post_64k", "origin:3000", [*post, "/input/body-65536.json"], 200),
        ("filtr_post_64k", "filtr:8080", [*post, "/input/body-65536.json"], 200),
        ("filtr_block", "filtr:8080", ["-H", "X-Test: ${jndi:ldap://example.invalid/test}"], 403),
    ]
    if args.baseline_image:
        comparison = []
        for name, target, extra, expected in workloads:
            if name.startswith("filtr_"):
                comparison.append((name.replace("filtr_", "baseline_", 1), "baseline:8080", extra, expected))
            comparison.append((name, target, extra, expected))
        workloads = comparison
    runs = {w[0]: [] for w in workloads}
    for workload in workloads:
        load(compose, workload, args.warmup, args.connections)
    for repeat in range(args.repeats):
        for workload in workloads[::1 if repeat % 2 == 0 else -1]:
            print(f"Round {repeat + 1}/{args.repeats}: {workload[0]}", flush=True)
            result = load(compose, workload, args.duration, args.connections)
            runs[workload[0]].append(result)
            (output / f"{workload[0]}-{repeat + 1}.json").write_text(json.dumps(result, indent=2) + "\n")
    return {name: summarize(values) for name, values in runs.items()}


def execute(args, output, input_dir):
    env = dict(os.environ, FILTR_ADMIN_TOKEN=secrets.token_hex(64), FILTR_BENCH_INPUT=str(input_dir),
               FILTR_BENCH_IMAGE=args.image, FILTR_BENCH_BASELINE_IMAGE=args.baseline_image or BASELINE_IMAGE)
    # Compose receives only explicitly declared container variables. Never load the project's .env.
    compose = ["docker", "compose", "--env-file", "/dev/null", "--project-name",
               f"filtr-bench-{secrets.token_hex(4)}", "--file", str(ROOT / "bench/compose.yaml")]
    compose = functools.partial(command, prefix=compose, env=env)
    try:
        print("Building benchmark tools and demo origin; starting the selected Filtr image", flush=True)
        (output / "build.log").write_text(compose(["build", "origin", "loadgen"]))
        compose(["up", "--detach", "origin", "filtr", *(["baseline"] if args.baseline_image else [])])
        policy = install_policy(compose)
        baseline = install_policy(compose, "baseline") if args.baseline_image else None
        before = policy["counters"]
        results = measure(compose, args, output)
        after = api(compose, "/v1/status")
        if after["counters"]["upstream_errors"] != 0:
            raise RuntimeError("Upstream errors invalidate this benchmark")
        comparison = None
        if baseline:
            baseline_after = api(compose, "/v1/status", service="baseline")
            if baseline_after["counters"]["upstream_errors"] != 0:
                raise RuntimeError("Baseline upstream errors invalidate this benchmark")
            comparison = {"counters_before": baseline["counters"],
                          "counters_after": baseline_after["counters"],
                          "ai_status": baseline_after["policy"]["ai"]["status"]}
        return {"results": results, "counters_before": before, "counters_after": after["counters"],
                "ai_status": after["policy"]["ai"]["status"],
                "active_rules": policy["policy"]["active_rules"], "comparison_baseline": comparison}
    finally:
        compose(["down", "--volumes", "--remove-orphans"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=int, default=15)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--connections", type=int, default=64)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--host-description", default="unspecified")
    parser.add_argument("--image", default=BASELINE_IMAGE, help="Filtr image to measure")
    parser.add_argument("--baseline-image", help="Also measure this Filtr image, alternating each workload pair")
    parser.add_argument("--output", type=Path, default=ROOT / "data/benchmark")
    args = parser.parse_args()
    if min(args.duration, args.repeats, args.connections, args.warmup) < 1:
        parser.error("duration, repeats, connections and warmup must be positive")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="filtr-bench-") as temporary:
        input_dir = Path(temporary)
        input_dir.chmod(0o755)
        for size in (1024, 65536):
            payload = input_dir / f"body-{size}.json"
            payload.write_bytes(b'{"data":"' + b"a" * (size - 11) + b'"}')
            payload.chmod(0o644)
        result = execute(args, output, input_dir)
    result["setup"] = {"recorded_at": datetime.now(timezone.utc).isoformat(),
                       "duration_seconds": args.duration, "repeats": args.repeats,
                       "connections": args.connections, "warmup_seconds": args.warmup,
                       "host": args.host_description, "cpu_limit_per_container": 2,
                       "docker": json.loads(command(["docker", "info", "--format",
                           '{"version":"{{.ServerVersion}}","architecture":"{{.Architecture}}",'
                           '"cpus":{{.NCPU}},"memory_bytes":{{.MemTotal}}}'])),
                       "source_revision": command(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).strip(),
                       "source_dirty": bool(command(["git", "-C", str(ROOT), "status", "--porcelain"])),
                       "image": args.image,
                       "baseline_image": args.baseline_image,
                       "baseline_image_id": command(["docker", "image", "inspect", args.baseline_image, "--format", "{{.Id}}"]).strip() if args.baseline_image else None,
                       "image_id": command(["docker", "image", "inspect", args.image, "--format", "{{.Id}}"]).strip(),
                       "load_generator": "oha 1.16.0"}
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["results"], indent=2), flush=True)


if __name__ == "__main__":
    main()
