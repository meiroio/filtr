#!/usr/bin/env python3
"""Two-tab recording: terminal slides in one tab, real HTTP requests in the other."""

import argparse
import curses
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import textwrap
import time

from check import ROOT, admin_request, command, origin


SLIDES = [
    ("WHY I BUILT IT", "Last week: vulnerability armageddon.", [
        "Patching Node and Bun in production.",
        "New issue. Investigate. Update. Deploy. Repeat.",
        "Keep the application available while we fix it.",
    ], "The reason Filtr exists."),
    ("WHAT FILTR DOES", "Time to patch. Less exposure.", [
        "HTTPS ingress  ->  FILTR  ->  Application",
        "SBOM  ->  AI research  ->  validated HTTP filters",
        "Inventory: dependencies, runtimes, OS packages, images.",
        "Findings without a supported filter stay advisory by default.",
    ], "Rust reverse proxy. API only."),
    ("LIVE DEMO / SWITCH TO TAB 2", "One request class. A changing inventory.", [
        "Vulnerable inventory: normal request passes; Brotli blocked.",
        "Patched inventory: the identical Brotli request passes.",
        "Real HTTP responses and a previously cached AI restriction.",
        "Inventory policy replay; running Bun remains patched.",
    ], "No exploit, image downgrade, new AI calls or filter bypass."),
    ("FROM FINDING TO FIXING", "Give the SRE agent a useful next step.", [
        "Webhook -> report -> upgrade actual artifacts",
        "Candidate SBOM -> cache-only preview -> deploy -> verify",
        "Preview keeps live policy unchanged. Missing reviews: unknown.",
        "Component reviews: one-day cache by default; refresh on expiry.",
    ], "The live replay uses cache-only previews and strict cache-only uploads."),
    ("WHY SIMPLE MODE EXISTS", "Built for Kubernetes. Useful beyond it.", [
        "KUBERNETES    Published images + deployment manifest",
        "SIMPLE MODE   Supported Debian / Ubuntu servers",
        "              Apache + PHP, or Node behind Nginx / Apache",
        "Prebuilt packages. Inventory discovery. Dry run. Rollback.",
    ], "Source and installation instructions on GitHub."),
    ("TRY IT / HELP IMPROVE IT", "github.com/meiroio/filtr", [
        "Start in a test environment with an accurate inventory.",
        "HTTP/1 MVP. AI can miss findings. Keep patching.",
        "Free for noncommercial use; commercial use needs permission.",
    ], "I'd love your feedback."),
]
PLAIN_BODY = b"Harmless compressed request body."
# Produced from PLAIN_BODY by node:zlib in patched Bun 1.4.4; no exploit payload.
BROTLI_BODY = bytes([27, 32, 0, 248, 197, 109, 108, 93, 223, 244, 92, 145, 94, 18,
                     100, 14, 82, 72, 65, 105, 132, 60, 7, 45, 245, 217, 105, 225,
                     75, 158, 88, 8])


def narration():
    script = (ROOT / "docs/video-script-en.md").read_text()
    sections = re.split(r"^## ", script, flags=re.M)[1:]
    if len(sections) != len(SLIDES):
        raise RuntimeError("The narration and terminal deck need the same number of sections")
    return [(s.splitlines()[0].split(" — ")[0],
             s.split("**Narration:**", 1)[1].split("**Final frame:**", 1)[0].strip("\n“”"))
            for s in sections]


def slide_lines(index, notes):
    timing, spoken = narration()[index]
    eyebrow, title, body, closing = SLIDES[index]
    lines = [("brand", f"F I L T R                                      {index + 1:02} / {len(SLIDES):02}"),
             ("muted", f"{timing}  /  {eyebrow}"), ("body", ""), ("title", title),
             ("body", "")]
    content = spoken.split("\n\n") if notes else body
    for paragraph in content:
        lines.extend([("body", paragraph), ("body", "")])
    lines.append(("muted", "SPEAKER NOTES / N returns to slide" if notes else closing))
    return lines


def draw(screen, index, notes):
    height, width = screen.getmaxyx()
    screen.erase()
    if width < 72 or height < 24:
        screen.addnstr(0, 0, "Enlarge terminal to at least 72 columns x 24 rows. Q quits.",
                       max(0, width - 1))
        screen.refresh()
        return
    content_width = min(width - 8, 92)
    left = (width - content_width) // 2
    styles = {"brand": curses.color_pair(1) | curses.A_BOLD,
              "title": curses.A_BOLD, "muted": curses.color_pair(2), "body": 0}
    row = 2
    for kind, paragraph in slide_lines(index, notes):
        for line in textwrap.wrap(paragraph, content_width) or [""]:
            if row >= height - 4:
                screen.addnstr(row, left, "Enlarge terminal to show remaining text.", content_width)
                break
            screen.addnstr(row, left, line, content_width, styles[kind])
            row += 1
        if row >= height - 4:
            break
    screen.addnstr(height - 2, left,
                   "Space / arrows: move   1-6: jump   N: notes   Q: quit", content_width,
                   curses.color_pair(2))
    screen.refresh()


def deck(screen, notes):
    curses.curs_set(0)
    screen.keypad(True)
    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
    index = 0
    while True:
        draw(screen, index, notes)
        key = screen.getch()
        if key in [ord("q"), ord("Q"), 27]:
            return
        if key in [ord("n"), ord("N")]:
            notes = not notes
        elif key in [curses.KEY_RIGHT, curses.KEY_DOWN, ord(" "), 10, 13]:
            index = min(index + 1, len(SLIDES) - 1)
        elif key in [curses.KEY_LEFT, curses.KEY_UP, curses.KEY_BACKSPACE, ord("b")]:
            index = max(index - 1, 0)
        elif ord("1") <= key <= ord("6"):
            index = key - ord("1")


def slides(args):
    if args.plain:
        for index in range(len(SLIDES)):
            print("\n".join(text for _, text in slide_lines(index, args.notes)))
            print("\n" + "-" * 72 + "\n")
        return 0
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RuntimeError("Interactive slides require a terminal; use --plain for text output")
    curses.wrapper(deck, args.notes)
    return 0


def paint(text, color):
    if sys.stdout.isatty() and "NO_COLOR" not in os.environ:
        return f"\033[{color}m{text}\033[0m"
    return text


def request_path(value):
    if not value.startswith("/") or value.startswith("//") or "#" in value or any(ord(c) < 32 for c in value):
        raise argparse.ArgumentTypeError("Path must be a relative HTTP path beginning with one slash")
    return value


def report_request(args, path, output, name, body=None):
    code, report = admin_request(args.container, path, output / f"{name}.json", body)
    if code != 200:
        suffix = " Cached analysis is missing, expired or incomplete; live policy was not installed." if code == 409 else ""
        raise RuntimeError(f"Admin {path}: HTTP {code}.{suffix} Inspect the private report.")
    return report


def require_cache_mode(args, output):
    status = report_request(args, "/v1/status", output, "status")
    if status.get("ai_mode", {}).get("cache_only") is not True:
        raise RuntimeError("This replay requires FILTR_AI_CACHE_ONLY=true and a build reporting ai_mode.cache_only=true. No policy was changed.")
    if not status.get("ready") or status.get("traffic", {}).get("effective") == "blocked":
        raise RuntimeError("The existing policy must be ready and traffic must not be fully blocked. No traffic-mode changes are made.")
    return status


def complete_cached_policy(policy, label, minimum_seconds=600):
    ai = policy.get("ai", {})
    cache = ai.get("cache", {})
    if (ai.get("status") != "complete" or ai.get("attempts") != []
            or ai.get("unreviewed_components") or ai.get("rejected")
            or cache.get("misses") != 0 or cache.get("hits", 0) < 1):
        counts = (f"hits={cache.get('hits', 0)}, misses={cache.get('misses', 0)}, "
                  f"unreviewed={len(ai.get('unreviewed_components', []))}, "
                  f"rejected={len(ai.get('rejected', []))}, attempts={len(ai.get('attempts', []))}")
        raise RuntimeError(f"{label}: cached analysis is incomplete ({counts}). Complete cached coverage is required; no new AI review will be requested.")
    expiry = cache.get("next_refresh_at")
    if not isinstance(expiry, (int, float)) or expiry - time.time() < minimum_seconds:
        raise RuntimeError(f"{label}: cached reviews need at least {minimum_seconds // 60} minutes remaining for this recording. Do not refresh without an approved AI budget.")


def cached_preview(args, sbom, output, label):
    preview = report_request(args, "/v1/preview?cache_only=true", output, label, sbom)
    if preview.get("cache_only") is not True or preview.get("installed") is not False:
        raise RuntimeError(f"{label}: server did not confirm a cache-only preview. No candidate was installed.")
    candidate = preview["candidate"]
    complete_cached_policy(candidate["policy"], label)
    if preview.get("analysis_complete") is not True:
        raise RuntimeError(f"{label}: preview did not confirm complete analysis. No candidate was installed.")
    if candidate["remediation"].get("quarantined"):
        raise RuntimeError(f"{label}: candidate would fully block traffic; this is not the targeted-filter demo.")
    return candidate


def component_inventory(policy):
    # Coverage flattens Component; status and rule IDs describe policy, not inventory.
    # Component.kind/sources are currently omitted by serde. Preserve them if a
    # future report exposes them; persisted-byte verification covers them today.
    identity_fields = ("name", "package", "version", "component_type", "sources")
    return [{"component_index": index,
             **{key: entry[key] for key in identity_fields if key in entry}}
            for index, entry in enumerate(policy["components"])]


def verify_saved_sbom(args, expected, output, label):
    saved = output / f"{label}-persisted.sbom.json"
    command(["docker", "cp", f"{args.container}:{args.installed_sbom}", str(saved)])
    saved.chmod(0o600)
    if saved.read_bytes() != expected.read_bytes():
        raise RuntimeError("Persisted SBOM differs from the supplied snapshot, including its metadata/provenance")


def bun_brotli_rule(candidate, cve):
    for rule in candidate["remediation"].get("blockers", []):
        action = rule.get("action", {})
        scope = action.get("filter", {})
        headers = scope.get("headers", [])
        affected_bun = any(
            component.get("name", "").lower().rsplit("/", 1)[-1] == "bun"
            or (component.get("package") or "").lower().endswith("/bun")
            for component in rule.get("affected_components", []))
        if (rule.get("origin") == "ai_discovery" and cve in rule.get("cves", []) and affected_bun
                and action.get("type") == "request" and not scope.get("body_patterns")
                and not scope.get("methods") and scope.get("path_prefix", "") in ["", "/"]
                and len(headers) == 1
                and headers[0].get("name", "").lower() == "content-encoding"
                and headers[0].get("kind") in ["exact", "token"]
                and headers[0].get("value", "").strip().lower() == "br"):
            return rule["rule_id"]
    raise RuntimeError(f"No cached AI rule for Bun/{cve} narrowly matching incoming Content-Encoding: br. The replay stops; it will not invent a rule or run AI.")


def strict_install(args, sbom, output, label):
    result = report_request(args, "/v1/sbom?cache_only=true", output, label, sbom)
    if result.get("cache_only") is not True or result.get("installed") is not True:
        raise RuntimeError("The server did not confirm a strict cache-only installation; use the required build.")
    complete_cached_policy(result["policy"], label, minimum_seconds=0)
    return result


def public_request(args, output, label, compressed, rule_id=None):
    before = report_request(args, "/v1/status", output, label + "-before")
    body = output / ("request.br" if compressed else "request.txt")
    expected = 403 if rule_id else args.brotli_status
    request = ["curl", "--noproxy", "*", "--silent", "--show-error", "--max-time", "15",
               "--http1.1", "--request", "POST", "--header", "Content-Type: text/plain",
               "--data-binary", "@" + str(body), "--output", str(output / (label + ".body")),
               "--write-out", "%{http_code}"]
    if compressed:
        request.extend(["--header", "Content-Encoding: br"])
    request.append(args.url + args.brotli_path)
    code = int(command(request))
    if code != expected:
        raise RuntimeError(f"{label}: HTTP {code}, expected {expected}. Inspect private response and remediation reports.")
    after = report_request(args, "/v1/status", output, label + "-after")
    delta = {name: after["counters"][name] - before["counters"][name]
             for name in ["proxied", "blocked", "upstream_errors"]}
    if rule_id:
        rejection = json.loads((output / (label + ".body")).read_text())
        if rejection.get("error") != rule_id or delta["blocked"] < 1 or delta["proxied"] != 0:
            raise RuntimeError("The rejection did not prove the expected cached rule blocked this request before upstream forwarding.")
    elif delta["proxied"] < 1 or delta["upstream_errors"] != 0:
        raise RuntimeError("The response did not demonstrate successful upstream forwarding.")
    return {"http_status": code, "counter_delta": delta, "passed": True}


def live_steps(args):
    return [
        ("Load vulnerable inventory", "vulnerable", [
            "WHAT: Install the vulnerable Bun inventory using cached analysis only.",
            "WHY: Replay the previously researched incoming-Brotli restriction.",
            "EXPECT: Atomic installation; missing cache means no policy change.",
        ], "The vulnerable inventory's cached targeted rule is active."),
        ("Normal request still passes", "normal", [
            "WHAT: POST harmless plain text to the application's readiness endpoint.",
            "WHY: Show that the targeted restriction keeps ordinary traffic available.",
            f"EXPECT: HTTP {args.brotli_status}, forwarded to Betterpipes.",
        ], "The ordinary request reached the application."),
        ("Brotli request is blocked", "blocked", [
            "WHAT: POST the same harmless content with Content-Encoding: br.",
            "WHY: Match the specific incoming request class covered by the cached CVE rule.",
            "EXPECT: HTTP 403 identifying that exact rule; no upstream forwarding.",
        ], "The cached Bun rule blocked Brotli input; this is not an exploit."),
        ("Load patched inventory", "patched", [
            "WHAT: Install the patched inventory through the strict cache-only API.",
            "WHY: In production, upload this only after deploying the real patch.",
            "EXPECT: The obsolete CVE rule disappears; other protections remain.",
        ], "The patched inventory is active. This replay did not deploy software."),
        ("Identical Brotli request passes", "restored", [
            "WHAT: Repeat the identical Brotli body, headers and endpoint.",
            "WHY: Demonstrate that an accurate patched inventory removes the old restriction.",
            f"EXPECT: HTTP {args.brotli_status}, now forwarded to Betterpipes.",
        ], "The same Brotli request reached the application with filtering enabled."),
        ("Normal traffic remains available", "final-normal", [
            "WHAT: Repeat the ordinary request after the inventory change.",
            "WHY: Check the completed replay's traffic flow.",
            f"EXPECT: HTTP {args.brotli_status}; the patched inventory remains installed.",
        ], "Both request classes now reach Betterpipes under the patched inventory."),
    ]


def live_frame(args, index, step, results, output):
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="", flush=True)
    name, action, explanation, _ = step
    print(paint("F I L T R  /  INVENTORY POLICY REPLAY", "36;1"))
    print("Running Betterpipes/Bun is not changed; no exploit or deployment.\n")
    print(f"{index + 1} / 6   {name}\n")
    for line in explanation:
        print(textwrap.fill(line, width=72))
    if action in ["vulnerable", "patched"]:
        print("\nADMIN POST /v1/sbom?cache_only=true (token stays inside Docker)")
    else:
        compressed = action in ["blocked", "restored"]
        coding = " -H 'Content-Encoding: br'" if compressed else ""
        body = output / ("request.br" if compressed else "request.txt")
        print("\n$ curl --http1.1 -X POST -H 'Content-Type: text/plain'" + coding)
        print("    --data-binary @" + shlex.quote(str(body)) + " " + shlex.quote(args.url + args.brotli_path))
    print("\nPrevious step statuses: " + (" -> ".join(str(r["http_status"]) for r in results) or "none"))


def proceed(automatic, prompt):
    return automatic or input(prompt + "   Q: quit > ").strip().lower() != "q"


def prepare_replay(args, output):
    status = require_cache_mode(args, output)
    original = output / "original.sbom.json"
    command(["docker", "cp", f"{args.container}:{args.installed_sbom}", str(original)])
    original.chmod(0o600)
    for path in [args.vulnerable_sbom, args.patched_sbom, original]:
        if not path.is_file():
            raise RuntimeError(f"SBOM file is missing: {path}")
    # Freeze inputs before previews so a later edit cannot change an approved step.
    for option in ["vulnerable_sbom", "patched_sbom"]:
        snapshot = output / (option + ".json")
        snapshot.write_bytes(getattr(args, option).read_bytes())
        setattr(args, option, snapshot)
    candidates = {label: cached_preview(args, sbom, output, label + "-preview")
                  for label, sbom in [("vulnerable", args.vulnerable_sbom),
                                      ("patched", args.patched_sbom), ("original", original)]}
    if component_inventory(candidates["original"]["policy"]) != component_inventory(status["policy"]):
        raise RuntimeError("The saved SBOM does not match the active inventory; check --installed-sbom before replay.")
    rule = bun_brotli_rule(candidates["vulnerable"], args.cve)
    patched = candidates["patched"]["remediation"]
    if (any(args.cve in item.get("cves", []) for item in patched.get("blockers", []))
            or any(item.get("cve") == args.cve for item in patched.get("uncovered_vulnerabilities", []))):
        raise RuntimeError("The patched cached inventory still reports the selected CVE; fix the inventory or actual dependency first.")
    (output / "request.txt").write_bytes(PLAIN_BODY)
    (output / "request.br").write_bytes(BROTLI_BODY)
    manifest = {"container": args.container, "url": args.url, "rule_id": rule, "cve": args.cve,
                "original_sbom": str(original), "original_sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
                "vulnerable_sha256": hashlib.sha256(args.vulnerable_sbom.read_bytes()).hexdigest(),
                "patched_sha256": hashlib.sha256(args.patched_sbom.read_bytes()).hexdigest(),
                "inventory_policy_replay": True, "completed": False, "restored_original": False}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return original, rule, manifest


def restore_original(args, original, output, manifest):
    print("\nRestoring the original inventory through the strict cache-only API...")
    try:
        restored = strict_install(args, original, output, "restored-original")
        initial = json.loads((output / "original-preview.json").read_text())
        if component_inventory(restored["policy"]) != component_inventory(initial["candidate"]["policy"]):
            raise RuntimeError("Restored inventory differs from the saved original")
        verify_saved_sbom(args, original, output, "restored-original")
        manifest["restored_original"] = True
        print("PASS original inventory restored; traffic mode was never changed.")
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        manifest["restore_error"] = str(error)
        print(f"RESTORATION FAILED: {error}", file=sys.stderr)
        print("Retry strict restoration after resolving connectivity/cache state:", file=sys.stderr)
        print("python3 demo/present.py restore --container " + shlex.quote(args.container)
              + " --installed-sbom " + shlex.quote(args.installed_sbom)
              + " --sbom " + shlex.quote(str(original)), file=sys.stderr)
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        raise


def live(args):
    os.umask(0o077)
    report_root = ROOT / "data/demo-live"
    report_root.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="take-", dir=report_root)).resolve()
    print("Preflight: cache-only mode, three complete cached inventories, and a real scoped Bun rule.")
    print("Inventory policy replay: Betterpipes continues running patched Bun 1.4.4.")
    print(f"Private reports: {output}")
    original, rule, manifest = prepare_replay(args, output)
    print("PASS preflight. No live policy has changed. No new AI calls are permitted.")
    if args.preflight_only:
        return 0
    results = []
    changed = False
    try:
        for index, step in enumerate(live_steps(args)):
            live_frame(args, index, step, results, output)
            if not proceed(args.auto, "Enter: run this step"):
                return 0
            action = step[1]
            if action in ["vulnerable", "patched"]:
                changed = True  # An interrupted HTTP call may still install on the server.
                sbom = args.vulnerable_sbom if action == "vulnerable" else args.patched_sbom
                strict_install(args, sbom, output, action + "-installed")
                result = {"http_status": 200, "installed": action, "passed": True}
            else:
                result = public_request(args, output, action, action in ["blocked", "restored"],
                                        rule if action == "blocked" else None)
            results.append(result)
            (output / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
            print("\n" + paint(f"PASS  HTTP {result['http_status']}", "32;1"))
            print(textwrap.fill("OBSERVED: " + step[3], width=72))
            if index < 5 and not proceed(args.auto, "Enter: explain the next step"):
                return 0
        verify_saved_sbom(args, args.patched_sbom, output, "patched")
        manifest["persisted_inventory_verified"] = True
        manifest["completed"] = True
        print("\nReplay complete. Patched inventory installed; no traffic-mode changes or new AI calls.")
        print("Switch back to tab 1, slide 4. Private evidence remains off screen.")
        return 0
    finally:
        if changed and not manifest["completed"]:
            restore_original(args, original, output, manifest)
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def restore(args):
    os.umask(0o077)
    report_root = ROOT / "data/demo-live"
    report_root.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="recovery-", dir=report_root)).resolve()
    require_cache_mode(args, output)
    cached_preview(args, args.sbom, output, "recovery-preview")
    strict_install(args, args.sbom, output, "recovery-installed")
    verify_saved_sbom(args, args.sbom, output, "recovery")
    print("PASS saved inventory restored through the strict cache-only API.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    deck_parser = modes.add_parser("slides", help="Six slides with optional speaker notes")
    deck_parser.add_argument("--plain", action="store_true", help="Print without terminal controls")
    deck_parser.add_argument("--notes", action="store_true", help="Start with narration visible")
    live_parser = modes.add_parser("live", help="Cache-only vulnerable/patched inventory policy replay")
    live_parser.add_argument("--container", default="filtr-betterpipes-filtr-1")
    live_parser.add_argument("--url", type=origin, default="http://127.0.0.1:18080")
    live_parser.add_argument("--vulnerable-sbom", type=Path, required=True)
    live_parser.add_argument("--patched-sbom", type=Path, required=True)
    live_parser.add_argument("--installed-sbom", default="/data/sbom.json",
                             help="Actual installed SBOM path inside the selected container")
    live_parser.add_argument("--cve", default="CVE-2026-111497")
    live_parser.add_argument("--brotli-path", type=request_path, default="/readyz")
    live_parser.add_argument("--brotli-status", type=int, choices=range(200, 600), default=200,
                             metavar="STATUS", help="Expected upstream HTTP status for both benign POSTs")
    live_parser.add_argument("--preflight-only", action="store_true",
                             help="Validate cache and rules without changing the installed inventory")
    live_parser.add_argument("--auto", action="store_true", help="Run all six steps without pauses")
    restore_parser = modes.add_parser("restore", help="Restore a saved SBOM through strict cache-only upload")
    restore_parser.add_argument("--container", default="filtr-betterpipes-filtr-1")
    restore_parser.add_argument("--installed-sbom", default="/data/sbom.json")
    restore_parser.add_argument("--sbom", type=Path, required=True)
    args = parser.parse_args()
    try:
        return {"slides": slides, "live": live, "restore": restore}[args.mode](args)
    except (EOFError, KeyboardInterrupt):
        print("\nPresentation stopped.")
        return 130
    except (RuntimeError, OSError, ValueError, curses.error, subprocess.TimeoutExpired) as error:
        print(f"Presentation stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
