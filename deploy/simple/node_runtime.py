"""Inspect the selected live service. Never read its environment or run code as root."""
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time

from common import InstallError, read, run


def service_property(unit, name):
    return run(["systemctl", "show", unit, f"--property={name}", "--value"]).strip()


def process_identity(pid, proc=Path("/proc")):
    path = proc / str(pid)
    fields = dict(line.split(":", 1) for line in read(path / "status", 65536).decode().splitlines() if ":" in line)
    uids = [int(value) for value in fields["Uid"].split()]
    gid = int(fields["Gid"].split()[0])
    if 0 in uids or len(set(uids)) != 1 or gid == 0:
        raise InstallError("the Node service must run under an unprivileged user and group")
    executable = os.readlink(path / "exe")
    if Path(executable.removesuffix(" (deleted)")).name not in ("node", "nodejs"):
        raise InstallError("service MainPID must be Node itself; shell wrappers/PM2 managers need manual integration")
    return {"pid": pid, "uid": uids[0], "gid": gid, "executable": executable}


def listening_sockets(pid, proc=Path("/proc")):
    base = proc / str(pid)
    owned = set()
    with os.scandir(base / "fd") as descriptors:
        for count, path in enumerate(descriptors):
            if count >= 65536:
                raise InstallError("Node process exceeds bounded socket discovery; use manual integration")
            try:
                target = os.readlink(path.path)
            except FileNotFoundError:
                continue
            match = re.fullmatch(r"socket:\[(\d+)\]", target)
            if match:
                owned.add(match[1])
    result = []
    for table in ("tcp", "tcp6"):
        for line in read(base / "net" / table, 8 * 1024 * 1024).decode().splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "0A" or fields[9] not in owned:
                continue
            address, port = fields[1].split(":")
            raw = bytes.fromhex(address)
            # Linux renders each native 32-bit word in host byte order (supported x86_64/arm64).
            raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
            result.append((ipaddress.ip_address(raw), int(port, 16)))
    return result


def private_endpoint(sockets, requested=None):
    ports = {port for _, port in sockets}
    if requested is None:
        if len(ports) != 1:
            raise InstallError("Node has zero/multiple listening ports; select its HTTP port with --backend-port")
        requested = ports.pop()
    matches = [address for address, port in sockets if port == requested]
    if not matches or any(not address.is_loopback for address in matches):
        raise InstallError("Node backend must listen only on loopback; bind the app to 127.0.0.1 before installing")
    host = "127.0.0.1" if any(str(address) == "127.0.0.1" for address in matches) else "[::1]"
    if not any(str(address) in ("127.0.0.1", "::1") for address in matches):
        raise InstallError("profile supports a 127.0.0.1 or ::1 backend")
    return requested, f"http://{host}:{requested}"


def versions(identity):
    # Execute only a fixed built-in expression, as the app UID with no supplementary
    # groups or inherited NODE_OPTIONS/NODE_PATH/LD_PRELOAD. Do not load project code.
    command = [f"/proc/{identity['pid']}/exe", "--eval",
               "process.stdout.write(JSON.stringify(process.versions))"]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd="/",
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, user=identity["uid"], group=identity["gid"],
        extra_groups=[], start_new_session=True)
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if not selector.select(max(0, deadline - time.monotonic())):
                    break
                chunk = os.read(process.stdout.fileno(), 8193 - len(output))
                if not chunk:
                    process.wait(timeout=1)
                    break
                output.extend(chunk)
                if len(output) > 8192:
                    break
            else:
                raise InstallError("Node runtime inspection timed out")
        if process.poll() is None or process.returncode or len(output) > 8192:
            raise InstallError("cannot inspect the live Node build within bounded limits")
        result = json.loads(output)
        if not isinstance(result, dict) or not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", result.get("node", "")):
            raise InstallError("Node did not return an exact runtime version")
        return result
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=2)
        process.stdout.close()


def inspect(unit, app_dir=None, backend_port=None):
    if not unit or not re.fullmatch(r"[A-Za-z0-9_@.-]+\.service", unit) or unit.startswith("-"):
        raise InstallError("--app-service must name an existing Node systemd .service")
    run(["systemctl", "is-active", "--quiet", unit])
    pid = int(service_property(unit, "MainPID"))
    if pid <= 1:
        raise InstallError("Node service has no live MainPID")
    working = Path(service_property(unit, "WorkingDirectory"))
    root = Path(app_dir) if app_dir else working
    if not root.is_absolute() or root == Path("/") or not root.is_dir() or not working.resolve().is_relative_to(root.resolve()):
        raise InstallError("--app-dir must contain the service's explicit WorkingDirectory")
    identity = process_identity(pid)
    port, upstream = private_endpoint(listening_sockets(pid), backend_port)
    identity.update(versions=versions(identity), app_service=unit, app_dir=str(root.resolve()),
                    backend_port=port, upstream=upstream)
    return identity
