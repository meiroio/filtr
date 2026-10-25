"""Small, bounded operations shared by discovery and the root installer."""
import json
import os
from pathlib import Path
import subprocess
import tempfile


class InstallError(Exception):
    pass


def run(args, timeout=30):
    # No shell, inherited secrets, application plugins or user-provided executables.
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except subprocess.TimeoutExpired as error:
        raise InstallError(f"{Path(args[0]).name} timed out; check its service logs") from error
    if result.returncode:
        raise InstallError(f"{Path(args[0]).name} failed; check its configuration/service logs")
    return result.stdout


def read(path, limit=16 * 1024 * 1024):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise InstallError(f"file exceeds discovery limit: {path}")
    return data


def atomic(path, content, mode=0o600, uid=0, gid=0):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".filtr-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), uid, gid)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def json_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode()


def safe_destination(path):
    """Do not let a local unprivileged account redirect a root installation."""
    path = Path(path)
    for parent in path.parents:
        if parent.is_symlink():
            raise InstallError(f"managed path has a symlinked parent: {parent}")
        if parent.exists():
            info = parent.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise InstallError(f"managed directory must be root-owned and not group/world-writable: {parent}")
    if path.exists() and not path.is_symlink():
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise InstallError(f"managed file must be root-owned and not group/world-writable: {path}")
