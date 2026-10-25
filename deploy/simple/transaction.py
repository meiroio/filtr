"""Durable before-images and conflict-aware rollback of installer-owned changes."""
import hashlib
import json
import os
from pathlib import Path
import stat

from common import InstallError, atomic, json_bytes, read, run
import service


def fingerprint(path):
    path = Path(path)
    if path.is_symlink():
        return "symlink:" + os.readlink(path)
    if path.exists():
        return hashlib.sha256(read(path, 128 * 1024 * 1024)).hexdigest()
    return "absent"


class Transaction:
    def __init__(self, state):
        self.state = Path(state)
        self.journal = self.state / "transaction.json"
        self.record = None

    def begin(self, paths, metadata):
        if self.journal.exists():
            previous = json.loads(read(self.journal))
            if previous.get("status") != "rolled_back":
                raise InstallError("an installation/journal already exists; use --rollback or --refresh-inventory")
        self.record = {"version": 1, "status": "applying", "metadata": metadata, "files": []}
        backups = self.state / "backups"
        backups.mkdir(mode=0o700, exist_ok=True)
        for index, path in enumerate(paths):
            path = Path(path)
            entry = {"path": str(path), "before": fingerprint(path)}
            if path.is_symlink():
                entry["kind"] = "symlink"
                entry["target"] = os.readlink(path)
            elif path.exists():
                info = path.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise InstallError(f"refusing to replace nonregular or hardlinked file: {path}")
                backup = backups / str(index)
                atomic(backup, read(path, 128 * 1024 * 1024))
                entry.update(kind="file", backup=str(backup), mode=stat.S_IMODE(info.st_mode),
                             uid=info.st_uid, gid=info.st_gid)
            else:
                entry["kind"] = "absent"
            self.record["files"].append(entry)
        self.save()

    def save(self):
        atomic(self.journal, json_bytes(self.record))

    def finish(self):
        for entry in self.record["files"]:
            entry["installed"] = fingerprint(entry["path"])
        self.record["status"] = "installed"
        self.save()

    def restore_files(self, check_conflicts=True):
        self.record = self.record or json.loads(read(self.journal))
        if self.record.get("version") != 1 or self.record.get("status") == "rolled_back":
            raise InstallError("no active simple-mode installation to roll back")
        if check_conflicts and self.record["status"] == "installed":
            conflicts = [e["path"] for e in self.record["files"]
                         if fingerprint(e["path"]) != e["installed"]]
            if conflicts:
                raise InstallError("managed files changed after installation; reconcile before rollback: " + ", ".join(conflicts))
        for entry in reversed(self.record["files"]):
            path = Path(entry["path"])
            if entry["kind"] == "absent":
                path.unlink(missing_ok=True)
            elif entry["kind"] == "symlink":
                path.unlink(missing_ok=True)
                path.symlink_to(entry["target"])
            else:
                atomic(path, read(entry["backup"], 128 * 1024 * 1024), entry["mode"], entry["uid"], entry["gid"])

    def rollback(self, check_conflicts=True):
        self.restore_files(check_conflicts)
        web_server = self.record["metadata"].get("web_server", "apache")
        service.check_web_server(web_server)
        service.reload_web_server(web_server)
        # Original routing is live; never stop the proxy before restoring that routing.
        if self.record.get("service_attempted"):
            run(["systemctl", "stop", "filtr-simple.service"])
        run(["systemctl", "daemon-reload"])
        self.record["status"] = "rolled_back"
        self.save()
