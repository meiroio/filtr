#!/bin/sh
# Build on a native runner or use Docker's configured architecture emulation.
set -eu
version=${1:?usage: package-release.sh VERSION amd64|arm64 OUTPUT_DIRECTORY}
architecture=${2:?missing architecture}
output=${3:?missing output directory}
case "$version" in *[!A-Za-z0-9._-]*|'') exit 2;; esac
case "$architecture" in amd64|arm64) ;; *) exit 2;; esac
repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
docker buildx build --platform "linux/$architecture" --file "$repository/deploy/simple/Dockerfile.release" \
  --target binary --output "type=local,dest=$temporary/package" "$repository"
cp "$repository/deploy/filtr-install" "$temporary/package/filtr-install"
mkdir "$temporary/package/simple"
cp "$repository"/deploy/simple/*.py "$temporary/package/simple/"
cp "$repository/LICENSE" "$temporary/package/LICENSE"
cp "$repository/README.md" "$temporary/package/README.md"
cp "$repository/filtr.png" "$temporary/package/filtr.png"
cp "$repository/.env.example" "$temporary/package/.env.example"
mkdir "$temporary/package/docs"
cp "$repository"/docs/*.md "$temporary/package/docs/"
chmod 755 "$temporary/package/filtr" "$temporary/package/filtr-install"
cd "$temporary/package"
# No application-specific inventories, secrets or local reports enter this archive.
sha256sum filtr filtr-install simple/*.py docs/*.md LICENSE README.md filtr.png .env.example > SHA256SUMS
python3 - "$output/filtr-$version-linux-$architecture.tar.gz" <<'PY'
import sys
import tarfile

def public_metadata(info):
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mtime = 0
    info.pax_headers = {}
    info.mode = 0o755 if info.isdir() or info.name in ("filtr", "filtr-install") else 0o644
    return info

with tarfile.open(sys.argv[1], "w:gz") as archive:
    for name in ("filtr", "filtr-install", "simple", "docs", "LICENSE", "README.md", "filtr.png", ".env.example", "SHA256SUMS"):
        archive.add(name, arcname=name, filter=public_metadata)
PY
cd "$output"
sha256sum "filtr-$version-linux-$architecture.tar.gz" > "filtr-$version-linux-$architecture.tar.gz.sha256"
