#!/bin/sh
set -eu
release=${1:?usage: run-node.sh RELEASE_DIRECTORY [DISTRIBUTION_IMAGE]}
distribution=${2:-debian:bookworm-slim}
release=$(CDPATH= cd -- "$release" && pwd)
repository=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
image=filtr-node-integration-test
docker build --build-arg "DISTRIBUTION=$distribution" -f "$repository/tests/simple/Dockerfile.node" -t "$image" "$repository"
docker run --rm --cap-add SYS_PTRACE \
  --mount "type=bind,src=$repository/tests/simple,dst=/source/tests/simple,readonly" \
  --mount "type=bind,src=$repository/deploy/simple,dst=/source/deploy/simple,readonly" \
  --entrypoint python3 "$image" -m unittest discover -s /source/tests/simple -p 'test_*.py'
docker run --rm --cap-add SYS_PTRACE --mount "type=bind,src=$release,dst=/release,readonly" "$image"
docker run --rm --cap-add SYS_PTRACE -e TEST_WEB_SERVER=apache --mount "type=bind,src=$release,dst=/release,readonly" "$image"
docker run --rm --cap-add SYS_PTRACE -e TEST_FAILURE=reload --mount "type=bind,src=$release,dst=/release,readonly" "$image"
docker run --rm --cap-add SYS_PTRACE -e TEST_PUBLIC_BIND=1 --mount "type=bind,src=$release,dst=/release,readonly" "$image"
