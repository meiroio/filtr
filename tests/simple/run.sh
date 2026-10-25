#!/bin/sh
set -eu
release=${1:?usage: tests/simple/run.sh RELEASE_DIRECTORY [DISTRIBUTION_IMAGE]}
distribution=${2:-debian:bookworm-slim}
release=$(CDPATH= cd -- "$release" && pwd)
repository=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
image=filtr-simple-integration-test
docker build --build-arg "DISTRIBUTION=$distribution" -f "$repository/tests/simple/Dockerfile" -t "$image" "$repository"
docker run --rm \
  --mount "type=bind,src=$repository/tests/simple,dst=/source/tests/simple,readonly" \
  --mount "type=bind,src=$repository/deploy/simple,dst=/source/deploy/simple,readonly" \
  --entrypoint python3 "$image" -m unittest discover -s /source/tests/simple -p 'test_*.py'
docker run --rm --mount "type=bind,src=$release,dst=/release,readonly" "$image"
docker run --rm -e TEST_PHP=fpm --mount "type=bind,src=$release,dst=/release,readonly" "$image"
docker run --rm -e TEST_FAILURE=reload --mount "type=bind,src=$release,dst=/release,readonly" "$image"
docker run --rm -e TEST_BLOCKED=1 --mount "type=bind,src=$release,dst=/release,readonly" "$image"
docker run --rm -e TEST_HTTP_ONLY=1 --mount "type=bind,src=$release,dst=/release,readonly" "$image"
