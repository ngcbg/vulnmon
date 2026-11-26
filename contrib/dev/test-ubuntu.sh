#!/bin/sh
# Run the test suite inside an Ubuntu 24.04 container (podman preferred, docker fallback).
# Usage: contrib/dev/test-ubuntu.sh [command ...]   (default: full unittest discovery)
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
engine=${CONTAINER_ENGINE:-$(command -v podman || command -v docker || true)}
[ -n "$engine" ] || { echo "test-ubuntu: podman or docker required" >&2; exit 1; }
image=vulnmon-dev:ubuntu-24.04
"$engine" build --quiet -t "$image" -f "$root/contrib/dev/Containerfile" "$root/contrib/dev" >/dev/null
set -- ${1+"$@"}
if [ "$engine" = "$(command -v podman 2>/dev/null)" ]; then userns=--userns=keep-id; else userns=; fi
exec "$engine" run --rm $userns --network=none -v "$root:/src:ro,Z" "$image" "$@"
