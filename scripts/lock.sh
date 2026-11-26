#!/usr/bin/env sh
# Regenerate the hashed lock files the Docker images install from (#121).
#
#   scripts/lock.sh            keep existing pins, only resolve what requirements.txt changed
#   scripts/lock.sh --upgrade  move every package to the newest version the ranges allow
#
# Needs uv (https://docs.astral.sh/uv/). The locks are universal (Linux/macOS,
# amd64/arm64): the agent's for Python 3.10+ (CI matrix and the 3.12 image),
# the middleware's for 3.12+ (its image; FastAPI there needs 3.11+).
set -eu
cd "$(dirname "$0")/.."
UPGRADE="${1:-}"
lock() {
  uv pip compile "$1/requirements.txt" \
    --universal --python-version "$2" --generate-hashes \
    --no-header --quiet $UPGRADE \
    -o "$1/requirements.lock"
}
lock . 3.10
lock middleware 3.12
