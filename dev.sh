#!/usr/bin/env bash
# dev.sh — run from repo root on the macOS host
set -euo pipefail
IMAGE=aetherlink-dev
case "${1:-}" in
  build) docker build -t "$IMAGE" dev/ ;;
  shell) docker run --rm -it --privileged \
           -v "$PWD":/work -v aetherlink-cargo:/usr/local/cargo/registry \
           "$IMAGE" bash ;;
  run)   shift; docker run --rm --privileged \
           -v "$PWD":/work -v aetherlink-cargo:/usr/local/cargo/registry \
           "$IMAGE" bash -lc "$*" ;;
  *) echo "usage: ./dev.sh {build|shell|run <cmd>}"; exit 1 ;;
esac
