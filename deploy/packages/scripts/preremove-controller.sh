#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "0" ]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop wiremesh-controller.service >/dev/null 2>&1 || true
    systemctl disable wiremesh-controller.service >/dev/null 2>&1 || true
  fi
fi
