#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "0" ]; then
  if command -v systemctl >/dev/null 2>&1; then
    # Stop only if active, so a genuine stop/timeout failure propagates and
    # halts removal; an inactive or absent unit is a no-op. Disable best-effort.
    if systemctl is-active --quiet wiremesh-gateway.service; then
      systemctl stop wiremesh-gateway.service
    fi
    systemctl disable wiremesh-gateway.service >/dev/null 2>&1 || true
  fi
fi
