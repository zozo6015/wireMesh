#!/bin/sh
set -e
mkdir -p /var/lib/wiremesh /etc/wiremesh
chmod 0700 /var/lib/wiremesh
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi
echo "WireMesh gateway: enroll once (see /etc/wiremesh/gateway.env), then: systemctl enable --now wiremesh-gateway"
