#!/bin/sh
set -e
getent group wiremesh >/dev/null 2>&1 || groupadd --system wiremesh
getent passwd wiremesh >/dev/null 2>&1 || \
  useradd --system --gid wiremesh --home-dir /var/lib/wiremesh \
          --shell /usr/sbin/nologin --comment "WireMesh" wiremesh
mkdir -p /var/lib/wiremesh /etc/wiremesh
chown wiremesh:wiremesh /var/lib/wiremesh
chmod 0700 /var/lib/wiremesh
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi
echo "WireMesh: edit the config in /etc/wiremesh, then: systemctl enable --now <service>"
