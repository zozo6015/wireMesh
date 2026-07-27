#!/bin/sh
set -e
getent group wiremesh >/dev/null 2>&1 || groupadd --system wiremesh
getent passwd wiremesh >/dev/null 2>&1 || \
  useradd --system --gid wiremesh --home-dir /var/lib/wiremesh \
          --shell /usr/sbin/nologin --comment "WireMesh" wiremesh
mkdir -p /etc/wiremesh
# Dedicated relay state dir (ops finding 2026-07-27/28, "Relay Finding A"):
# the relay must NOT share /var/lib/wiremesh with the gateway — on a shared
# host that is the gateway's root-only state dir, and the User=wiremesh relay
# cannot read an identity enrolled there. This mirrors the unit's
# StateDirectory=wiremesh-relay, but creates the directory NOW so it already
# exists (correctly owned) at enroll time — enrollment is documented to run
# BEFORE the first service start ever creates the StateDirectory.
mkdir -p /var/lib/wiremesh-relay
chown wiremesh:wiremesh /var/lib/wiremesh-relay
chmod 0700 /var/lib/wiremesh-relay
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi
echo "WireMesh relay: enroll first (wiremesh-relay-enroll ... --certdir /var/lib/wiremesh-relay),"
echo "then: systemctl enable --now wiremesh-relay   (see docs/install.md)"
