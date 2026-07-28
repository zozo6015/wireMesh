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

# Upgrade path (ops finding "Relay Finding A"): an earlier relay .deb defaulted
# the identity to /var/lib/wiremesh (the gateway's dir). If this host still has
# its identity there AND the new dedicated dir is empty AND relay.env still
# references the OLD path (an operator who set a custom --certdir must be left
# alone), migrate the three identity files to the new dir. Idempotent: skipped
# entirely on fresh installs (no legacy files) and on re-runs (new dir already
# populated). Never destroys a working install — files are MOVED only when the
# destination is empty, and the env is only rewritten to match.
OLD_DIR=/var/lib/wiremesh
NEW_DIR=/var/lib/wiremesh-relay
RELAY_ENV=/etc/wiremesh/relay.env
have_legacy_identity() {
  [ -f "$OLD_DIR/relay.pem" ] && [ -f "$OLD_DIR/relay.key" ] && [ -f "$OLD_DIR/ca.pem" ]
}
new_dir_empty() {
  [ ! -f "$NEW_DIR/relay.pem" ] && [ ! -f "$NEW_DIR/relay.key" ] && [ ! -f "$NEW_DIR/ca.pem" ]
}
# Env still points at the legacy dir (word-boundary match so it won't fire on
# /var/lib/wiremesh-relay itself) and not at some operator-custom path.
env_uses_old_dir() {
  [ -f "$RELAY_ENV" ] && grep -Eq "(^|[[:space:]])$OLD_DIR([[:space:]]|\$)" "$RELAY_ENV"
}
if have_legacy_identity && new_dir_empty && env_uses_old_dir; then
  echo "WireMesh relay: migrating legacy identity $OLD_DIR -> $NEW_DIR (Relay Finding A)"
  for f in ca.pem relay.pem relay.key; do
    mv "$OLD_DIR/$f" "$NEW_DIR/$f"
    chown wiremesh:wiremesh "$NEW_DIR/$f"
    chmod 0600 "$NEW_DIR/$f"
  done
  # Repoint RELAY_ARGS' cert-dir at the new path (leave every other token
  # as-is). Anchor OLD_DIR on BOTH sides with the SAME word boundary the
  # `env_uses_old_dir` grep uses — a leading space/tab and a trailing
  # space/tab/EOL — so it rewrites only a bare `$OLD_DIR` token and never a
  # `$OLD_DIR-relay` / `$OLD_DIR-foo` suffix or an unrelated path containing
  # the string. Boundaries are captured (\1, \2) and preserved.
  sed -i -E "s#(RELAY_ARGS=.*[[:space:]])$OLD_DIR([[:space:]]|\$)#\\1$NEW_DIR\\2#" "$RELAY_ENV" || true
  echo "WireMesh relay: identity migrated; RELAY_ARGS cert-dir updated to $NEW_DIR"
elif have_legacy_identity && ! new_dir_empty; then
  echo "WireMesh relay: NOTE legacy identity still present in $OLD_DIR but $NEW_DIR is already" \
       "populated; leaving both untouched (verify relay.env points at the intended cert dir)."
fi

if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi
echo "WireMesh relay: enroll first (wiremesh-relay-enroll ... --certdir /var/lib/wiremesh-relay),"
echo "then: systemctl enable --now wiremesh-relay   (see docs/install.md)"
