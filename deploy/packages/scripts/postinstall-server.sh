#!/bin/sh
set -e
getent group wiremesh >/dev/null 2>&1 || groupadd --system wiremesh
# Home dir stays /var/lib/wiremesh so this useradd is byte-identical to the
# relay package's (whichever package installs first creates the shared account;
# a divergent --home-dir would make the account depend on install order). The
# controller never uses $HOME — its state lives in WIREMESH_DATA_DIR.
getent passwd wiremesh >/dev/null 2>&1 || \
  useradd --system --gid wiremesh --home-dir /var/lib/wiremesh \
          --shell /usr/sbin/nologin --comment "WireMesh" wiremesh
mkdir -p /etc/wiremesh
# NOTE: this script deliberately does NOT create or chown /var/lib/wiremesh.
# It used to (`chown wiremesh:wiremesh` + `chmod 0700`), which STOLE the
# directory from a co-located wiremesh-gateway — the gateway keeps its
# identity there, runs as root but with CapabilityBoundingSet lacking
# CAP_DAC_OVERRIDE, so 0700-owned-by-wiremesh genuinely locked it out and it
# crash-looped on "reading identity.json ... Permission denied" (px migration,
# 2026-08-01, docs/runbooks/controller-migration-to-fi.md). The controller now
# has its own /var/lib/wiremesh-controller, created and owned by systemd's
# StateDirectory= in the unit.

OLD_DIR=/var/lib/wiremesh
NEW_DIR=/var/lib/wiremesh-controller
CONTROLLER_ENV=/etc/wiremesh/controller.env
# The complete set of entries the controller creates under WIREMESH_DATA_DIR:
# `controller.db` (+ SQLite's sidecars, in case the DB was left mid-journal)
# from wiremesh-controller::serve, and `ca.pem` / `ca.key` / `secrets/` from
# the EmbeddedTrust layout (crates/wiremesh-trust/src/lib.rs). Anything ELSE in
# OLD_DIR — identity.json, wg_private.key, epoch_keys.json, state.json — is a
# co-located gateway's and must be left exactly where it is, which is why this
# moves a known list of entries and never the directory itself.
CONTROLLER_ENTRIES="controller.db controller.db-journal controller.db-wal controller.db-shm ca.pem ca.key secrets"

# Does OLD_DIR actually hold controller state? The DB and the CA private key
# are the two entries no controller can run without, and neither name collides
# with anything the gateway writes.
have_controller_state() {
  [ -f "$OLD_DIR/controller.db" ] || [ -f "$OLD_DIR/ca.key" ]
}
# Target must be absent or genuinely empty — never merge into a populated dir.
new_dir_empty() {
  [ -d "$NEW_DIR" ] || return 0
  [ -z "$(ls -A "$NEW_DIR" 2>/dev/null)" ]
}
# Only migrate when controller.env still carries the packaged default. If the
# operator picked their own data dir we must not touch their layout, and if the
# setting is absent entirely we cannot repoint it with a substitution.
env_uses_old_dir() {
  [ -f "$CONTROLLER_ENV" ] &&
    grep -Eq "^[[:space:]]*WIREMESH_DATA_DIR=[\"']?$OLD_DIR[\"']?[[:space:]]*\$" "$CONTROLLER_ENV"
}
# A drop-in Environment=WIREMESH_DATA_DIR= overrides the EnvironmentFile, so
# rewriting controller.env would NOT repoint the service — and a controller
# started against an emptied data dir mints a BRAND NEW CA, invalidating every
# enrolled gateway. Refuse the migration rather than risk that.
dropin_overrides_data_dir() {
  grep -rqs WIREMESH_DATA_DIR /etc/systemd/system/wiremesh-controller.service.d 2>/dev/null
}

if ! have_controller_state; then
  : # Fresh install (or state already migrated) — nothing to do.
elif ! new_dir_empty; then
  echo "WireMesh controller: NOTE controller state still in $OLD_DIR but $NEW_DIR is already populated;" \
       "leaving both untouched — confirm WIREMESH_DATA_DIR in $CONTROLLER_ENV points at the one you want."
elif ! env_uses_old_dir || dropin_overrides_data_dir; then
  echo "WireMesh controller: NOTE state is in $OLD_DIR but WIREMESH_DATA_DIR is not the packaged default" \
       "(custom value, absent, or overridden by a systemd drop-in);" \
       "this unit only grants write access to $NEW_DIR, so either move controller.db/ca.pem/ca.key/secrets" \
       "there and set WIREMESH_DATA_DIR=$NEW_DIR, or add ReadWritePaths=<your dir> via a systemd drop-in."
else
  # Repoint the config BEFORE moving anything: if the substitution silently
  # fails we abort with the files still in place, rather than leaving a
  # controller pointed at an emptied dir (which would self-generate a new CA).
  mkdir -p "$NEW_DIR"
  chown wiremesh:wiremesh "$NEW_DIR"
  chmod 0700 "$NEW_DIR"
  sed -i -E "s#^([[:space:]]*)WIREMESH_DATA_DIR=[\"']?$OLD_DIR[\"']?[[:space:]]*\$#\\1WIREMESH_DATA_DIR=$NEW_DIR#" \
      "$CONTROLLER_ENV" || true
  if grep -Eq "^[[:space:]]*WIREMESH_DATA_DIR=$NEW_DIR[[:space:]]*\$" "$CONTROLLER_ENV"; then
    echo "WireMesh controller: migrating control-plane state $OLD_DIR -> $NEW_DIR (co-located gateway files stay put)"
    migrated_ok=1
    for f in $CONTROLLER_ENTRIES; do
      [ -e "$OLD_DIR/$f" ] || continue
      # Same-filesystem rename: a running controller's open fds follow the
      # inode, so an in-flight upgrade keeps writing to the moved files and
      # simply picks up the new path on its next restart.
      mv "$OLD_DIR/$f" "$NEW_DIR/$f" || migrated_ok=0
    done
    chown -R wiremesh:wiremesh "$NEW_DIR" || migrated_ok=0
    if [ "$migrated_ok" = 1 ]; then
      echo "WireMesh controller: state migrated; WIREMESH_DATA_DIR now $NEW_DIR — restart wiremesh-controller to apply."
    else
      echo "WireMesh controller: WARNING the move from $OLD_DIR to $NEW_DIR did not complete;" \
           "do NOT start the controller until ca.pem/ca.key/controller.db/secrets are all in $NEW_DIR" \
           "(starting it against an incomplete dir generates a new CA and invalidates every enrolled gateway)."
    fi
  else
    echo "WireMesh controller: NOTE could not repoint WIREMESH_DATA_DIR in $CONTROLLER_ENV;" \
         "state left in $OLD_DIR — set WIREMESH_DATA_DIR=$NEW_DIR and move controller.db/ca.pem/ca.key/secrets there manually."
  fi
fi

if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi
echo "WireMesh: edit the config in /etc/wiremesh, then: systemctl enable --now <service>"
