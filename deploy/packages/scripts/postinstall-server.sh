#!/bin/sh
# wiremesh-controller postinstall (deb AND rpm — POSIX sh, no bashisms).
#
# Two jobs: create the shared service account + /etc/wiremesh, and migrate a
# pre-0.5 install off the SHARED /var/lib/wiremesh onto the controller's own
# /var/lib/wiremesh-controller.
#
# CONTRACT: this script must NEVER exit non-zero because of the migration.
# A half-configured package is worse than an unmigrated one, so every
# migration step is guarded and every bail-out path prints exactly what the
# operator has to do and falls through to the end.
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
# identity there, runs as root but with a CapabilityBoundingSet lacking
# CAP_DAC_OVERRIDE, so a 0700 dir owned by `wiremesh` genuinely locked it out
# and it crash-looped on "reading identity.json ... Permission denied" (px
# migration, 2026-08-01, docs/runbooks/controller-migration-to-fi.md). The
# controller now has its own /var/lib/wiremesh-controller, created and owned
# by systemd's StateDirectory= in the unit.

# Reload BEFORE the migration, not after: the new unit file is already
# unpacked at this point, and the migration below asks systemd (via
# `systemctl show`) what the service will ACTUALLY do — which is only accurate
# once the new fragment and any drop-ins have been re-read.
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi

OLD_DIR=/var/lib/wiremesh
NEW_DIR=/var/lib/wiremesh-controller
STAGE=/var/lib/wiremesh-controller.migrating
CONTROLLER_ENV=/etc/wiremesh/controller.env
# The complete set of entries the controller creates under WIREMESH_DATA_DIR:
# `controller.db` (+ SQLite's sidecars, in case the DB was left mid-journal)
# from wiremesh-controller::serve, and `ca.pem` / `ca.key` / `secrets/` from
# the EmbeddedTrust layout (crates/wiremesh-trust/src/lib.rs). Anything ELSE in
# OLD_DIR — identity.json, wg_private.key, epoch_keys.json, state.json — is a
# co-located gateway's and must be left exactly where it is, which is why this
# copies a known list of entries and never the directory itself.
CONTROLLER_ENTRIES="controller.db controller.db-journal controller.db-wal controller.db-shm ca.pem ca.key secrets"
# ca.pem is the ONE entry that is not controller-exclusive: a legacy relay's
# identity dir was also /var/lib/wiremesh, and its identity is ca.pem +
# relay.pem + relay.key (IDENTITY_FILES in crates/wiremesh-relay/src/enroll.rs;
# server_config reads certdir/ca.pem at lib.rs:192). postinstall-relay.sh's own
# migration requires ALL THREE to still be present, so removing ca.pem here
# would both break a running legacy relay and permanently skip its migration.
# It is a PUBLIC certificate, so the fix is free: copy it, never delete it.
KEEP_IN_OLD_DIR="ca.pem"

say() { echo "WireMesh controller: $*"; }

# --- state detection -------------------------------------------------------

# Does OLD_DIR actually hold controller state? The DB and the CA private key
# are the two entries no controller can run without, and neither name is
# written by the gateway or the relay.
have_controller_state() {
  [ -f "$OLD_DIR/controller.db" ] || [ -f "$OLD_DIR/ca.key" ]
}

# True when $1 exists and is either a non-empty directory or not a directory
# at all (so the caller refuses to mkdir/rename over a plain file). Pure POSIX
# shell globbing rather than `ls -A`, which is XSI, not base POSIX.
dir_has_entries() {
  [ -e "$1" ] || return 1
  [ -d "$1" ] || return 0
  for e in "$1"/* "$1"/.[!.]* "$1"/..?*; do
    if [ -e "$e" ] || [ -L "$e" ]; then return 0; fi
  done
  return 1
}

# The LAST WIREMESH_DATA_DIR= value in the EnvironmentFile (systemd keeps the
# last assignment when a variable is set more than once), quotes stripped.
# Empty when the file is absent or never sets it — in which case the binary's
# own compiled default applies (crates/wiremesh-controller/src/main.rs:46-48),
# and that default is OLD_DIR.
env_file_data_dir() {
  [ -f "$CONTROLLER_ENV" ] || return 0
  sed -n -E "s/^[[:space:]]*WIREMESH_DATA_DIR=[\"']?([^\"'[:space:]]*)[\"']?[[:space:]]*\$/\\1/p" \
      "$CONTROLLER_ENV" | tail -n 1
}

# A systemd `Environment=` assignment beats the EnvironmentFile (drop-ins are
# applied after the packaged unit), so if one exists we cannot repoint the
# service by editing controller.env and must not pretend otherwise.
# `systemctl show` prints ONE line, `Environment=VAR1=a VAR2=b`, so the
# property name has to come off BEFORE splitting on spaces — otherwise the
# first variable in the list is silently invisible (it reads as
# `Environment=WIREMESH_DATA_DIR=...`), which is exactly the position an
# operator's single override lands in.
systemd_env_data_dir() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl show -p Environment wiremesh-controller 2>/dev/null |
    sed -n "s/^Environment=//p" |
    tr ' ' '\n' |
    sed -n -E "s/^WIREMESH_DATA_DIR=(.*)\$/\\1/p" | tail -n 1
}

# Will the service the operator actually runs be able to WRITE $NEW_DIR? Only
# if its effective unit still declares StateDirectory=wiremesh-controller —
# `systemctl edit --full` freezes a private copy of the old unit (old
# WorkingDirectory/ReadWritePaths, no StateDirectory=), and under
# ProtectSystem=strict that leaves the new dir read-only. Migrating into a dir
# the controller cannot open would trade a working control plane for a crash
# loop, so this is a hard precondition. Returns non-zero when we can prove it
# is NOT satisfied; when systemd cannot be queried at all (chroot, container
# image build) we look for the override files ourselves instead.
unit_grants_new_dir() {
  if command -v systemctl >/dev/null 2>&1; then
    sd=$(systemctl show -p StateDirectory wiremesh-controller 2>/dev/null || true)
    case "$sd" in
      *wiremesh-controller*) return 0 ;;
      StateDirectory=*)      return 1 ;;   # answered, and the answer is "no"
      *) : ;;                              # no usable answer — fall through
    esac
  fi
  # Offline fallback. A full-unit override shadows the packaged unit outright;
  # a drop-in cannot remove StateDirectory= but can set Environment=, which
  # systemd_env_data_dir would have caught had systemd been reachable.
  [ ! -f /etc/systemd/system/wiremesh-controller.service ] || return 1
  for d in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
    if grep -Eqs "^[[:space:]]*Environment=.*WIREMESH_DATA_DIR" \
         "$d/wiremesh-controller.service.d"/*.conf; then
      return 1
    fi
  done
  return 0
}

# --- copy / verify helpers -------------------------------------------------

# Verify one staged entry against its source. `cp` already reports write
# errors; this re-checks existence and byte size afterwards so a truncated or
# silently-dropped file cannot pass. (No cmp/diff — neither is in the
# packages' declared dependencies.) `secrets/` is flat by construction:
# EmbeddedTrust rejects keys containing '/' (wiremesh-trust/src/lib.rs:186-189),
# so a one-level walk covers it completely.
verify_entry() {
  src="$OLD_DIR/$1"
  dst="$STAGE/$1"
  if [ -d "$src" ]; then
    [ -d "$dst" ] || return 1
    for s in "$src"/*; do
      [ -f "$s" ] || continue
      b=${s##*/}
      [ -f "$dst/$b" ] || return 1
      [ "$(wc -c < "$s")" = "$(wc -c < "$dst/$b")" ] || return 1
    done
    return 0
  fi
  [ -f "$dst" ] || return 1
  [ "$(wc -c < "$src")" = "$(wc -c < "$dst")" ] || return 1
}

abort_migration() {
  rm -rf "$STAGE" 2>/dev/null || true
  say "NOTE $1"
  say "state left untouched in $OLD_DIR — migrate by hand: copy controller.db, ca.pem," \
      "ca.key and secrets/ into $NEW_DIR (chown wiremesh:wiremesh, dir 0700, files 0600)" \
      "and set WIREMESH_DATA_DIR=$NEW_DIR in $CONTROLLER_ENV."
}

# --- the migration ---------------------------------------------------------

if ! have_controller_state; then
  : # Fresh install, or already migrated — nothing to do.
elif dir_has_entries "$NEW_DIR"; then
  say "NOTE controller state still in $OLD_DIR but $NEW_DIR already exists and is not an empty" \
      "directory; leaving both untouched — confirm WIREMESH_DATA_DIR in $CONTROLLER_ENV points" \
      "at the one you want (and that $NEW_DIR really is a directory)."
else
  # Which data dir will the service actually use? On a .deb upgrade dpkg has
  # ALREADY replaced controller.env during unpack (nfpm v2.38.0 maps both
  # `config` and `config|noreplace` to a plain deb conffile — deb has no
  # noreplace mechanism — and dpkg silently installs the new version of an
  # UNMODIFIED conffile, before postinst runs), so the file reads NEW_DIR
  # before this script starts and needs no rewrite. On rpm,
  # `%config(noreplace)` keeps the operator's file, so it still reads OLD_DIR
  # and we do have to rewrite it. Both are legitimate migration starting
  # points; anything else is an operator's own layout and is left alone.
  dropin_dir=$(systemd_env_data_dir)
  file_dir=$(env_file_data_dir)
  effective=${dropin_dir:-${file_dir:-$OLD_DIR}}

  if [ -n "$dropin_dir" ]; then
    abort_migration "a systemd drop-in sets Environment=WIREMESH_DATA_DIR=$dropin_dir, which\
 overrides $CONTROLLER_ENV — this script will not silently fight an explicit override."
  elif [ "$effective" != "$OLD_DIR" ] && [ "$effective" != "$NEW_DIR" ]; then
    abort_migration "WIREMESH_DATA_DIR is $effective, neither the legacy $OLD_DIR nor the\
 packaged $NEW_DIR — that is your own layout and this script will not touch it."
  elif ! unit_grants_new_dir; then
    abort_migration "the effective wiremesh-controller.service does not declare\
 StateDirectory=wiremesh-controller (a \`systemctl edit --full\` override, most likely), so\
 ProtectSystem=strict would leave $NEW_DIR read-only. Run \`systemctl revert\
 wiremesh-controller\`, or add StateDirectory=wiremesh-controller to your override, first."
  else
    # COPY into a staging dir, verify, then flip it into place with a single
    # rename. Never move-then-fix-up: a crash midway through a move leaves the
    # data dir partially populated, and a controller that boots on a data dir
    # with NEITHER ca.pem nor ca.key mints a BRAND NEW CA (wiremesh-trust's
    # load_or_create_ca), silently invalidating every enrolled gateway. (The
    # half-CA case is already fail-closed there — it refuses to regenerate —
    # so the empty/partial dir is the one state worth engineering against.)
    # The rename takes $NEW_DIR from absent straight to complete with no
    # window in between, and the originals are deleted only after that.
    rm -rf "$STAGE" 2>/dev/null || true
    copy_ok=1
    if ! mkdir -p "$STAGE"; then
      copy_ok=0
    else
      for f in $CONTROLLER_ENTRIES; do
        if [ ! -e "$OLD_DIR/$f" ]; then continue; fi
        # -R -p (POSIX; -a is a GNU/BSD extension) preserves mode and, running
        # as root, ownership. Stop at the FIRST failure — carrying on would
        # build a partial staging dir whose later entries still verify.
        if ! cp -R -p "$OLD_DIR/$f" "$STAGE/$f"; then copy_ok=0; break; fi
        if ! verify_entry "$f"; then copy_ok=0; break; fi
      done
    fi

    if [ "$copy_ok" != 1 ]; then
      abort_migration "copying control-plane state into $STAGE failed or did not verify."
    elif [ -e "$NEW_DIR" ] && ! rmdir "$NEW_DIR" 2>/dev/null; then
      # Only reachable if $NEW_DIR gained content between the emptiness check
      # and here.
      abort_migration "$NEW_DIR is not an empty directory that can be replaced."
    elif ! mv "$STAGE" "$NEW_DIR"; then
      abort_migration "could not move $STAGE into place at $NEW_DIR."
    else
      chown -R wiremesh:wiremesh "$NEW_DIR" || say "WARNING could not chown $NEW_DIR to wiremesh:wiremesh"
      chmod 0700 "$NEW_DIR" || say "WARNING could not chmod 0700 $NEW_DIR"
      say "copied control-plane state $OLD_DIR -> $NEW_DIR (co-located gateway/relay files untouched)"

      # Point the config at it. Nothing to do in the deb case — the conffile
      # already says NEW_DIR. In the rpm case rewrite every legacy line; if the
      # setting was deleted outright, append it (the compiled default is
      # OLD_DIR, so leaving it unset would silently keep the old path).
      # Editing a conffile from a maintainer script does make dpkg treat it as
      # locally modified and prompt on the NEXT upgrade — unavoidable when the
      # value must change, and skipped entirely on the deb path.
      env_ok=1
      if [ "$(env_file_data_dir)" != "$NEW_DIR" ]; then
        if [ -f "$CONTROLLER_ENV" ] && [ -n "$(env_file_data_dir)" ]; then
          sed -i -E "s#^([[:space:]]*)WIREMESH_DATA_DIR=[\"']?$OLD_DIR[\"']?[[:space:]]*\$#\\1WIREMESH_DATA_DIR=$NEW_DIR#" \
              "$CONTROLLER_ENV" || true
        else
          printf '# Repointed by the wiremesh-controller postinstall (state moved out of %s).\nWIREMESH_DATA_DIR=%s\n' \
                 "$OLD_DIR" "$NEW_DIR" >> "$CONTROLLER_ENV" || true
        fi
        [ "$(env_file_data_dir)" = "$NEW_DIR" ] || env_ok=0
      fi

      if [ "$env_ok" != 1 ]; then
        # The copy is committed but the config still points at OLD_DIR, where
        # every original is still present — so the controller keeps working
        # exactly as before. Deliberately do NOT delete the originals here.
        say "WARNING copied the state to $NEW_DIR but could NOT repoint WIREMESH_DATA_DIR in" \
            "$CONTROLLER_ENV; the controller still runs from $OLD_DIR (unchanged and working)." \
            "Set WIREMESH_DATA_DIR=$NEW_DIR by hand, then delete controller.db/ca.key/secrets from $OLD_DIR."
      else
        for f in $CONTROLLER_ENTRIES; do
          case " $KEEP_IN_OLD_DIR " in *" $f "*) continue ;; esac
          if [ ! -e "$OLD_DIR/$f" ]; then continue; fi
          rm -rf "$OLD_DIR/$f" || say "WARNING could not remove the old copy of $f from $OLD_DIR"
        done
        say "migration complete; WIREMESH_DATA_DIR is $NEW_DIR — restart wiremesh-controller to apply."
        if [ -f "$OLD_DIR/relay.pem" ] || [ -f "$OLD_DIR/relay.key" ]; then
          say "NOTE a legacy relay identity is also in $OLD_DIR; its ca.pem was COPIED, not moved," \
              "so the relay and its own migration to /var/lib/wiremesh-relay are unaffected."
        fi
      fi
    fi
  fi
fi

# --- repair a host the OLD postinst already broke --------------------------
#
# Dropping the bad chown fixes new installs but does nothing for a host that
# was already hit: /var/lib/wiremesh stays wiremesh-owned 0700 and the
# root-but-no-CAP_DAC_OVERRIDE gateway keeps failing on identity.json.
# postinstall-gateway.sh chmods but never chowns, so it will not fix it
# either. Print the exact command rather than running it: when a legacy relay
# identity also lives here the directory genuinely cannot serve both (the
# relay runs as User=wiremesh and needs it wiremesh-owned), so which way to
# chown is the operator's call, not ours.
if [ -d "$OLD_DIR" ] && [ -f "$OLD_DIR/identity.json" ]; then
  owner=$(ls -ld "$OLD_DIR" 2>/dev/null | awk '{print $3}' || true)
  if [ "$owner" = "wiremesh" ]; then
    say "ACTION REQUIRED $OLD_DIR is owned by 'wiremesh' but holds a gateway identity." \
        "An earlier controller package chowned it away from the gateway, which cannot read it" \
        "(it runs as root but its unit drops CAP_DAC_OVERRIDE) and will crash-loop on" \
        "\"reading identity.json ... Permission denied\". Fix with:  chown root:root $OLD_DIR"
    if [ -f "$OLD_DIR/relay.pem" ]; then
      say "  ...but a legacy relay identity is ALSO in $OLD_DIR and needs it wiremesh-owned." \
          "Migrate the relay to /var/lib/wiremesh-relay first (reinstall/upgrade wiremesh-relay," \
          "or move ca.pem/relay.pem/relay.key there yourself), THEN chown this dir to root:root."
    fi
  fi
fi

echo "WireMesh: edit the config in /etc/wiremesh, then: systemctl enable --now <service>"
