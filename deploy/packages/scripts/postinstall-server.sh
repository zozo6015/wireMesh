#!/bin/sh
# wiremesh-controller postinstall (deb AND rpm — POSIX sh, no bashisms).
#
# Creates the shared service account + /etc/wiremesh, and decides ONE thing:
# which data dir this host's controller uses.
#
#   - Fresh install (no controller state anywhere): the new default,
#     /var/lib/wiremesh-controller. This is what fixes the co-located-gateway
#     bug — /var/lib/wiremesh belongs to the gateway (px migration finding,
#     2026-08-01, docs/runbooks/controller-migration-to-fi.md).
#   - Existing install (state already in /var/lib/wiremesh): PIN the config to
#     it and leave every byte where it is.
#
# This script NEVER moves, copies or deletes control-plane state. That is a
# deliberate reversal of an earlier design: an automatic migration has to copy
# a live SQLite DB out from under a running controller, and it has to keep the
# config and the data consistent across every abort path — but on deb, where
# dpkg silently replaces an unmodified conffile during unpack, the config was
# ALREADY pointing at the new dir before the script even ran, so every abort
# left it pointing somewhere empty. A controller starting on an empty data dir
# used to mint a BRAND-NEW CA and invalidate every enrolled gateway. Pinning
# has no such failure mode: there is no window in which the config and the
# data can disagree, because neither ever moves. (Belt and braces,
# wiremesh-trust's load_or_create_ca now also refuses to mint a CA when it
# finds an existing one at the legacy path.)
#
# Splitting a co-located host is therefore a MANUAL, service-down procedure —
# see docs/install.md. A human doing it with the controller stopped has none
# of the problems an unattended maintainer script has.
#
# CONTRACT: never exit non-zero. A half-configured package is worse than an
# unpinned one, so every step is guarded and every refusal prints what to do.
set -e

OLD_DIR=/var/lib/wiremesh
NEW_DIR=/var/lib/wiremesh-controller
CONTROLLER_ENV=/etc/wiremesh/controller.env

say()  { echo "WireMesh controller: $*"; }
warn() { echo "WireMesh controller: WARNING $*" >&2; }

# --- service account + config dir ------------------------------------------

# Guarded: a failure here means the service will not start, but it must still
# not abort the package transaction and leave dpkg/rpm half-configured — the
# warning is loud and names the consequence instead.
# Home dir stays /var/lib/wiremesh so this useradd is byte-identical to the
# relay package's (whichever package installs first creates the shared
# account; a divergent --home-dir would make it depend on install order). The
# controller never uses $HOME — its state lives in WIREMESH_DATA_DIR.
getent group wiremesh >/dev/null 2>&1 || groupadd --system wiremesh ||
  warn "could not create the 'wiremesh' group; wiremesh-controller.service will not start."
getent passwd wiremesh >/dev/null 2>&1 ||
  useradd --system --gid wiremesh --home-dir /var/lib/wiremesh \
          --shell /usr/sbin/nologin --comment "WireMesh" wiremesh ||
  warn "could not create the 'wiremesh' user; wiremesh-controller.service will not start."
mkdir -p /etc/wiremesh || warn "could not create /etc/wiremesh."

# NOTE: this script deliberately does NOT create or chown /var/lib/wiremesh.
# It used to (`chown wiremesh:wiremesh` + `chmod 0700`), which STOLE the
# directory from a co-located wiremesh-gateway — the gateway keeps its
# identity there, runs as root but with a CapabilityBoundingSet lacking
# CAP_DAC_OVERRIDE, so a 0700 dir owned by `wiremesh` genuinely locked it out
# and it crash-looped on "reading identity.json ... Permission denied".
# /var/lib/wiremesh-controller is created and owned by systemd's
# StateDirectory= in the unit.

# Reload before querying systemd below: the new unit is already unpacked, and
# `systemctl show` answers from what systemd last read, not from what is on
# disk.
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi

# --- which data dir does this host use? ------------------------------------

# `controller.db` and `ca.key` are the two entries no controller can run
# without, and neither name is written by the gateway or the relay. (ca.pem
# alone would NOT do: a legacy relay identity is ca.pem + relay.pem +
# relay.key in this same directory, so it would false-positive on a
# relay-only host.)
has_controller_state() {
  [ -f "$1/controller.db" ] || [ -f "$1/ca.key" ]
}

# The LAST WIREMESH_DATA_DIR= value in the EnvironmentFile (systemd keeps the
# last assignment when a variable is set more than once), quotes stripped.
# Empty when the file is absent or never sets it.
env_file_data_dir() {
  [ -f "$CONTROLLER_ENV" ] || return 0
  sed -n -E "s/^[[:space:]]*WIREMESH_DATA_DIR=[\"']?([^\"'[:space:]]*)[\"']?[[:space:]]*\$/\\1/p" \
      "$CONTROLLER_ENV" | tail -n 1
}

# A systemd `Environment=` assignment beats the EnvironmentFile (drop-ins are
# applied after the packaged unit), so when one exists, editing controller.env
# would change nothing and we must not pretend otherwise.
#
# `--value` strips the property name (without it the FIRST variable in the
# list hides behind `Environment=`), and `xargs -n1` splits the list the way
# systemd quoted it — a value containing whitespace comes back shell-quoted,
# e.g. `OTHER=x "WIREMESH_DATA_DIR=/srv/wm dir"`, which a bare `tr ' ' '\n'`
# would split straight through the quotes and miss.
systemd_env_data_dir() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl show --value -p Environment wiremesh-controller 2>/dev/null |
    xargs -n1 2>/dev/null |
    sed -n -E "s/^WIREMESH_DATA_DIR=(.*)\$/\\1/p" | tail -n 1
}

# Write WIREMESH_DATA_DIR=$OLD_DIR into the EnvironmentFile, replacing every
# existing assignment (there may be more than one; systemd honours the last,
# so all of them have to go) or appending one if the setting was deleted
# outright — the compiled-in default is $OLD_DIR too, but relying on that
# would leave this host hostage to a future change of that default.
pin_to_old_dir() {
  if [ -n "$(env_file_data_dir)" ]; then
    sed -i -E "s#^([[:space:]]*)WIREMESH_DATA_DIR=.*#\\1WIREMESH_DATA_DIR=$OLD_DIR#" \
        "$CONTROLLER_ENV" || true
  else
    printf '# Pinned by the wiremesh-controller postinstall: this host already had\n# control-plane state here when the packaged default moved to %s.\nWIREMESH_DATA_DIR=%s\n' \
           "$NEW_DIR" "$OLD_DIR" >> "$CONTROLLER_ENV" || true
  fi
  if [ "$(env_file_data_dir)" = "$OLD_DIR" ]; then
    say "existing control-plane state found in $OLD_DIR — pinned WIREMESH_DATA_DIR to it." \
        "Nothing was moved. To give the controller a directory of its own later, see the" \
        "manual (service-down) procedure in docs/install.md."
  else
    warn "this host's control-plane state is in $OLD_DIR but WIREMESH_DATA_DIR could not be" \
         "pinned in $CONTROLLER_ENV. Set WIREMESH_DATA_DIR=$OLD_DIR by hand BEFORE starting" \
         "the controller."
  fi
}

if has_controller_state "$OLD_DIR" && ! has_controller_state "$NEW_DIR"; then
  dropin_dir=$(systemd_env_data_dir)
  if [ -n "$dropin_dir" ]; then
    # An explicit override beats anything we could write here, so report what
    # we see and stop. Only worth a warning when it disagrees with the data.
    if [ "$dropin_dir" = "$OLD_DIR" ]; then
      say "a systemd drop-in already sets WIREMESH_DATA_DIR=$dropin_dir, matching the state on disk."
    else
      warn "control-plane state is in $OLD_DIR but a systemd drop-in sets" \
           "WIREMESH_DATA_DIR=$dropin_dir. Leaving both alone — confirm that is what you want" \
           "before starting the controller."
    fi
  else
    case "$(env_file_data_dir)" in
      "$OLD_DIR")
        # rpm keeps the operator's %config(noreplace) file, so it usually
        # already says this. Nothing to write — and no conffile churn.
        say "existing control-plane state in $OLD_DIR; WIREMESH_DATA_DIR already points at it."
        ;;
      ""|"$NEW_DIR")
        # The deb path: dpkg silently replaced an unmodified conffile during
        # unpack, so it now reads the new default. Undo that for this host.
        pin_to_old_dir
        ;;
      *)
        say "NOTE there is control-plane state in $OLD_DIR, but WIREMESH_DATA_DIR is" \
            "$(env_file_data_dir) — your own layout, left untouched."
        ;;
    esac
  fi
fi

# --- repair a host the OLD postinst already broke --------------------------
#
# Dropping the bad chown fixes new installs but does nothing for a host that
# was already hit: /var/lib/wiremesh stays wiremesh-owned 0700 and the
# root-but-no-CAP_DAC_OVERRIDE gateway keeps failing on identity.json.
# postinstall-gateway.sh chmods but never chowns, so it will not fix it
# either. Print the exact command rather than running it — TWO reasons this
# stays the operator's call: a co-located legacy relay identity needs this
# directory wiremesh-owned (the relay runs as User=wiremesh), and on a pinned
# host the CONTROLLER's own ca.key/controller.db are in here too and need
# exactly the same access. No single ownership satisfies all three; only
# someone who knows what runs on this host can choose.
if [ -d "$OLD_DIR" ] && [ -f "$OLD_DIR/identity.json" ]; then
  owner=$(ls -ld "$OLD_DIR" 2>/dev/null | awk '{print $3}' || true)
  if [ "$owner" = "wiremesh" ]; then
    say "ACTION REQUIRED $OLD_DIR is owned by 'wiremesh' but holds a gateway identity." \
        "An earlier controller package chowned it away from the gateway, which cannot read it" \
        "(it runs as root but its unit drops CAP_DAC_OVERRIDE) and will crash-loop on" \
        "\"reading identity.json ... Permission denied\". Fix with:  chown root:root $OLD_DIR"
    if has_controller_state "$OLD_DIR" || [ -f "$OLD_DIR/relay.pem" ]; then
      say "  ...but this directory ALSO holds control-plane and/or relay state that must stay" \
          "readable by the 'wiremesh' user. Give the gateway a directory to itself first (move" \
          "the controller state per docs/install.md, and/or migrate the relay to" \
          "/var/lib/wiremesh-relay), THEN chown this one to root:root."
    fi
  fi
fi

echo "WireMesh: edit the config in /etc/wiremesh, then: systemctl enable --now <service>"
