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
# config and the data consistent across every abort path — but BOTH package
# managers silently replace an UNMODIFIED controller.env before any script of
# ours runs (dpkg during unpack; rpm too, because %config(noreplace) only
# protects a file whose checksum changed), so the config was ALREADY pointing
# at the new dir, and every abort left it pointing somewhere empty. A
# controller starting on an empty data dir
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

# `ca.key` is THE marker for "a real controller lives here". Deliberately not
# `controller.db` as well:
#   - controller.db is not evidence of anything. The controller opens (and
#     fully migrates) its DB before the CA guard gets a chance to refuse, so a
#     single boot against the wrong directory leaves a complete, empty schema
#     behind. Accepting it made a mis-started NEW_DIR look permanently
#     occupied, which silently disabled the pin below — forever, and with no
#     message at all.
#   - ca.pem is not usable either: a legacy relay identity is ca.pem +
#     relay.pem + relay.key in this same shared directory, so ca.pem would
#     false-positive on a relay-only host.
# ca.key is written by neither the gateway nor the relay, and a controller
# cannot run without it.
has_controller_state() {
  [ -f "$1/ca.key" ]
}

# The LAST WIREMESH_DATA_DIR= value in the EnvironmentFile (systemd keeps the
# last assignment when a variable is set more than once), quotes stripped.
# Empty when the file is absent or never sets it.
env_file_data_dir() {
  [ -f "$CONTROLLER_ENV" ] || return 0
  sed -n -E "s/^[[:space:]]*WIREMESH_DATA_DIR=[\"']?([^\"'[:space:]]*)[\"']?[[:space:]]*\$/\\1/p" \
      "$CONTROLLER_ENV" | tail -n 1
}

# Any `Environment=WIREMESH_DATA_DIR=` a drop-in sets — reported to the
# operator, never acted on.
#
# The EnvironmentFile WINS over Environment=. systemd.exec(5), under
# EnvironmentFile=, is explicit: "Settings from these files override settings
# made with Environment=." (Verified against systemd v252, the reverse of what
# an earlier revision of this script assumed — that mistake made the script
# skip the pin whenever a drop-in existed, leaving the effective data dir at
# the empty new directory while printing a reassuring message saying
# otherwise.) So controller.env is authoritative and a drop-in is inert
# noise; it is still worth naming, because an operator who wrote one almost
# certainly believes it is doing something.
#
# `--value` strips the property name (without it the FIRST variable in the
# list hides behind `Environment=`), and `xargs -n1` splits the list the way
# systemd quoted it — a value containing whitespace comes back shell-quoted,
# e.g. `OTHER=x "WIREMESH_DATA_DIR=/srv/wm dir"`, which a bare `tr ' ' '\n'`
# would split straight through the quotes and miss. xargs is findutils:
# Essential on Debian, @core on RHEL, and declared for rpm in controller.yaml.
# If it were somehow missing this yields an empty answer, which only costs the
# informational note below — the pin itself does not depend on it.
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
    # NOT `sed -i`: on a config-managed host /etc/wiremesh/controller.env is
    # often a symlink into /etc/puppet, /etc/ansible, a git checkout... and
    # `sed -i` would silently replace the symlink with a regular file,
    # detaching it from the thing that manages it. (`--follow-symlinks` fixes
    # that but is GNU-only.) Transform into a temp file, then `cat` it back
    # over the original — a write THROUGH the symlink, preserving the link,
    # the inode, the owner and the mode.
    pin_tmp="$CONTROLLER_ENV.wiremesh-pin.$$"
    if sed -E "s#^([[:space:]]*)WIREMESH_DATA_DIR=.*#\\1WIREMESH_DATA_DIR=$OLD_DIR#" \
           "$CONTROLLER_ENV" > "$pin_tmp" 2>/dev/null; then
      cat "$pin_tmp" > "$CONTROLLER_ENV" || true
    fi
    rm -f "$pin_tmp" || true
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
  # The EnvironmentFile is authoritative (see systemd_env_data_dir), so this
  # decision is made from it ALONE. A drop-in cannot change the outcome and is
  # only reported afterwards.
  case "$(env_file_data_dir)" in
    "$OLD_DIR")
      # Already correct. Something made this file locally modified — an
      # operator edit, or a previous run of the pin below — so rpm kept it
      # (dropping a .rpmnew alongside) and dpkg either kept it or prompted and
      # was told to. Nothing to write; re-running must be a no-op.
      say "existing control-plane state in $OLD_DIR; WIREMESH_DATA_DIR already points at it."
      ;;
    ""|"$NEW_DIR")
      # The package just replaced an UNMODIFIED config with the new default
      # (both dpkg and rpm do this — see the header of controller.env), or the
      # setting was deleted outright. Either way, put this host back on its
      # own state.
      pin_to_old_dir
      ;;
    *)
      # A path we do not manage. Warned, not noted: if it is wrong the
      # controller either refuses to start (CA guard) or starts on the wrong
      # state, and nothing else here will catch it.
      warn "there is control-plane state in $OLD_DIR, but WIREMESH_DATA_DIR is" \
           "$(env_file_data_dir) — your own layout, left untouched. Confirm it is correct" \
           "before starting the controller."
      ;;
  esac

  # Purely informational. A drop-in `Environment=` is overridden by the
  # EnvironmentFile, so it changes nothing — but whoever added it thinks it
  # does, and if it disagrees they should know it is inert.
  dropin_dir=$(systemd_env_data_dir)
  if [ -n "$dropin_dir" ]; then
    effective=$(env_file_data_dir)
    [ -n "$effective" ] || effective=$OLD_DIR
    if [ "$dropin_dir" = "$effective" ]; then
      say "note: a systemd drop-in also sets Environment=WIREMESH_DATA_DIR=$dropin_dir." \
          "It agrees with $CONTROLLER_ENV, which takes precedence regardless."
    else
      warn "a systemd drop-in sets Environment=WIREMESH_DATA_DIR=$dropin_dir, but" \
           "EnvironmentFile= overrides Environment= in systemd, so the effective value is" \
           "$effective (from $CONTROLLER_ENV). The drop-in has NO effect — delete it, or move" \
           "the setting into $CONTROLLER_ENV, so the two stop disagreeing."
    fi
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
  owner=$(stat -c %U "$OLD_DIR" 2>/dev/null || true)
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
