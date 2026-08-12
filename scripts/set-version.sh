#!/usr/bin/env bash
# Rewrite the [package] version of the crates we ship as release artifacts so the
# built binaries self-report the release version (`--version`). Portable across
# the Linux/macOS/Windows(git-bash) runners via perl (sed -i is not portable).
#
#   scripts/set-version.sh 1.2.3        # or  v1.2.3  (leading v is stripped)
#
# Path deps carry no version requirement, so bumping these is safe and needs no
# dependent edits. Only the FIRST `version = "..."` (the [package] one) is touched.
set -euo pipefail

VERSION="${1:?usage: set-version.sh <version>}"
VERSION="${VERSION#v}"

# Require MAJOR.MINOR.PATCH with an optional -prerelease and/or +build suffix
# (accepts 1.2.3, 0.0.0-dev, 1.2.3-rc.1, 1.2.3+build; rejects "", foo, 1, 1..2, +).
if ! printf '%s' "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
  echo "set-version: '$VERSION' is not MAJOR.MINOR.PATCH[-prerelease][+build]" >&2
  exit 1
fi

# Every crate that produces a shipped artifact. wiremesh-operator ships as the
# ghcr.io/<owner>/wiremesh-operator container image (the `component:` matrix in
# .github/workflows/container-images.yml) and was missing here, so the operator
# reported 0.1.0 on every release.
for crate in fabricctl wiremesh-controller wiremesh-gateway wiremesh-operator wiremesh-relay; do
  f="crates/$crate/Cargo.toml"
  [ -f "$f" ] || { echo "set-version: $f not found" >&2; exit 1; }
  # First `version = "..."` only ($seen starts undef per perl invocation).
  V="$VERSION" perl -i -pe 'if (!$seen && /^version\s*=\s*"/) { s/"[^"]*"/"$ENV{V}"/; $seen=1 }' "$f"
  # Verify the substitution actually landed — a moved/renamed [package] version
  # line would otherwise silently ship a stale version. Fixed-string match so a
  # version like 1.2.3+build isn't misread as a regex.
  if ! grep -qF "\"$VERSION\"" "$f"; then
    echo "set-version: FAILED to set version in $f (no version = \"...\" produced)" >&2
    exit 1
  fi
  echo "set $crate version -> $VERSION"
done
