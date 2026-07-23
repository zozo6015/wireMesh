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

# Reject anything that isn't a plain semver-ish token (defends the perl substitution).
case "$VERSION" in
  *[!0-9A-Za-z.+-]*) echo "set-version: refusing suspicious version '$VERSION'" >&2; exit 1 ;;
esac

for crate in fabricctl wiremesh-controller wiremesh-gateway wiremesh-relay; do
  f="crates/$crate/Cargo.toml"
  [ -f "$f" ] || { echo "set-version: $f not found" >&2; exit 1; }
  # First `version = "..."` only ($seen starts undef per perl invocation).
  V="$VERSION" perl -i -pe 'if (!$seen && /^version\s*=\s*"/) { s/"[^"]*"/"$ENV{V}"/; $seen=1 }' "$f"
  echo "set $crate version -> $VERSION"
done
