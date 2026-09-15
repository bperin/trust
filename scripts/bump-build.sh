#!/usr/bin/env bash
# bump-build.sh — increment BUILD_NUMBER and rewrite the README build
# badge and Build section.
#
# Runs in CI on every push to main (build-number.yml). The commit it
# produces carries [skip ci] so the bump workflow does not re-trigger
# itself. Fails loudly if the badge line or build markers are missing,
# so a renamed README section cannot silently stop the bump.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
num_file="$root/BUILD_NUMBER"
readme="$root/README.md"

[ -f "$num_file" ] || { echo "FAIL: $num_file not found" >&2; exit 1; }
[ -f "$readme" ] || { echo "FAIL: $readme not found" >&2; exit 1; }

read -r num < "$num_file"
case "$num" in
	'' | *[!0-9]*) echo "FAIL: BUILD_NUMBER is not an integer (got: '$num')" >&2; exit 1 ;;
esac

num=$((num + 1))
date="$(date -u +%Y-%m-%d)"
printf '%d\n' "$num" > "$num_file"

export BN="$num" BDATE="$date"

perl -pi -e 's/(\[!\[Build\]\(https:\/\/img\.shields\.io\/badge\/build-)\d+(-[0-9a-f]+\)\]\([^)]*\))/${1}$ENV{BN}${2}/' "$readme"

perl -0pi -e 's/<!-- build:start -->.*<!-- build:end -->/<!-- build:start -->\n\n## Build\n\nCurrent build: **$ENV{BN}** ($ENV{BDATE}). The build number increments automatically on every push to `main` — see\n[`.github\/workflows\/build-number.yml`](.github\/workflows\/build-number.yml).\n\n<!-- build:end -->/s' "$readme"

grep -q "badge/build-${num}-" "$readme" || { echo "FAIL: build badge not updated to ${num}" >&2; exit 1; }
grep -q "Current build: \*\*${num}\*\*" "$readme" || { echo "FAIL: build section not updated to ${num}" >&2; exit 1; }

echo "build number bumped to ${num} (${date})"
