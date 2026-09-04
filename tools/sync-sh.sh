#!/bin/sh
# Regenerates third_party/sh: the trimmed, patched copy of mvdan.cc/sh/v3 that
# the root go.mod points at with a `replace` directive.
#
# The directory is a build product and is not tracked in git. Source of truth:
#   - the mvdan.cc/sh/v3 version required in go.mod (content pinned by go.sum)
#   - patches/sh/*.patch, applied in name order with `patch -p1`
#
# Run from the repo root, or via `go generate ./...`.
set -eu

cd "$(dirname "$0")/.."

mod=mvdan.cc/sh/v3
dst=third_party/sh
pkgs="expand fileutil internal interp pattern syntax"

ver=$(go mod edit -json | tr -d '\n' | sed -n 's/.*"Path":[[:space:]]*"mvdan\.cc\/sh\/v3",[[:space:]]*"Version":[[:space:]]*"\([^"]*\)".*/\1/p')
[ -n "$ver" ] || { echo "sync-sh: $mod not found in go.mod require block" >&2; exit 1; }

# -mod=mod: the replace target may not exist yet, so don't let go consult it.
src=$(GOFLAGS=-mod=mod go mod download -json "$mod@$ver" | sed -n 's/.*"Dir": *"\([^"]*\)".*/\1/p')
[ -d "$src" ] || { echo "sync-sh: module download failed for $mod@$ver" >&2; exit 1; }

echo "sync-sh: $mod $ver -> $dst"
rm -rf "$dst"
mkdir -p "$dst"
for p in $pkgs; do cp -R "$src/$p" "$dst/$p"; done
cp "$src/go.mod" "$src/go.sum" "$src/LICENSE" "$dst/"
chmod -R u+w "$dst"

find "$dst" -name '*_test.go' -delete
find "$dst" -type d -name testdata -prune -exec rm -rf {} +

for p in patches/sh/*.patch; do
	echo "sync-sh: applying $p"
	patch -p1 -s -N -d "$dst" < "$p"
done

echo "sync-sh: done"
