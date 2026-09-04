# Local task runner. `just` lists recipes; `just ci` runs what CI runs.

set shell := ["sh", "-eu", "-c"]

release_targets := "linux/amd64 linux/arm64 darwin/amd64 darwin/arm64"

# List recipes.
default:
    @just --list --unsorted

# A fresh clone will not build until this has run once (see patches/sh/README.md).
# Regenerate third_party/sh: pinned mvdan.cc/sh, trimmed and patched.
sync:
    sh tools/sync-sh.sh

# Regenerate third_party/sh only if it is missing.
_ensure-sh:
    @[ -d third_party/sh ] || sh tools/sync-sh.sh

# Build the smash binary into ./smash.
build: _ensure-sh
    go build -o smash ./cmd/smash

# Run smash with the given arguments, e.g. `just run -- --help`.
run *args: _ensure-sh
    go run ./cmd/smash {{args}}

# Install smash into $GOBIN / $GOPATH/bin.
install: _ensure-sh
    go install ./cmd/smash

# Run the test suite. Extra args are passed to `go test`, e.g. `just test -run TestNoclobber`.
test *args: _ensure-sh
    go test -count=1 ./... {{args}}

# Run the tests under the race detector (a CI gate: the audit log is written concurrently).
race *args: _ensure-sh
    go test -race -count=1 ./... {{args}}

# gofmt every tracked Go file in place.
fmt:
    gofmt -w $(git ls-files '*.go')

# Fail if any tracked Go file is not gofmt-clean.
fmt-check:
    #!/bin/sh
    set -eu
    out=$(gofmt -l $(git ls-files '*.go'))
    if [ -n "$out" ]; then
        echo "files need gofmt:" >&2
        echo "$out" >&2
        exit 1
    fi

# go vet.
vet: _ensure-sh
    go vet ./...

# Fail if go.mod / go.sum are not tidy.
tidy-check: _ensure-sh
    go mod tidy
    git diff --exit-code -- go.mod go.sum

# Run staticcheck (not a CI gate yet: two deprecation findings outstanding).
lint: _ensure-sh
    go run honnef.co/go/tools/cmd/staticcheck@latest ./...

# Cross-compile every release target to /dev/null.
cross: _ensure-sh
    #!/bin/sh
    set -eu
    for target in {{release_targets}}; do
        echo "== $target"
        GOOS=${target%/*} GOARCH=${target#*/} CGO_ENABLED=0 go build -o /dev/null ./cmd/smash
    done

# Build release tarballs into dist/ for every target. VERSION defaults to `git describe`.
dist version=`git describe --tags --always --dirty`: _ensure-sh
    #!/bin/sh
    set -eu
    rm -rf dist
    # yaml.v3 is linked in but not vendored, so its licence comes from the
    # module cache. mvdan/sh's is in the tree, under third_party.
    # The doubled opening braces are just's escape for the one brace pair
    # go's -f template needs.
    yaml_license="$(go list -m -f '{{{{.Dir}}' gopkg.in/yaml.v3)/LICENSE"
    for target in {{release_targets}}; do
        goos=${target%/*}; goarch=${target#*/}
        name="smash_{{version}}_${goos}_${goarch}"
        echo "== $name"
        mkdir -p "dist/$name"
        GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 \
            go build -trimpath -ldflags="-s -w" -o "dist/$name/smash" ./cmd/smash
        cp README.md "dist/$name/"
        cp third_party/sh/LICENSE "dist/$name/LICENSE.mvdan-sh"
        cp "$yaml_license" "dist/$name/LICENSE.yaml.v3"
        tar -C dist -czf "dist/$name.tar.gz" "$name"
    done
    (cd dist && shasum -a 256 *.tar.gz > checksums.txt && cat checksums.txt)

# The pushed tag triggers .github/workflows/release.yml to build and publish binaries.
# Cut a release: run the CI checks, tag `version` (vX.Y.Z), and push the tag.
release version: ci
    #!/bin/sh
    set -eu
    case "{{version}}" in
        v[0-9]*.[0-9]*.[0-9]*) ;;
        *) echo "release: version must look like v1.2.3, got '{{version}}'" >&2; exit 1 ;;
    esac
    if [ -n "$(git status --porcelain)" ]; then
        echo "release: working tree is not clean" >&2; exit 1
    fi
    if git rev-parse -q --verify "refs/tags/{{version}}" >/dev/null; then
        echo "release: tag {{version}} already exists" >&2; exit 1
    fi
    git tag -a "{{version}}" -m "{{version}}"
    git push origin "{{version}}"
    echo "release: pushed {{version}}; watch the Release workflow on GitHub"

# Everything the required CI jobs check: fmt, tidy, vet, build, test, race, cross-compile.
ci: fmt-check tidy-check vet cross test race

# Remove build products: the binary, dist/, and the generated third_party/sh.
clean:
    rm -rf smash dist third_party/sh
