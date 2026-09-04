#!/bin/bash
#
# Warp Agent CLI installer.
#
# Rendered by warp-server with an immutable channel, artifact endpoint,
# installation root, and command name.
#
# Installs use a versioned layout so the Warp Agent CLI's background
# auto-updater can stage new versions without touching the one currently
# running:
#
#     $WARP_TUI_INSTALL_DIR/
#       versions/<version>/       # binary + resources/ for each installed version
#       current                    # symlink to the active versions/<version>
#     $WARP_TUI_BIN_DIR/<cli-name> # symlink to current/warp-tui-<channel>
#
# Environment overrides:
#   WARP_TUI_VERSION       Version to install (default: latest for the channel).
#   WARP_TUI_DOWNLOAD_URL  Artifact endpoint.
#   WARP_TUI_INSTALL_DIR   Root of the versioned install layout described
#                          above.
#   WARP_TUI_BIN_DIR       Directory for the CLI symlink on PATH
#                          (default: ~/.local/bin).

set -euo pipefail

CHANNEL="stable"
DOWNLOAD_URL="${WARP_TUI_DOWNLOAD_URL:-https://app.warp.dev/download/agent-cli/artifact}"
DEFAULT_INSTALL_DIR="$HOME/.warp/tui"
INSTALL_DIR="${WARP_TUI_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
BIN_DIR="${WARP_TUI_BIN_DIR:-$HOME/.local/bin}"
CLI_NAME="warp"

err() {
    echo "error: $*" >&2
    exit 1
}

case "$(uname -s)" in
    Darwin)
        OS="macos"
        ;;
    Linux)
        OS="linux"
        ;;
    *)
        err "unsupported operating system: $(uname -s) (expected Darwin or Linux)."
        ;;
esac

# Map the machine architecture to the release naming (aarch64 / x86_64).
case "$(uname -m)" in
    arm64 | aarch64)
        ARCH="aarch64"
        ;;
    x86_64)
        ARCH="x86_64"
        ;;
    *)
        err "unsupported architecture: $(uname -m) (expected arm64 or x86_64)."
        ;;
esac

BINARY_NAME="warp-tui-$CHANNEL"
LEGACY_INSTALL_DIR="$HOME/.warp/tui"

URL="$DOWNLOAD_URL?os=$OS&arch=$ARCH"
if [[ -n "${WARP_TUI_VERSION:-}" ]]; then
    URL="$URL&version=$WARP_TUI_VERSION"
fi

# Resolve the artifact URL up front instead of letting curl follow the 302.
# The redirect target embeds the exact version being installed
# (<channel>/<version>/tui/<os>/<arch>/...), which names the version
# directory below and pins the download so the "latest" version can't change
# between resolution and download.
ARTIFACT_URL="$(curl -fsS -o /dev/null -w '%{redirect_url}' "$URL")" \
    || err "failed to resolve the Warp Agent CLI download for the $CHANNEL channel."
VERSION="$(sed -n 's#.*/\([^/]*\)/tui/.*#\1#p' <<< "$ARTIFACT_URL")"
if [[ -z "$VERSION" ]]; then
    err "could not determine the Warp Agent CLI version from the download URL."
fi
# $VERSION names a directory that is later created, so reject anything that
# could escape versions/ (e.g. "..") or misbehave in shell commands before
# using it in a path.
if [[ ! "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ || "$VERSION" == *..* ]]; then
    err "refusing to install: unexpected version '$VERSION' in the download URL."
fi

VERSIONS_DIR="$INSTALL_DIR/versions"
VERSION_DIR="$VERSIONS_DIR/$VERSION"
CURRENT_LINK="$INSTALL_DIR/current"
UPDATE_LOCK="$INSTALL_DIR/.update.lock"
UPDATE_LOCK_OWNER=""
STALE_LOCK_PREFIX="$INSTALL_DIR/.update.lock.stale"
STALE_LOCK_AGE_SECONDS=$((60 * 60))

release_update_lock() {
    if [[ -z "$UPDATE_LOCK_OWNER" || ! -f "$UPDATE_LOCK" || -L "$UPDATE_LOCK" ]]; then
        return 0
    fi
    if [[ "$(cat "$UPDATE_LOCK" 2>/dev/null || true)" != "$UPDATE_LOCK_OWNER" ]]; then
        return 0
    fi
    rm -f "$UPDATE_LOCK"
    UPDATE_LOCK_OWNER=""
}

cleanup() {
    rm -rf "$STAGING_DIR" || true
    release_update_lock || true
}

lock_modified_at() {
    if [[ "$OS" == "macos" ]]; then
        stat -f '%m' "$1" 2>/dev/null
    else
        stat -c '%Y' "$1" 2>/dev/null
    fi
}

lock_identity() {
    local path="$1"
    local kind
    local metadata
    local owner

    if [[ -d "$path" && ! -L "$path" ]]; then
        kind="directory"
        owner="$(cat "$path/owner" 2>/dev/null || true)"
    elif [[ -f "$path" && ! -L "$path" ]]; then
        kind="file"
        owner="$(cat "$path" 2>/dev/null || true)"
    else
        return 1
    fi
    if [[ "$OS" == "macos" ]]; then
        metadata="$(stat -f '%d:%i:%m:%z' "$path" 2>/dev/null)" || return 1
    else
        metadata="$(stat -c '%d:%i:%Y:%s' "$path" 2>/dev/null)" || return 1
    fi
    printf '%s:%s:%s' "$kind" "$metadata" "$owner"
}

acquire_update_lock() {
    local attempt
    local identity
    local identity_hash
    local lock_modified
    local lock_age
    local now
    local stale_lock

    UPDATE_LOCK_OWNER="installer-$$-$(date +%s)-$RANDOM"
    for attempt in 1 2; do
        # A regular file remains compatible with deployed Rust updaters. Bash
        # noclobber makes creation exclusive without requiring `flock`.
        if (set -o noclobber; printf '%s' "$UPDATE_LOCK_OWNER" > "$UPDATE_LOCK") 2>/dev/null; then
            return
        fi
        if [[ ! -e "$UPDATE_LOCK" && ! -L "$UPDATE_LOCK" ]]; then
            continue
        fi
        identity="$(lock_identity "$UPDATE_LOCK" || true)"
        lock_modified="$(lock_modified_at "$UPDATE_LOCK" || true)"
        now="$(date +%s)"
        if [[ "$attempt" -eq 1 &&
            -n "$identity" &&
            "$lock_modified" =~ ^[0-9]+$ &&
            "$now" =~ ^[0-9]+$ ]]; then
            lock_age=$((now - lock_modified))
            if [[ "$lock_age" -gt "$STALE_LOCK_AGE_SECONDS" ]]; then
                identity_hash="$(printf '%s' "$identity" | cksum | awk '{print $1 "-" $2}')"
                stale_lock="$STALE_LOCK_PREFIX.$identity_hash"
                if [[ ! -e "$stale_lock" && ! -L "$stale_lock" ]]; then
                    mv -n "$UPDATE_LOCK" "$stale_lock" 2>/dev/null || true
                fi
                if [[ "$(lock_identity "$stale_lock" || true)" == "$identity" ]]; then
                    echo "Recovering stale Warp Agent CLI install lock at $UPDATE_LOCK..." >&2
                    # Keep the generation-specific tombstone so another
                    # process that observed this stale owner cannot move a
                    # freshly acquired successor lock.
                    continue
                fi
            fi
        fi

        UPDATE_LOCK_OWNER=""
        err "another Warp Agent CLI installation or update is already in progress."
    done

    UPDATE_LOCK_OWNER=""
    err "another Warp Agent CLI installation or update is already in progress."
}

# Stage the download + extraction next to the final version dir so an
# existing, working install is only touched once the new build has been fully
# downloaded, extracted, and validated. Staging on the same filesystem as
# $VERSIONS_DIR keeps the final swap a quick rename. Mirrors the Oz CLI
# installer.
mkdir -p "$VERSIONS_DIR"
STAGING_DIR="$(mktemp -d "$VERSIONS_DIR/.warp-tui-install.XXXXXX")"
trap cleanup EXIT

echo "Downloading Warp Agent CLI $VERSION ($CHANNEL, $OS/$ARCH)..."
if ! curl -fSL "$ARTIFACT_URL" -o "$STAGING_DIR/warp-tui.tar.gz"; then
    err "failed to download the Warp Agent CLI for the $CHANNEL channel."
fi

echo "Unpacking..."
# The tarball contains the renamed binary (`warp-tui-<channel>`) plus a sibling
# `resources/` tree. The binary resolves `resources/` relative to its own
# location at runtime, so they must be installed together.
PAYLOAD_DIR="$STAGING_DIR/payload"
mkdir -p "$PAYLOAD_DIR"
tar xzf "$STAGING_DIR/warp-tui.tar.gz" -C "$PAYLOAD_DIR"

# Validate the payload before replacing any existing install.
if [[ ! -f "$PAYLOAD_DIR/$BINARY_NAME" ]]; then
    err "downloaded archive did not contain expected binary '$BINARY_NAME'."
fi
if [[ ! -d "$PAYLOAD_DIR/resources" ]]; then
    err "downloaded archive did not contain the expected 'resources/' directory."
fi
chmod +x "$PAYLOAD_DIR/$BINARY_NAME"

if [[ "$OS" == "macos" ]]; then
    # Standalone (non-app-bundle) binaries can't have a notarization ticket
    # stapled, so clear quarantine to avoid a first-run Gatekeeper prompt.
    xattr -dr com.apple.quarantine "$PAYLOAD_DIR" 2>/dev/null || true
fi
# Downloads and validation intentionally happen before taking the shared
# cross-language install lock. The lock only protects immutable-version
# finalization and the atomic `current` swap.
acquire_update_lock

# Completed versions are immutable. Another installer may have completed this
# exact version while this process was downloading it; reuse a valid install,
# but never replace an incomplete or unexpected path because a live process
# may still depend on it.
if [[ -e "$VERSION_DIR" || -L "$VERSION_DIR" ]]; then
    if [[ -d "$VERSION_DIR" &&
        ! -L "$VERSION_DIR" &&
        -f "$VERSION_DIR/$BINARY_NAME" &&
        -x "$VERSION_DIR/$BINARY_NAME" &&
        ! -L "$VERSION_DIR/$BINARY_NAME" &&
        -d "$VERSION_DIR/resources" &&
        ! -L "$VERSION_DIR/resources" ]]; then
        echo "Reusing existing Warp Agent CLI $VERSION at $VERSION_DIR..."
    else
        err "refusing to replace invalid existing version at $VERSION_DIR; remove it manually and retry."
    fi
else
    echo "Installing to $VERSION_DIR..."
    if ! mv "$PAYLOAD_DIR" "$VERSION_DIR"; then
        err "failed to install the Warp Agent CLI into $VERSION_DIR."
    fi
fi

# Atomically point `current` at the selected version: build the symlink aside,
# then rename it over the old one. Avoids a window where `current` is missing
# or dangling. BSD and GNU mv use different flags to replace a symlink itself.
NEW_CURRENT_LINK="$INSTALL_DIR/.current.new"
rm -rf "$NEW_CURRENT_LINK"
ln -s "versions/$VERSION" "$NEW_CURRENT_LINK"
if [[ "$OS" == "macos" ]]; then
    # Earlier mv calls may have cached a user-provided executable from PATH.
    hash -r
    command -p mv -fh "$NEW_CURRENT_LINK" "$CURRENT_LINK" || err "failed to activate Warp Agent CLI $VERSION."
elif ! mv -fT "$NEW_CURRENT_LINK" "$CURRENT_LINK"; then
    err "failed to activate Warp Agent CLI $VERSION."
fi
release_update_lock

echo "Linking $BIN_DIR/$CLI_NAME..."
mkdir -p "$BIN_DIR"
if [[ "$CHANNEL" == "dev" ]]; then
    previous_warp_target="$(readlink "$BIN_DIR/warp" 2>/dev/null || true)"
    if [[ "$previous_warp_target" == "$CURRENT_LINK/$BINARY_NAME" ||
        "$previous_warp_target" == "$LEGACY_INSTALL_DIR/current/$BINARY_NAME" ]]; then
        rm -f "$BIN_DIR/warp"
    fi
fi
ln -sf "$CURRENT_LINK/$BINARY_NAME" "$BIN_DIR/$CLI_NAME"

echo ""
echo "Warp Agent CLI $VERSION installed to $VERSION_DIR"
echo "Run it with: $CLI_NAME"

# Nudge the user if the bin dir isn't on PATH yet.
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        echo ""
        echo "note: $BIN_DIR is not on your PATH. Add it, e.g.:"
        if [[ "${SHELL:-}" == */zsh ]]; then
            SHELL_RC="$HOME/.zshrc"
        else
            SHELL_RC="$HOME/.bashrc"
        fi
        echo "    echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> $SHELL_RC && source $SHELL_RC"
        ;;
esac