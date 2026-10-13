#!/bin/sh
# Sediment installer for macOS and Linux.
#
#   curl -fsSL https://nyanites.github.io/sediment/install.sh | sh
#
# What it does, in order:
#   1. Downloads the latest Sediment release for your OS and CPU, and its
#      SHA256SUMS.txt, from https://github.com/Nyanites/sediment/releases
#   2. Checks the download against the published SHA-256 checksum and stops if it
#      doesn't match.
#   3. macOS: copies Sediment.app into /Applications (or ~/Applications if
#      /Applications isn't writable), replacing an older Sediment.app there.
#      Linux: installs the program to ~/.local/bin/sediment and adds a menu entry.
#   4. Cleans up its temporary files.
#
# It never asks for your password and changes nothing else on your computer.
#
# Options (environment variables):
#   SEDIMENT_VERSION=0.1.0       install a specific release instead of the latest
#   SEDIMENT_INSTALL_DIR=<dir>   install somewhere else
#
# Uninstall:
#   macOS: drag Sediment from Applications to the Trash.
#   Linux: rm ~/.local/bin/sediment ~/.local/share/applications/sediment.desktop \
#             ~/.local/share/icons/hicolor/256x256/apps/sediment.png
#
# Source: https://github.com/Nyanites/sediment/blob/main/docs/install.sh

SD_TMP=""

sd_cleanup() {
    if [ -n "$SD_TMP" ] && [ -d "$SD_TMP" ]; then
        rm -rf "$SD_TMP"
    fi
}

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[31mError:\033[0m %s\n' "$*" >&2; exit 1; }

fetch() {
    curl -fL --proto '=https' --tlsv1.2 --retry 3 "$@"
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    else
        shasum -a 256 "$1" | awk '{ print $1 }'
    fi
}

# Downloads release asset $1 into the temp dir and verifies it.
download() {
    say "Downloading $1"
    fetch --progress-bar -o "$SD_TMP/$1" "$base/$1" || fail "download failed"
    expected=$(awk -v f="$1" '$2 == f || $2 == "*" f { print $1 }' "$SD_TMP/SHA256SUMS.txt")
    [ -n "$expected" ] || fail "checksum for $1 not found in SHA256SUMS.txt"
    actual=$(sha256 "$SD_TMP/$1")
    [ "$expected" = "$actual" ] || fail "checksum mismatch for $1 (expected $expected, got $actual); not installing"
}

install_macos() {
    command -v ditto >/dev/null || fail "missing required tool: ditto"
    major=$(sw_vers -productVersion | cut -d. -f1)
    [ "$major" -ge 11 ] 2>/dev/null || fail "Sediment needs macOS 11 or newer."
    app="Sediment.app"
    dest="${SEDIMENT_INSTALL_DIR:-/Applications}"
    if [ -z "${SEDIMENT_INSTALL_DIR:-}" ] && [ ! -w "$dest" ]; then
        dest="$HOME/Applications"
    fi
    mkdir -p "$dest"
    [ -w "$dest" ] || fail "can't write to $dest"

    download Sediment-macos.zip
    say "Installing to $dest"
    mkdir -p "$SD_TMP/unpacked"
    ditto -x -k "$SD_TMP/Sediment-macos.zip" "$SD_TMP/unpacked" || fail "couldn't unpack the download"
    [ -d "$SD_TMP/unpacked/$app" ] || fail "$app not found in the download"
    if pgrep -xq sediment; then
        say "Quitting the running Sediment"
        osascript -e 'quit app "Sediment"' >/dev/null 2>&1 || true
        sleep 1
    fi
    # Replace only an existing Sediment.app, never anything else.
    if [ -d "$dest/$app" ]; then
        rm -rf "${dest:?}/$app"
    fi
    ditto "$SD_TMP/unpacked/$app" "$dest/$app"
    say "Sediment is installed in $dest"
    printf '    Open it from Launchpad or Applications, then drop in a $MFT, $J or .pf file.\n'
}

install_linux() {
    case "$(uname -m)" in
        x86_64 | amd64) asset=sediment-linux-x86_64 ;;
        aarch64 | arm64) asset=sediment-linux-arm64 ;;
        *) fail "no Linux build for $(uname -m); build from source: https://github.com/Nyanites/sediment" ;;
    esac
    bindir="${SEDIMENT_INSTALL_DIR:-$HOME/.local/bin}"
    data="${XDG_DATA_HOME:-$HOME/.local/share}"
    mkdir -p "$bindir" "$data/applications" "$data/icons/hicolor/256x256/apps"
    [ -w "$bindir" ] || fail "can't write to $bindir"

    download "$asset"
    download sediment.png
    say "Installing to $bindir"
    # Install via a temp name in the same directory, then rename: replaces a running copy safely.
    cp "$SD_TMP/$asset" "$bindir/.sediment.new"
    chmod 755 "$bindir/.sediment.new"
    mv -f "$bindir/.sediment.new" "$bindir/sediment"
    cp "$SD_TMP/sediment.png" "$data/icons/hicolor/256x256/apps/sediment.png"
    cat > "$data/applications/sediment.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Sediment
GenericName=Forensic Artifact Explorer
Comment=Explore \$MFT, USN journal and Prefetch files
Exec="$bindir/sediment" %F
Icon=sediment
Terminal=false
Categories=Utility;Security;
EOF
    command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$data/applications" >/dev/null 2>&1 || true

    say "Sediment is installed: $bindir/sediment"
    case ":$PATH:" in
        *":$bindir:"*) printf '    Start it from your app menu or run: sediment\n' ;;
        *) printf '    Start it from your app menu, or add %s to your PATH to run: sediment\n' "$bindir" ;;
    esac
}

# Everything runs inside main(), called on the last line, so a partially downloaded
# script does nothing.
main() {
    set -eu
    repo="Nyanites/sediment"
    for tool in curl awk uname; do
        command -v "$tool" >/dev/null || fail "missing required tool: $tool"
    done
    command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 \
        || fail "missing required tool: sha256sum or shasum"

    if [ -n "${SEDIMENT_VERSION:-}" ]; then
        case "$SEDIMENT_VERSION" in
            *[!0-9A-Za-z.-]*) fail "invalid SEDIMENT_VERSION: $SEDIMENT_VERSION" ;;
        esac
        base="https://github.com/$repo/releases/download/v${SEDIMENT_VERSION#v}"
    else
        base="https://github.com/$repo/releases/latest/download"
    fi

    SD_TMP=$(mktemp -d "${TMPDIR:-/tmp}/sediment-install.XXXXXX")
    trap sd_cleanup EXIT
    trap 'exit 1' INT TERM
    fetch -sS -o "$SD_TMP/SHA256SUMS.txt" "$base/SHA256SUMS.txt" \
        || fail "couldn't download the checksum file"

    case "$(uname -s)" in
        Darwin) install_macos ;;
        Linux) install_linux ;;
        *) fail "this installer runs on macOS and Linux; on Windows use: irm https://nyanites.github.io/sediment/install.ps1 | iex" ;;
    esac
}

main "$@"
