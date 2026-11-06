#!/usr/bin/env bash
# Run XRAY against the real 2024 xz backdoor: Debian's backdoored liblzma5
# builds, the clean releases around them, and Arch's builds of the same
# versions (where the payload was not injected). Packages come from
# snapshot.debian.org and archive.archlinux.org and are checked against the
# hashes below. Nothing here loads or runs the backdoored library: XRAY only
# reads it with readelf.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=${XRAY_REAL_XZ_WORK:-$here/work}
read -ra xray <<< "${XRAY:-xray}"
mkdir -p "$work" && cd "$work"

fetch() {  # fetch FILE URL SHA256
    [ -f "$1" ] || curl -sfL -m 300 -o "$1" "$2"
    echo "$3  $1" | sha256sum -c --quiet || { echo "hash mismatch: $1" >&2; exit 1; }
}
fetch liblzma5_5.4.5-0.3_amd64.deb https://snapshot.debian.org/file/779cddb0761b4004e301e51b5f6ec70d714a8613 ed3fe5e4d9d8c7dd8d702d39d5d2e6abdfac3539c0a9e3e075b4d05b9c707c92
fetch liblzma5_5.6.0-0.2_amd64.deb https://snapshot.debian.org/file/1702526d4072e630a505ba36c0085b3295293130 2ed51ae8764a177aa6401df935ecef3d103db1f72ac98a7c803cdc4869fd3d98
fetch liblzma5_5.6.1-1_amd64.deb https://snapshot.debian.org/file/81f1f56c590eee24bc320293f2c5c508fcb55d02 15b08cbaa49b6df580f81ef85d5dd4bcca4dac41daa87b47c67177707b697cb7
fetch "liblzma5_5.6.1+really5.4.5-1_amd64.deb" https://snapshot.debian.org/file/fbf003e074a58180a9dc58416197714d0e9e8d47 6fb584435e845612f4af9c9ae3c703c69891119f265b45ec7e96a2542dfc3592
fetch xz-5.4.6-1-x86_64.pkg.tar.zst https://archive.archlinux.org/packages/x/xz/xz-5.4.6-1-x86_64.pkg.tar.zst 8362a5e440748420043c354d519d6ef44862985c9f57ab6f05db6967abdd4f9f
fetch xz-5.6.1-1-x86_64.pkg.tar.zst https://archive.archlinux.org/packages/x/xz/xz-5.6.1-1-x86_64.pkg.tar.zst 63b219db0b2f0b6215cc4e4ca64f3fa59b914e7b15bde17c36bf2b21e459c13e

show() { printf '\n\033[1;36m== %s\033[0m\n' "$1"; shift; printf '\033[1m$ xray %s\033[0m\n' "$*"; "${xray[@]}" "$@" || true; }
show "Debian: clean 5.4.5 -> backdoored 5.6.0" drift liblzma5_5.4.5-0.3_amd64.deb liblzma5_5.6.0-0.2_amd64.deb
show "Debian: clean 5.4.5 -> backdoored 5.6.1" drift liblzma5_5.4.5-0.3_amd64.deb liblzma5_5.6.1-1_amd64.deb
show "Debian: backdoored 5.6.1 -> the revert (5.6.1+really5.4.5)" drift liblzma5_5.6.1-1_amd64.deb "liblzma5_5.6.1+really5.4.5-1_amd64.deb"
show "Control, Arch: 5.4.6 -> 5.6.1 built from the same release, payload not injected" drift xz-5.4.6-1-x86_64.pkg.tar.zst xz-5.6.1-1-x86_64.pkg.tar.zst
