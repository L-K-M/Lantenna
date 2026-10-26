#!/usr/bin/env bash
# Assert that the license notices are inside the built packages. ci.yml and
# release.yml run the same checks so they cannot drift: a green CI bundles job
# must mean the release check would pass too.
#
#   scripts/check-bundle-notices.sh macos <dir containing Lantenna.app>
#   scripts/check-bundle-notices.sh linux <path/to.deb> <path/to.AppImage>
set -euo pipefail

mode="${1:-}"
case "$mode" in
  macos)
    res="${2:?usage: $0 macos <dir containing Lantenna.app>}/Lantenna.app/Contents/Resources"
    for f in Third-Party-Notices.txt Rust-Licenses.html; do
      test -s "$res/$f"
    done
    grep -q '^tauri ' "$res/Third-Party-Notices.txt"
    grep -q '^svelte ' "$res/Third-Party-Notices.txt"
    grep -q '^objc2 ' "$res/Third-Party-Notices.txt"
    grep -q 'Copyright notices for The Rust Standard Library' "$res/Rust-Licenses.html"
    ;;
  linux)
    deb="${2:?usage: $0 linux <deb> <AppImage>}"
    appimage="$(realpath "${3:?usage: $0 linux <deb> <AppImage>}")"
    doc=usr/share/doc/lantenna
    tmp="$(mktemp -d)"
    dpkg-deb -x "$deb" "$tmp/deb"
    (cd "$tmp" && "$appimage" --appimage-extract 'usr/share/*' >/dev/null)
    for root in "$tmp/deb" "$tmp/squashfs-root"; do
      for f in copyright Third-Party-Notices.txt Rust-Licenses.html; do
        test -s "$root/$doc/$f"
      done
      grep -q '^Files: usr/bin/lantenna$' "$root/$doc/copyright"
      grep -q '^tauri ' "$root/$doc/Third-Party-Notices.txt"
      grep -q '^gtk ' "$root/$doc/Third-Party-Notices.txt"
      grep -q '^option-ext ' "$root/$doc/Third-Party-Notices.txt"
      grep -q '^osmium-ui ' "$root/$doc/Third-Party-Notices.txt"
    done
    # The AppImage also carries its Ubuntu libraries' and runtime's notices.
    test -s "$tmp/squashfs-root/$doc/SOURCES.txt"
    test -s "$tmp/squashfs-root/usr/share/doc/libglib2.0-0/copyright"
    grep -q 'Bundled system libraries' "$tmp/squashfs-root/$doc/Third-Party-Notices.txt"
    grep -q 'type2-runtime' "$tmp/squashfs-root/$doc/Third-Party-Notices.txt"
    rm -rf "$tmp"
    ;;
  *)
    echo "usage: $0 macos <dir containing Lantenna.app> | linux <deb> <AppImage>" >&2
    exit 2
    ;;
esac
