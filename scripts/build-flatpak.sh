#!/usr/bin/env bash
set -euo pipefail
# Build dist/Lantenna-<version>-linux.flatpak by repacking the release .deb
# under flatpak's /app prefix — the bundle ships byte-for-byte what the .deb
# installs. Usage:
#   scripts/build-flatpak.sh [--install]     # build the .deb first, then repack
#   scripts/build-flatpak.sh path/to.deb     # repack an existing .deb (CI)
#
# The bundle names Flathub as its runtime's source, so installing it fetches
# the GNOME runtime from there. Needs flatpak and flatpak-builder; both come
# from Flathub (user installation) on the first build.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
readonly APP_ID=ch.lkmc.lantenna
readonly MANIFEST="$ROOT/flatpak/$APP_ID.yml"
readonly FLATHUB_REPO=https://dl.flathub.org/repo/flathub.flatpakrepo
readonly WORK="$ROOT/dist/flatpak"

die() { echo "build-flatpak.sh: $*" >&2; exit 1; }

INSTALL=0
DEB=""
for argument in "$@"; do
  case "$argument" in
    --install) INSTALL=1 ;;
    -h|--help) sed -n '2,9s/^# //p' "$0"; exit 0 ;;
    *.deb) DEB="$argument" ;;
    *) echo "Unknown argument: $argument" >&2; exit 2 ;;
  esac
done

command -v flatpak-builder >/dev/null 2>&1 ||
  die "flatpak-builder not found: install flatpak and flatpak-builder"
command -v dpkg-deb >/dev/null 2>&1 ||
  die "dpkg-deb not found: install dpkg"

if [[ -z "$DEB" ]]; then
  npm run tauri -- build --bundles deb
  DEB="$(ls -t src-tauri/target/release/bundle/deb/*.deb | head -1)"
fi
[ -f "$DEB" ] || die ".deb not found: $DEB"

# Debian /usr -> flatpak /app.
rm -rf "$WORK/debroot" "$WORK/stage" "$WORK/build" "$WORK/repo"
mkdir -p "$WORK"   # dpkg-deb creates the target dir but not its parents
dpkg-deb -x "$DEB" "$WORK/debroot"
mkdir -p "$WORK/stage"
cp -a "$WORK/debroot/usr/." "$WORK/stage/"

# flatpak exports the desktop file and icons only when they are named after
# the app id; the bundler names them after the binary instead.
# Wrapper scripts hardcode /usr; inside flatpak the prefix is /app.
while IFS= read -r f; do
  sed -i 's|/usr/|/app/|g' "$f"
done < <(grep -rl '/usr/' "$WORK/stage/bin/" 2>/dev/null || true)
while IFS= read -r f; do
  sed -i 's|Exec=/usr/bin/|Exec=|; s|Exec=/opt/[^/]*/bin/|Exec=|' "$f"
done < <(find "$WORK/stage/share/applications" -name '*.desktop' 2>/dev/null)

DESKTOP="$(find "$WORK/stage/share/applications" -name '*.desktop' | head -1)"
[ -n "$DESKTOP" ] || die "no .desktop file inside $DEB"
[ "$(basename "$DESKTOP")" = "$APP_ID.desktop" ] ||
  mv "$DESKTOP" "$WORK/stage/share/applications/$APP_ID.desktop"
if ! find "$WORK/stage/share/icons" -name "$APP_ID.*" | grep -q .; then
  ICON="$(find "$WORK/stage/share/icons" -name '*.png' | sort | tail -1)"
  [ -n "$ICON" ] || ICON="$(find "$WORK/stage/share/icons" -name '*.svg' | head -1)"
  [ -n "$ICON" ] || die "no icon inside $DEB"
  cp "$ICON" "$(dirname "$ICON")/$APP_ID.${ICON##*.}"
fi

flatpak remote-add --user --if-not-exists flathub "$FLATHUB_REPO"
# --disable-rofiles-fuse: containers (CI) have no FUSE, and a copy-only build
# gains nothing from it.
flatpak-builder --user --install-deps-from=flathub --force-clean \
  --disable-rofiles-fuse \
  --state-dir="$WORK/state" --repo="$WORK/repo" \
  "$WORK/build" "$MANIFEST"

VERSION="$(dpkg-deb -f "$DEB" Version)"
BUNDLE="$ROOT/dist/Lantenna-$VERSION-linux.flatpak"
flatpak build-bundle --runtime-repo="$FLATHUB_REPO" \
  "$WORK/repo" "$BUNDLE" "$APP_ID"
if ((INSTALL)); then
  flatpak install --user -y --noninteractive --bundle "$BUNDLE"
fi
echo "Built ${BUNDLE#"$ROOT"/}"
