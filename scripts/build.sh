#!/usr/bin/env bash
# Verify Lantenna the way CI does, then build the desktop app for this host.
#
#   scripts/build.sh             # verify + build the host bundles
#   scripts/build.sh --clean     # remove build outputs first, then do the same
#   scripts/build.sh --install   # also install the app for this host:
#                                #   macOS: Lantenna.app -> /Applications
#                                #   Linux: the .deb via sudo apt install, or
#                                #          the AppImage into ~/Applications
#   scripts/build.sh --run       # launch the app afterwards
#
# Verification mirrors ci.yml: svelte-check, vitest and the vite build (which
# also runs scripts/check-built-html.mjs), then cargo fmt/clippy/test against
# src-tauri/ (the Rust crate embeds the built frontend via generate_context!,
# so the frontend build must come first). `npm run tauri build` then produces
# the host bundles under src-tauri/target/release/bundle/ and the
# distributables (.dmg / .deb / .AppImage) are copied to dist/.
#
# Requirements: Node (CI pins 20), npm, and a stable Rust toolchain. Linux
# additionally needs the Tauri v2 system packages listed in README.md
# (libwebkit2gtk-4.1-dev et al.). Without cargo, or on Linux without those
# packages, the Rust checks and the app build are skipped on a plain run and
# fail when --install/--run was requested.
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
script_path="$script_dir/$(basename "$0")"
cd "$script_dir/.."

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  awk 'NR==1 && /^#!/ {next} /^#/ {sub(/^# ?/,""); print; next} {exit}' "$script_path"
  exit 0
fi

readonly APP_NAME="Lantenna"
readonly BINARY_NAME="lantenna"
readonly BUNDLE_DIR="src-tauri/target/release/bundle"
readonly DIST_DIR="dist"
readonly HOST="$(uname -s)"

clean=0 install=0 run=0
for argument in "$@"; do
  case "$argument" in
    --clean) clean=1 ;;
    --install) install=1 ;;
    --run) run=1 ;;
    *) echo "!! unknown argument: $argument (try --help)" >&2; exit 2 ;;
  esac
done

shopt -s nullglob

if ((clean)); then
  echo "==> clean"
  rm -rf build dist .svelte-kit src-tauri/target
fi

# Re-sync when the lockfile is newer than node_modules, so a pull that changed
# dependencies never verifies against the previously installed tree.
if [[ ! -d node_modules || package-lock.json -nt node_modules ]]; then
  echo "==> npm ci"
  npm ci
fi

echo "==> frontend checks"
npm run check
npm test
npm run build

can_build_app=1
reason=""
if ! command -v cargo >/dev/null 2>&1; then
  can_build_app=0
  reason="no Rust toolchain on PATH (rustup.rs)"
elif [[ "$HOST" == "Linux" ]] && ! pkg-config --exists webkit2gtk-4.1 2>/dev/null; then
  can_build_app=0
  reason="missing the Tauri Linux system packages (see the README's apt line)"
fi

if ((!can_build_app)); then
  if ((install || run)); then
    echo "!! --install/--run need the app build: $reason" >&2
    exit 1
  fi
  echo ".. skipping Rust checks and the app build: $reason"
  echo "==> frontend verified"
  exit 0
fi

echo "==> rust checks"
cargo fmt --all --check --manifest-path src-tauri/Cargo.toml
cargo clippy --locked --all-targets --manifest-path src-tauri/Cargo.toml -- -D warnings
cargo test --locked --manifest-path src-tauri/Cargo.toml

echo "==> tauri build"
npm run tauri build

# Stage the distributable bundles (not the bare .app) into dist/.
echo "==> stage to $DIST_DIR/"
mkdir -p "$DIST_DIR"
staged=()
for artifact in "$BUNDLE_DIR"/dmg/*.dmg "$BUNDLE_DIR"/deb/*.deb "$BUNDLE_DIR"/appimage/*.AppImage; do
  cp "$artifact" "$DIST_DIR/"
  staged+=("${artifact##*/}")
done
if ((${#staged[@]})); then
  printf -- '-- %s\n' "${staged[@]}"
else
  echo ".. no .dmg/.deb/.AppImage produced for this host"
fi

install_app() {
  case "$HOST" in
    Darwin)
      local app="$BUNDLE_DIR/macos/$APP_NAME.app"
      [[ -d $app ]] || { echo "!! expected bundle missing: $app" >&2; return 1; }
      rm -rf -- "/Applications/$APP_NAME.app"
      ditto "$app" "/Applications/$APP_NAME.app"
      echo "==> installed /Applications/$APP_NAME.app"
      open -R "/Applications/$APP_NAME.app" 2>/dev/null ||
        echo ".. skipped revealing in Finder (no GUI session)" >&2
      ;;
    Linux)
      local debs=("$BUNDLE_DIR"/deb/*.deb)
      local appimages=("$BUNDLE_DIR"/appimage/*.AppImage)
      if ((${#debs[@]})); then
        echo "==> apt install ${debs[*]##*/}"
        local paths=()
        for deb in "${debs[@]}"; do
          paths+=("./$deb")
        done
        sudo apt install "${paths[@]}"
      elif ((${#appimages[@]})); then
        mkdir -p "$HOME/Applications"
        for image in "${appimages[@]}"; do
          cp "$image" "$HOME/Applications/"
          chmod +x "$HOME/Applications/${image##*/}"
          echo "==> installed $HOME/Applications/${image##*/}"
        done
      else
        echo "!! nothing to install: no .deb or .AppImage under $BUNDLE_DIR" >&2
        return 1
      fi
      ;;
    *) echo "!! --install is unsupported on $HOST" >&2; return 1 ;;
  esac
}

run_app() {
  case "$HOST" in
    Darwin)
      local app="$BUNDLE_DIR/macos/$APP_NAME.app"
      if ((install)); then
        app="/Applications/$APP_NAME.app"
      fi
      [[ -d $app ]] || { echo "!! no app to run: $app" >&2; return 1; }
      open "$app"
      ;;
    Linux)
      local appimages=("$BUNDLE_DIR"/appimage/*.AppImage)
      local binary="$BINARY_NAME"
      if ((install)) && command -v "$binary" >/dev/null 2>&1; then
        "$binary" &   # just installed from the .deb
      elif ((${#appimages[@]})); then
        chmod +x "${appimages[0]}"
        "${appimages[0]}" &
      elif command -v "$binary" >/dev/null 2>&1; then
        "$binary" &
      else
        echo "!! nothing to run: no AppImage under $BUNDLE_DIR and no $binary on PATH" >&2
        return 1
      fi
      ;;
    *) echo "!! --run is unsupported on $HOST" >&2; return 1 ;;
  esac
}

if ((install)); then
  install_app
fi

if ((run)); then
  run_app
fi

echo "==> done"
