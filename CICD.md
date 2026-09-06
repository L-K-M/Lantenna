# CI/CD

Lantenna ships GitHub Actions workflows for continuous integration and for cutting
desktop releases. CI runs on every pull request and on pushes to `main`; releases
are produced by pushing a version tag. Everything works with **no secrets
configured** — code signing and notarization are optional and only kick in when
the relevant secrets are present.

Lantenna started as a **Mac OS X** application and now also ships for Linux, so
the release matrix covers macOS (`.dmg`) and Ubuntu/Linux (`.deb` + `.AppImage`).
Each platform has backend code the other never compiles — the AppKit accent and
highlight colors on macOS (`objc2-app-kit`), and on Linux the GTK decoration-state
tracking, the `ip neigh` neighbour reader and the iputils `ping` flag dialect — so
CI lints and tests on both runners to exercise both real targets.

## Workflows
| Workflow | Trigger | Purpose |
| --- | --- | --- |
| `.github/workflows/ci.yml` | PRs + pushes to `main` | Type-check, test and build the SvelteKit frontend, then run `cargo fmt`/`clippy`/`test` on macOS and Ubuntu. |
| `.github/workflows/release.yml` | Pushing a `v*.*.*` tag | Build the macOS Tauri `.dmg` bundles (Apple Silicon + Intel) and the Linux `.deb`/`.AppImage` bundles (x86_64), and attach them to a GitHub Release. |

## Continuous integration (`ci.yml`)

The CI workflow has two parallel jobs:

- **Frontend (check & build)** — runs on Ubuntu. Installs npm dependencies with
  `npm ci`, runs `npm run check` (`svelte-kit sync` + `svelte-check`), then
  `npm test` (vitest under jsdom: the window-activity subscription lifecycle and
  the title-bar drag regression), then `npm run build` (`vite build`). The
  frontend is platform-independent, so it builds on the cheaper Linux runner.
- **Rust (fmt, clippy, test)** — builds the frontend into `build/` first (because
  `tauri::generate_context!` embeds it at compile time), then runs
  `cargo fmt --all --check`, `cargo clippy --locked --all-targets -- -D warnings`,
  and `cargo test --locked`. `Swatinem/rust-cache` caches the cargo build between
  runs. The job is a matrix over `macos-latest` and `ubuntu-22.04`: each platform's
  `#[cfg(target_os = ...)]` code (AppKit system colors on macOS; GTK
  decoration-state tracking and the `ip neigh` neighbour reader on Linux) only
  compiles on its own OS, so both real targets are exercised. The bundles
  themselves are built by the release workflow.

Lantenna's `src-tauri` is a single crate (not a Cargo workspace), so the cargo
commands run without `--workspace`. There is no `Cargo.toml` at the repository
root — all cargo commands run from `src-tauri/` (the CI steps set
`working-directory: src-tauri`).

The Ubuntu jobs install the Tauri v2 Linux system packages first —
`libwebkit2gtk-4.1-dev` (the 4.1 series; Tauri v1 projects use `-4.0-dev`
instead) plus the usual build tools; the release workflow additionally installs
`patchelf` and `xdg-utils` for the AppImage bundler.

### Running CI checks locally

```bash
# Frontend
npm ci
npm run check
npm test
npm run build

# Rust (run from src-tauri/)
cd src-tauri
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

On Linux you also need the Tauri system dependencies (`libwebkit2gtk-4.1-dev`,
`build-essential`, `libxdo-dev`, `libssl-dev`, `libayatana-appindicator3-dev`,
`librsvg2-dev`, etc.). On macOS none of these are required.

## Releases (`release.yml`)

To cut a release:

```
git tag v1.2.3
git push origin v1.2.3
```

Or use the helper, which bumps the version everywhere it's declared (`package.json`, `src-tauri/tauri.conf.json`, `Cargo.toml`) and the README, then creates and pushes the matching tag:

```
scripts/release.sh 1.2.3 --push
```

The workflow:

1. **Creates a draft GitHub Release** named `Lantenna v1.2.3` with auto-generated
   release notes. Tags containing `-` (e.g. `v1.2.3-rc.1`) are marked as
   pre-releases.
2. **Builds the desktop bundles** with `tauri-apps/tauri-action@v0` across a
   three-way matrix and uploads each artifact to the draft release:
   - macOS Apple Silicon (`aarch64-apple-darwin`) — `.dmg` / `.app`
   - macOS Intel (`x86_64-apple-darwin`) — `.dmg` / `.app`
   - Linux x86_64 (`x86_64-unknown-linux-gnu`, built on `ubuntu-22.04`) —
     `.deb` / `.AppImage`

   The `bundle.targets` in `src-tauri/tauri.conf.json` is `"all"`; on a macOS
   runner that resolves to the `.app` and `.dmg` formats. On Linux the
   platform-specific `src-tauri/tauri.linux.conf.json` overrides it to
   `["deb", "appimage"]` (deliberately no `.rpm`) and declares the `iputils-ping`
   and `iproute2` packages the scanner shells out to. The Linux leg builds on the
   oldest supported Ubuntu LTS runner so the binaries link against a glibc old
   enough for the systems users run.
3. **Publishes the release** (flips it from draft to published) once all build
   jobs succeed. If a build fails, the release stays a draft so nothing
   half-built is published.

> **Why no Windows?** Nobody has built or run Lantenna on Windows. The code has
> Windows branches (`ping -n`, `arp -a`, and generic fallbacks for system colors
> and window-activity tracking), but none of them has been exercised, and the
> custom title bar has only been tested on macOS and Linux. If Windows support is
> wanted later, add a `windows-latest` entry to the matrix the same way the other
> Tauri repos do, then verify those paths.

Builds are **unsigned** unless the optional signing secrets below are configured.
An unsigned macOS app still runs, but users will see Gatekeeper warnings;
add the Apple secrets later to enable notarization without editing the workflow.
The Apple signing step is skipped on the Linux leg; the Linux packages are not
signed.

## Secrets

All secrets are **optional** — the workflows build and release successfully
without any of them. They only enable code signing / notarization and Tauri
updater signing.

| Secret | Used for |
| --- | --- |
| `APPLE_CERTIFICATE` | Base64 of the Apple Developer ID signing certificate (.p12). |
| `APPLE_CERTIFICATE_PASSWORD` | Password for the .p12 certificate. |
| `APPLE_SIGNING_IDENTITY` | Signing identity name (e.g. `Developer ID Application: …`). |
| `APPLE_ID` | Apple ID used for notarization. |
| `APPLE_PASSWORD` | App-specific password for that Apple ID. |
| `APPLE_TEAM_ID` | Apple Developer Team ID. |
| `TAURI_SIGNING_PRIVATE_KEY` | Tauri updater private signing key. |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | Password for the Tauri updater signing key. |

`GITHUB_TOKEN` is provided automatically by GitHub Actions; you do not need to
create it.
