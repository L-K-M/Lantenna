# Changelog

## Unreleased

- Linux builds: Ubuntu/Linux `.deb` and `.AppImage` bundles next to the macOS
  `.dmg`. On Linux the neighbour table is read with `ip neigh` (falling back to
  `arp`), and the title bar tracks GTK's own active state while dragging.
- Warnings are logged by default (`RUST_LOG` still overrides), so an
  unreadable neighbour table is visible.
- Scans run in two phases: live hosts are found first, then only those are
  port-scanned. Fast, Balanced and Thorough scans finish much sooner.
- Deep ⊇ Standard ⊇ Quick port profiles. Banners are read on the probe
  connection, including SMTP, IPP and Home Assistant.
- Fingerprints are rebuilt every scan, and Macs and NAS boxes are no longer
  labelled "Windows-like". Only the OUI is sent to online lookups, and
  randomized MACs are shown as "Private address" and never looked up.
- Malformed mDNS replies can no longer hang a scan, and a scanner panic no
  longer leaves the app stuck in "scanning".
- The first launch picks the interface that carries the default route instead
  of a VM bridge; virtual and public interfaces rank last.
- The host table stays populated and responsive during a rescan, and a
  "Stopping..." state covers the time between Stop and the scan ending.
- Filter by vendor, type, MAC, port or service; relative "Last Seen"; unnamed
  hosts sort last; double-click or Return opens a host.
- A Chooser-style icon view, next to the list view.
- CI: the Rust job runs from `src-tauri/`; Vite 8, Svelte 5.57, Tauri CLI 2.11
  and newer GitHub Actions versions.
