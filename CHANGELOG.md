# Changelog

## Unreleased

- A Mac OS 8.5 look, drawn with Osmium UI: a Platinum window with close,
  zoom, collapse and grow boxes; labeled controls on the gray; a Finder
  window header with chasing arrows and a progress bar; a Finder-style list
  with a Status column, a star column and resizable, remembered columns; a
  Host Information pane with General, Ports and Fingerprint tabs; and the
  icon view restyled to match.
- Menus for every command (the native menu bar on macOS, a Mac OS 8 menu
  bar inside the window on Linux), contextual menus in both views and
  keyboard equivalents such as Command-R to scan and Command-period to stop.
- No more toasts: scan state lives in the window header, per-host results in
  the pane's status line, and failures in alerts that say what to do next.
- Balloon Help (Help > Show Balloons) replaces the hover tooltips.
- Favorites, hidden hosts and custom names carry over; the host's name is
  now edited in the General tab, and the Favorites menu jumps to a favorite.
- macOS follows the system accent color; Linux uses Mac OS 8.5's default
  Lavender.
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
