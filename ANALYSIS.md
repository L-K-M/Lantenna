# Lantenna analysis and backlog

A working backlog for Lantenna: open bugs, performance work, missing features,
and design ideas, each written so an agent can pick it up without redoing the
investigation. It consolidates the September 2026 review with the open items
from the June 2026 review in [`awesome.md`](awesome.md), which stays as that
round's historical record.

Last updated 2026-09-26 against `main` at `7076c3c` (v1.0.1).

## How to use this file

- Each item has an ID, where the problem is, what to change, and how to verify
  the change. Sizes are rough: **S** (under an hour), **M** (a focused PR),
  **L** (multi-PR or design work).
- Line numbers drift. Search for the named function instead.
- When you finish an item, delete it here in the same PR. When you find
  something new, add it with the same shape.
- Check the "In flight" section first: those items already have open PRs.

---

## In flight (open PRs, not yet merged)

Nine PRs from the September review are open. Don't redo this work. Once a PR
merges, delete its row. If one is closed without merging, move its items back
into the backlog below.

| PR | What it fixes | Stacked on |
|---|---|---|
| #16 | The Rust CI job ran `cargo` in the repo root, which has no `Cargo.toml`, so every PR was red. Also `cargo fmt` and 4 clippy lints. | — |
| #17 | `parse_dns_name` looped forever on a self-referencing mDNS compression pointer (a LAN-wide DoS that wedged every later scan). The scan task now always releases the "running" lock, and a panic becomes `scan-error`. Labels with control characters are rejected. | #16 |
| #18 | Two-phase scanning: sweep 5 discovery ports, read ARP right away, ping, then probe the profile on live hosts only. Phased and throttled progress. Measured on a simulated /24: Fast 34 s → 8 s, Balanced 208 s → 26 s (and it finds hosts the old ARP read missed), Thorough ~2.5 h → 204 s. | #16 |
| #19 | Deep ⊇ Standard ⊇ Quick port profiles, heuristic ports actually probed, UDP-only ports removed. Banners are read on the probe connection (it used to open a second one), TLS ports are skipped, the `Server` header is case-insensitive, and SMTP/IPP/Home Assistant banners are read. | #16 |
| #20 | Fingerprints are rebuilt every scan (they used to be frozen for 90 days). Only lookups are cached, including Fingerbank misses. Macs and NAS boxes are no longer "Windows-like". Only the OUI goes to maclookup.app, randomized MACs are never looked up, and the UI shows "Private address". | #16 |
| #21 | Progress moves to its own store, table rows are keyed and memoized (main-thread time 27.5 s → 5.4 s on a 4,094-address scan). A "Stopping..." state fixes the cancel race. The table no longer empties on rescan. `errorMessage()` keeps Tauri's string errors. | #16 |
| #22 | The first launch picks the default-route interface (it used to pick `bridge100`). Virtual and public interfaces rank last. | #16 |
| #23 | Filter by vendor, type, MAC, port and service; the right empty-state text; selection scrolls into view; vendor names shortened; the "CO. , LTD." mangling fixed; readable ports column; relative Last Seen; no hover flash; unnamed hosts sort last; double-click or Return opens the host; port-target logic moved to a util. | #16 |
| #24 | A Chooser-style icon view (32 px icons, System 7 selection, 2D arrow keys). Icon rules moved to `$lib/util/hostIcons.ts`. | #23 |

**Merge notes:**

- Merge #16 first.
- #17–#20 and #22 all touch `src-tauri/src/scanner.rs`, but in different
  functions. Expect small textual conflicts only in imports and the test
  module.
- #21, #23 and #24 all touch `HostTable.svelte` and `+page.svelte`. When #21
  (per-row memoization) meets #23 (relative "Last Seen", refreshed every
  minute), keep Last Seen **out** of #21's `rowView` cache, or put `now` in the
  cache key. Otherwise the relative time freezes.
- `CHANGELOG.md` was left untouched to avoid nine-way conflicts. Add entries
  for the merged PRs in one follow-up commit.

---

## Verification toolbox

These are the setups the September review used. Reuse them instead of guessing.

**Rust, matching CI.** CI uses `dtolnay/rust-toolchain@stable`, which is 1.98.1
at the time of writing. Newer clippy flags more (for example
`unnecessary_sort_by`), so install the same version:
`rustup toolchain install 1.98.1 --profile minimal --component clippy,rustfmt`,
then run `cargo +1.98.1 fmt --check`,
`cargo +1.98.1 clippy --all-targets -- -D warnings` and `cargo +1.98.1 test`,
all in `src-tauri/`. On Linux, first install `libwebkit2gtk-4.1-dev`,
`libgtk-3-dev`, `libsoup-3.0-dev` and `librsvg2-dev`. The macOS-only
`system_colors.rs` can't be cross-checked without the macOS SDK. Only CI
checks it.

**A fake LAN for real end-to-end scans (Linux, root).** This needs `iproute2`,
`nftables` and `iputils-ping`:

1. `ip netns add ltlan`, then create a bridge `ltbr0` inside it.
2. Add a `ltscan` namespace (scanner, `10.77.0.100/24` on `eth0`) and one
   namespace per fake host. Connect each with a veth pair whose peer is
   enslaved to the bridge.
3. In each host namespace, run a tiny Python TCP listener on that device's
   ports. Make SSH send `SSH-2.0-...`, and HTTP answer `HEAD` with a lowercase
   `server:` header.
4. For "stealth" hosts, add an nft input chain that accepts only their open
   ports and drops all other TCP and ICMP.
5. Add a temporary `#[ignore]` tokio test that calls `run_scan` with
   `interface_name: "eth0"`, and run it with
   `ip netns exec ltscan cargo test <name> -- --ignored --nocapture`.

This gives real connect, refuse, timeout and ARP behavior. Loopback tests,
where `tokio::net::TcpListener` binds `127.0.0.1:0`, are enough for probe and
banner logic and also run on macOS CI.

**The UI without Tauri.** Serve a production build (`npm run build`, then
`npx vite preview --port <p>`). Dev mode can't serve a symlinked
`node_modules`. Then drive it with Playwright (installed globally; Chromium at
`/opt/pw-browsers`) and a script injected with `addInitScript` that defines
`window.__TAURI_INTERNALS__`:

- `invoke(cmd, args)` answers `get_network_interfaces`, `get_scan_results`,
  `get_system_colors`, `start_scan` and the rest from fixtures.
- `invoke('plugin:event|listen', { event, handler })` records handler ids from
  `transformCallback`.
- Emitting an event calls `callbacks.get(id)({ event, id, payload })`.
- `metadata.currentWindow.label` is `'main'`.
- `plugin:window|*` calls return plausible sizes.

To measure frontend cost, deliver each event in its own task (for example via
`MessageChannel`), as Tauri does, and read CDP `Performance.getMetrics`
(`TaskDuration`, `ScriptDuration`) before and after a scan.

---

## Backlog

### Bugs

**BUG-1: A cancelled scan overwrites the last complete scan (S).**
`start_scan` in `commands.rs` persists every `ScanResult` as `latest_scan`,
including cancelled ones. Cancel after 3 hosts and the next launch shows 3
hosts. Fix: when `cancelled`, merge the partial hosts into the previous result
(or skip persisting). Verify with a unit test on `Storage` using a cancelled
result.

**BUG-2: Deep Scan results aren't persisted (S).** `scan_host_ports` returns
the refreshed host to the UI but never updates `latest_scan`, so a restart
loses it. Fix: upsert the host into the stored latest scan. Note the frontend
also keeps favorite snapshots in `localStorage`.

**BUG-3: Deep Scan of an offline host sets `last_seen = now` (S).**
`scan_single_host_with_progress` stamps `last_seen` even when
`reachable == false`. Keep the previous value (it needs to be passed in) or
leave it empty.

**BUG-4: Large subnets are sampled, not scanned "first 4096" (M).**
`build_scan_targets` spreads `max_hosts` evenly across the subnet, but the UI
says "Scanning first 4096 hosts" (`scanStore.ts`, `startScan`). On a /16 that
probes 1 in 16 addresses. Fix: scan the /24 (or /22) around the local address
first, fix the message, and offer a custom range (FEAT-3).

**BUG-5: The mDNS sweep ignores the selected interface (M).**
`sweep_mdns_services` binds `0.0.0.0:0`, so queries go out on the default
interface only. Bind to the selected interface's address and set
`IP_MULTICAST_IF`. Also send QU questions for PTR (12) instead of ANY.

**BUG-6: Window shade and zoom probably fight `minHeight: 560` (S, needs a
Mac).** `WindowManager.toggleShade` sets the height to 36 px, and
`resizeHeightBy` can shrink below 560, while `tauri.conf.json` sets
`minHeight: 560`. Call `setMinSize(null)` before shading and restore it after
(which needs `core:window:allow-set-min-size` in `capabilities/default.json`).
Manual resizing while shaded also desyncs `isShaded`. Verify on macOS.

**BUG-7: Custom name editing (S).** The save button in `HostInspector` uses
`DownloadIcon`, a download arrow, and switching hosts silently discards an
unsaved draft. Fix: save on blur or Return, and use a check icon or a "Set"
label.

**BUG-8: Deep Scan can't be cancelled and blocks every host (M).** There's
no cancel for `scan_host_ports`, and `deepScanRunning` disables the button for
all hosts. Add a per-host cancel token in `ScanManager` (or a second manager)
and a Stop button.

**BUG-9: Listener attach/detach race in `scanStore` (S).** From `awesome.md`
B8. `attachListeners` awaits `listen()` calls one after another, and
`destroy()` can run in between, leaking late listeners. On remount a second
copy attaches. Use a generation token. `init()` is also not awaited in
`onMount`.

**BUG-10: OUI vendor cache eviction is alphabetical (S).** From `awesome.md`
G6. `prune_oui_vendor_cache` drops the lexicographically smallest OUIs. Store
an insertion or last-used timestamp and evict the oldest.

**BUG-11: `select_interface` can scan a subnet the interface isn't on (S).**
From `awesome.md` G8. If the requested subnet matches no interface but the
name does, the scan uses the requested subnet anyway. Reject the mismatch or
fall back to the interface's own subnet. It's reachable only through stale
persisted state today.

**BUG-12: The NEW badge can overflow the IP column (S).** On long addresses
(`192.168.100.254`), star + icon + address + NEW may not fit in about 190 px.
Check after #23 and move the badge to the name cell if needed.

**BUG-13: The icon view has no context menu (S).** After #24, right-clicking a
tile doesn't offer Hide or Clear Friendly Name. Extract the list's context menu
into a shared component (see FEAT-9).

### Performance

**PERF-1: Adaptive per-host timeouts (M).** After #18, Thorough time is
dominated by firewalled hosts: every one of their 2,057 ports waits out the
full timeout. Measure each host's RTT from its first answer (open or refused)
and use `max(100 ms, 8 × RTT)` for its remaining ports. For hosts that never
answer TCP (found via ARP), cap the per-host budget. Verify on the netns fake
LAN (4 stealth hosts): Thorough should drop well below 200 s.

**PERF-2: Unprivileged ICMP instead of spawning `ping` (M).** `ping_host`
forks a `ping` process per address. macOS allows `SOCK_DGRAM` + `IPPROTO_ICMP`
without root, as used by the `surge-ping` crate: one socket, thousands of
probes, and the TTL is available for OS hints (FP-6).

**PERF-3: Raise `RLIMIT_NOFILE` at startup (S).** GUI apps on macOS start with
a soft limit of 256 file descriptors. Fast mode allows 128 sockets, and EMFILE
(24) is retried once, then reported as closed. At startup, set the soft limit
to `min(hard, 4096)` (`libc::setrlimit`) and log the result.

**PERF-4: One storage save per scan (S).** Merges `awesome.md` G3. At the end
of a scan, `Storage::save` runs up to 3 times (vendors, Fingerbank, latest
scan). Each time it pretty-prints the whole JSON under the mutex on an async
worker. Batch into one save, use compact JSON, and write inside
`spawn_blocking`.

**PERF-5: Negative cache for maclookup.app (S).** An OUI that isn't in the
bundled database and that maclookup doesn't know is queried on every scan
(2 s timeout). Cache "not found" per OUI for 7 days, as #20 does for
Fingerbank. Also put a small semaphore (2 or 3) around online lookups; the free
tier allows about 2 req/s.

**PERF-6: Reverse DNS threads pile up (S).** `resolve_hostname_with_timeout`
drops the future after 250 ms, but the `spawn_blocking` `getnameinfo` keeps
running. Bound the blocking lookups with a semaphore.

### Fingerprinting, names and privacy

**FP-1: Real host names from mDNS, NetBIOS, SSDP and HTTP (L).** Merges
`awesome.md` M1 and M7. Many hosts show "Unknown". Sources, in order of value:

- (a) keep the mDNS PTR RDATA instance names ("Living Room Apple TV"), and
  parse SRV/TXT/A in the additional section;
- (b) the `_device-info._tcp` TXT `model=` value (for example `MacBookPro18,3`),
  mapped to a friendly Mac model name and icon;
- (c) a NetBIOS node-status query (UDP 137, NBSTAT) for Windows and Samba
  names;
- (d) the SSDP `LOCATION` XML `friendlyName` and `modelName`. SSDP discovery
  exists but is dead code: `discover_ssdp_devices`;
- (e) the HTTP `<title>` of the device's web UI.

Add a `name_source` field so the UI can show where a name came from. Test with
recorded packet fixtures.

**FP-2: Show confidence as Low/Medium/High (S).** Merges `awesome.md` G9. The
confidence is a clamped sum of boosts shown as "92%", which reads as a
calibrated probability. Show a qualitative chip and list the contributing
sources.

**FP-3: TLS certificate peek (M).** On 443, 5001 and 8443, read the
self-signed certificate's CN/O (printers, NAS, UniFi and iDRAC often put the
model there). Use `rustls` with a no-verify verifier limited to reading the
certificate.

**FP-4: TTL-based OS family hint (S, after PERF-2).** Initial TTL 64 means
Unix or macOS, 128 Windows, 255 network gear.

**FP-5: Banner notes duplicate the banner (S).** `extract_os_from_banners`
stores the whole HTTP `Server` value as the software and keeps only the first
banner. Record one note per distinct software.

**FP-6: Online lookups opt-in and Fingerbank key in settings (M).** Merges the
rest of `awesome.md` G4. After #20, only OUIs leave the machine, but it still
happens by default. `FINGERBANK_API_KEY` is read from the environment, which a
Finder-launched `.app` never has, so the Fingerbank path is unreachable in
practice. Add an "Online vendor lookups" setting (off or on, disclosed) and a
Fingerbank key field stored in the Keychain (FEAT-8).

**FP-7: `FINGERPRINTING.md` overstates what's implemented (S).** It lists
SSDP and the Fingerbank DHCP/UA/FQDN parameters as implemented, but SSDP is
dead code and the parameters are never filled. Correct the status table when
FP-1(d) lands, or sooner.

### Features

**FEAT-1: "This Mac" row (S).** The local address is excluded from targets, so
your own machine never appears. Add it with its interface, MAC and hostname,
tagged "This Mac".

**FEAT-2: Gateway badge (S, builds on #22).** `route -n get default` also
prints `gateway:`. Return it with the interfaces and tag that host "Gateway"
with the router icon.

**FEAT-3: Custom range and custom ports (M).** Merges `awesome.md` M6. Scan
`10.0.5.0/24`, `192.168.1.10-50`, or a port list like `8123,1883` from an
"Advanced..." popover. Validate the input in Rust (`ipnet`).

**FEAT-4: Stable device identity (M).** Custom names, favorites and hidden
flags are keyed by IP, so after DHCP churn your "NAS" label lands on someone's
phone. Key by MAC when known, keep IP as a fallback, and migrate the
`localStorage` maps once.

**FEAT-5: History and presence (L).** Merges `awesome.md` M4 and D5. Keep a
per-MAC record of first seen, last seen, times seen, IPs used, and last open
ports. This enables:

- "Gone since..." rows;
- NEW badges across launches;
- a "known devices" list;
- first-seen "birthdays";
- port-change alerts ("the printer opened 23").

Store it in the existing JSON store or SQLite.

**FEAT-6: Watch mode (L, after FEAT-5).** Merges `awesome.md` D4 and D7.
Rescan every N minutes and notify when an unknown MAC appears, using a macOS
notification plus an optional System 7 alert. A menu bar item with the host
count and new devices is a natural companion.

**FEAT-7: Export (M).** Merges `awesome.md` M3 and D6. Copy the list as
Markdown, CSV or JSON, and "Save Network Survey..." as a retro monospaced
report with `====` rules. Clipboard needs no new dependency; saving to a file
needs `tauri-plugin-dialog`.

**FEAT-8: Settings window, a "Control Panel" (M).** Default approach and
timeout, online lookups, the Fingerbank key, sounds, the watch interval, and
the theme. Use system7-ui's `MovableDialog`.

**FEAT-9: Richer context menu (M).** Today: Hide and Clear Friendly Name. Add
Open, Copy IP/MAC/Name, Rename..., Favorite, Deep Scan, Wake and Get Info.
Share it between the list and icon views (BUG-13), and make it keyboard
accessible.

**FEAT-10: Keyboard shortcuts (S).** Merges `awesome.md` M9. ⌘R scan/stop, ⌘F
focus filter, Esc clear filter, ⌘C copy the selected IP, Space favorite, ⌘I
inspector, ⌘⌫ hide. (Return and double-click to open arrive with #23 and #24.)
Also add native menu items for these.

**FEAT-11: Latency (S, after PERF-1).** Merges `awesome.md` M5. Record the
connect RTT of the first answer per host, and show it as a column or as signal
bars (DELIGHT-4).

**FEAT-12: Security hints (M).** Flag services worth a look: Telnet 23, FTP 21,
the Docker API on 2375 without TLS, Redis, Mongo and Elasticsearch reachable,
VNC 5900, and RDP. Show a small caution glyph in the table with a one-line
reason in the inspector. Avoid alarmism.

**FEAT-13: Deep-scan several selected hosts (M).** Needs multi-select in the
list and a queue.

**FEAT-14: IPv6 neighbors (L).** From `awesome.md` M8. List IPv6 neighbors
from the NDP table next to the IPv4 results, and link v4 and v6 records by MAC.

### UX

**UX-1: Welcome state (S).** Replace "No hosts yet. Start a scan." with a
System 7-style welcome panel: a big Scan button, the chosen interface and
subnet, and one line on what a scan does.

**UX-2: Better interface labels (S).** Add the hardware port name from
`networksetup -listallhardwareports` (Wi-Fi, Ethernet, Thunderbolt Bridge),
your own address, and a "default" marker (#22 provides `is_default_route`).

**UX-3: ETA in the footer (S).** Estimate from the measured rate during each
phase (#18 provides the phases).

**UX-4: Remember sort, view and inspector width (S).** Store them in
`localStorage` (#24 already remembers the view).

**UX-5: Why is this host listed? (S).** "Answered on TCP 443", "Seen in ARP
only", "Replied to ping". Carry a `discovered_via` field from `run_scan`.

**UX-6: Rename inline (S).** Double-click the Name cell to edit, like the
Finder. (Double-clicking the row opens the host after #23, so use a slow second
click or ⌘-Return for rename.)

### Visual and theming

**VIS-1: The narrow layout starves the table (S).** Below 980 px the
inspector stacks under the table with a 280 px max height, which leaves about
4 rows at 900×620. Keep the panels side by side down to the 840 px window
minimum with a 240 px inspector, or make the inspector collapsible.

**VIS-2: Fractional borders and focus rings (S).** `1.5px` rules in the
toolbar, footer and inspector render blurry at 1x and uneven at 2x. Use 1 px or
2 px, and make keyboard focus a consistent 1 px dotted black ring.

**VIS-3: NEW badge style (S).** The yellow pill with `line-height: 0.7`
clips. Use an inverse black-on-white tag or a folded-corner marker in System 7
style.

**VIS-4: Footer summary, a "network weather report" (S).** Merges
`awesome.md` D3. When idle, show "23 hosts · last scan 14:02 · 2 new" instead
of "Idle", or a one-line summary after each scan: "Quiet evening on
192.168.1.0/24: 12 regulars, 1 stranger."

**VIS-5: Typography (S).** Use Chicago (`Sysfont`) for chrome and Geneva 9/10
for list content, as System 7 did. Both fonts ship with system7-ui.

**VIS-6: Themes (M).** Offer "System 7 B&W" (1-bit), "System 7 Color" (the
current accent-driven look) and "Mac OS 8 Platinum" (grey bevels), built on
the `--system7-*` variables and chosen in Settings (FEAT-8).

**VIS-7: A size box (S).** The borderless window has no visible resize
affordance. Put a System 7 grow box in the footer corner that calls
`startResizeDragging('SouthEast')`, which needs
`core:window:allow-start-resize-dragging`.

**VIS-8: Separate Kind and Vendor columns; fewer toasts (S).** The
Fingerprint column crams "Vendor • Type (NN%)" into one cell. Finder-style
"Kind" and "Vendor" columns would scan better, especially together with FP-2.
Toasts for "Scan complete" and every copy action are noise when the footer and
the clipboard already confirm them. Keep toasts for errors and for results that
aren't otherwise visible.

**VIS-9: About box (S).** "About Lantenna..." with the antenna icon, the
version and a quip, in System 7 style.

### Delight

**DELIGHT-1: A broadcasting antenna (S).** Merges `awesome.md` D2. During a
scan, show a small pixel antenna in the footer emitting "waves" (CSS steps
animation), or a dithered 1-bit radar sweep while there are no results yet.

**DELIGHT-2: Sonar sound, opt-in (S).** Merges `awesome.md` D1. Synthesize a
short 8-bit "ping" with WebAudio (no copyrighted samples) when a new device
appears, and a chirp when the scan completes. Include a mute setting.

**DELIGHT-3: Subnet map (M).** From `awesome.md` D8. A 16×16 grid for a /24
where each cell is one address, filled when alive, clickable to select. It
could be a third view next to List and Icons.

**DELIGHT-4: Signal bars (S, after FEAT-11).** Show RTT as 1 to 4 pixel
antenna bars per row.

**DELIGHT-5: A "Get Info" window (M).** Pop the inspector out as a movable
System 7 dialog (`MovableDialog`) with ⌘I.

**DELIGHT-6: A bomb dialog for fatal errors (S).** Show "The scanner stopped
unexpectedly" (the message from #17) in system7-ui's `SystemErrorDialog` with
the bomb icon and a Restart button, instead of a banner.

**DELIGHT-7: A welcome splash (S).** A "Welcome to Lantenna" box on first
launch, whose progress bar actually tracks interface detection.

**DELIGHT-8: An Easter egg (S).** Typing `appletalk` into the filter shows
every device as a LaserWriter for a moment.

### Code health, tooling and docs

**CODE-1: Split `scanner.rs` (M, after the in-flight PRs merge).** It is
about 2,500 lines covering targets, the probe engine, ICMP, ARP, mDNS, SSDP,
banners, OUI and online lookups, heuristics, and service names. Split it into
`discovery/{tcp,arp,icmp}.rs`, `mdns.rs`, `banners.rs`,
`fingerprint/{heuristics,lookups}.rs` and `ports.rs`, as a pure move with no
behavior change.

**CODE-2: A named struct for `infer_device_profile` (S).** It returns a
5-tuple. Replace it with a struct.

**CODE-3: A shared device-kind vocabulary (M).** `device_type` is free text
matched by substring in `hostIcons.ts` (for example "tv" matches inside other
words), and service names and port meanings are duplicated between Rust
(`service_name`) and TypeScript (`portTargets.ts`). Introduce a `DeviceKind`
enum and a service table serialized to the frontend.

**CODE-4: Remaining duplicate helpers (S).** `ipToNumber` exists in
`scanStore.ts`, `HostTable.svelte` and `HostIconGrid.svelte`. Move it to a
util.

**CODE-5: Frontend tests and formatting (M).** There's no vitest, eslint or
prettier, and the Svelte files mix 2- and 4-space indentation. Do this in two
steps:

1. Add vitest for the pure utils (`format.ts`, `hostSearch.ts`,
   `portTargets.ts`, `hostIcons.ts`, `scanProgress.ts`, `mac.ts`, `errors.ts`),
   plus an `npm test` CI step. The September review checked these with ad-hoc
   assertions; turn those into tests.
2. Add prettier, in its own mechanical PR.

**CODE-6: A mock-IPC dev mode and UI smoke tests (M).** Ship the Tauri IPC
mock from the verification toolbox as `?mock` in dev builds, for a fast UI
loop, README screenshots, and Playwright smoke tests in CI (scan, filter,
select, icon view).

**CODE-7: Pin GitHub Actions to commit SHAs (S).** Tags like `@v5` and `@v2`
are mutable. Pin every workflow action to a SHA, with a version comment. The
GLM review workflow already does this.

**CODE-8: Shrink the favicon (S).** `static/favicon.png` is 2481×2481
(2.5 MB, 83% of the built frontend) and is embedded in the binary. Replace it
with a 64×64 PNG.

**CODE-9: Metadata and README (S).**

- `Cargo.toml` has `authors = ["you"]`.
- The README repeats the LLM disclosure, has no feature list or usage notes,
  and doesn't mention the optional `FINGERBANK_API_KEY`.
- `media-sources/screenshot.png` still shows the old "Ports: Quick" toolbar.
