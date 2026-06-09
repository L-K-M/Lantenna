# Lantenna — Code Review & Ideas

A thorough review of the current codebase (Rust scanner backend + Svelte/System 7 frontend),
collected into bugs, general issues, missing features, and ideas. Each entry has a
confidence/severity note and a status line that tracks whether it was implemented as part of
this review round.

---

## 1. Bugs

### B1. `cargo test` does not compile — test fixture out of date 🔴
**Where:** `src-tauri/src/storage.rs` (tests, `fingerprint_with_timestamp`)
`DeviceFingerprint` gained a `discovered_services: Vec<String>` field (models.rs), but the
test fixture struct literal was never updated. Any `cargo test` run fails with
`missing field 'discovered_services'`. This also means the storage tests (and by extension all
Rust tests) haven't run since the field was added.
**Status:** ✅ Fixed (bug-fix PR).

### B2. mDNS fingerprint cross-contamination — services attributed to the wrong host 🔴
**Where:** `src-tauri/src/scanner.rs` → `query_mdns_services(_ip: Ipv4Addr)`
The function takes the target IP but *ignores it* (note the `_ip`). It sends a multicast mDNS
query and accepts responses from **any** device on the LAN for 500 ms, then attributes every
advertised service to the host currently being fingerprinted. Concretely: if your Apple TV
answers while the scanner is enriching your printer, the printer's fingerprint gets
"AirPlay device" notes, a confidence boost, and possibly a wrong device type — and that wrong
fingerprint is then **cached for 90 days** keyed to the printer's MAC.
**Fix:** filter `recv_from` results so only responses whose source address matches the target
host are parsed.
**Status:** ✅ Fixed (bug-fix PR).

### B3. One mDNS multicast burst per host during enrichment 🟠
**Where:** `src-tauri/src/scanner.rs` → `enrich_hosts_with_cache` / `build_fingerprint`
Every enriched host triggers its own 23-question multicast burst + 500 ms listening window
(with enrichment concurrency up to 12, that's a small multicast storm per scan, and most of the
collected data was duplicated garbage due to B2). The whole subnet can be covered by a *single*
query whose responses are grouped by responder address.
**Status:** ✅ Fixed (bug-fix PR) — one shared mDNS sweep per scan, responses grouped by source IP.

### B4. `parse_ssh_banner` extracts the wrong software / misses the OS 🟠
**Where:** `src-tauri/src/scanner.rs` → `parse_ssh_banner`
For the most common Ubuntu banner `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1`:
- `software` ends up as `"Ubuntu"` (it takes the *comment* field and splits it on `-`),
  while the actual software (`OpenSSH_8.9p1`) lives in the first whitespace token.
- `os_guess` ends up `None` because it checks the last `-` segment (`3ubuntu0.1`) against the
  case-sensitive needle `"Ubuntu"`.
- Banners with no comment at all (e.g. plain `SSH-2.0-OpenSSH_9.6`) return `None` entirely,
  so the software is never recorded for the most common case.
**Fix:** software = the part after `SSH-<protoversion>-` in the first token; OS hints are
matched case-insensitively against the whole banner.
**Status:** ✅ Fixed (bug-fix PR, with unit tests).

### B5. Frontend types out of sync with Rust models 🟠
**Where:** `src/lib/types.ts`
- `DeviceFingerprint` is missing `discovered_services: string[]` (exists in models.rs).
- `PortInfo` is missing `banner: string | null` (exists in models.rs, and the backend spends
  real effort grabbing SSH/HTTP/FTP banners) — so the UI literally cannot show banners and
  TypeScript would reject any attempt to.
**Status:** ✅ Fixed (bug-fix PR) — types added, and banners are now displayed in the host
inspector port list.

### B6. "Last Seen" column shows only the time of day 🟡
**Where:** `src/lib/components/HostTable.svelte` → `formatTime`
Results restored from a previous day (persisted latest scan, favorite snapshots) render as e.g.
`14:32:08`, which reads as *today* 14:32. Misleading the morning after.
**Fix:** include the date when the timestamp is not from today.
**Status:** ✅ Fixed (bug-fix PR).

### B7. README installation instructions are missing the clone step 🟡
**Where:** `README.md` — the code block says “Clone the repository” but only contains
`cd Lantenna`.
**Status:** ✅ Fixed (bug-fix PR).

### B8. Listener attach/destroy race in `scanStore` 🟡
**Where:** `src/lib/util/scanStore.ts` → `attachListeners` / `destroy`
`attachListeners` awaits five `listen()` calls sequentially. If the page unmounts mid-flight
(`destroy()` runs while some `listen()` promises are pending), the late listeners are pushed
into `unlisteners` *after* the drain loop has already run and never get cleaned up; with
`listenersAttached` reset to `false`, a remount attaches a second copy. Low impact in practice
(single long-lived window), but it's a real leak pattern.
**Status:** 💤 Not fixed — documented here; fix is straightforward (generation counter or
attach token) if hot-reload double-listening is ever observed.

---

## 2. General issues

### G1. Banner grabbing opens a second, unthrottled TCP connection
`scan_port` successfully connects, then `grab_banner_for_port` *reconnects* to the same port
instead of reusing the already-open stream — doubling connections to every open port, and the
second connection is made **outside** the global connection semaphore. Cosmetically this also
makes Lantenna look noisier in target device logs.

### G2. UDP-only services are probed over TCP
The Standard profile's TCP port list includes 67/68/69 (DHCP/TFTP), 123 (NTP), 137/138
(NetBIOS dgram), 161 (SNMP), 500 (ISAKMP), 514 (syslog), 1812 (RADIUS), 5353 (mDNS) — all
UDP-side services that will essentially never accept a TCP connect. These are wasted probes,
and worse, heuristics like the Apple check `has(5353)` in `infer_device_profile` can
essentially never fire because TCP 5353 is almost never open.

### G3. Storage does synchronous file I/O under a mutex on async workers
`Storage::save()` serializes the entire store (latest scan + both caches) with
`to_string_pretty` and writes it to disk while holding the data mutex — and it's called from
async contexts (`cache_vendors`, `cache_fingerprints` during enrichment). On a large scan this
is a repeated full-file rewrite that blocks tokio worker threads. Consider `spawn_blocking`
and/or a debounced single save at the end of enrichment.

### G4. External MAC lookups leak MACs off-box and aren't rate-limited
`lookup_vendor_via_maclookup` sends device MAC addresses to `api.maclookup.app` (and
optionally Fingerbank). Privacy-minded users may not expect a LAN scanner to phone home with
their device inventory; the free maclookup tier is also rate-limited (~2 req/s) while
enrichment runs up to 12 concurrent lookups. Suggest: an "offline mode" toggle, and a small
semaphore around external lookups. (The bundled OUI DB already covers the common cases.)

### G5. `enrich_host_internal` leaves stale duplicate cache entries
When a fingerprint cached under `ip:<addr>` is promoted to its `mac:<addr>` key, the old `ip:`
entry is left behind — harmless but wasteful, and the two copies can drift.

### G6. OUI vendor cache eviction is alphabetical, not LRU
`prune_oui_vendor_cache` sorts keys and removes the lexicographically smallest — so vendors
whose OUI starts with `00:` are always evicted first regardless of how recently they were used.

### G7. Hybrid-discovery phase happens "after" the progress bar completes
`total` counts only TCP targets; the ARP + ICMP fallback phase runs after `scanned == total`,
so the progress bar sits at 100 % (status: running) while hosts keep appearing. A second
progress stage ("Probing quiet hosts…") would set expectations better.

### G8. `select_interface` can scan a subnet the interface isn't on
If the requested subnet doesn't match any interface entry but the name does, the scan proceeds
with the *requested* subnet over a route that may not cover it. The current UI always sends
matching pairs, so this is only reachable via stale persisted state.

### G9. Confidence score is additive pseudo-precision
`confidence` accumulates +20 MAC, +15 vendor, +8 hostname, heuristic boosts… clamped to 99 and
rendered as a percentage. It reads as a calibrated probability but isn't one. Consider
displaying it as a coarse `Low / Medium / High` chip instead of `87%`.

---

## 3. Missing features

### M1. SSDP discovery is fully implemented… and dead code
`discover_ssdp_devices` / `parse_ssdp_response` exist behind `#[allow(dead_code)]` and are
never called. SSDP `LOCATION`/`SERVER` headers are a goldmine for fingerprinting routers,
TVs, consoles, and NAS boxes. Wiring this into the hybrid discovery/enrichment path is mostly
free signal.

### M2. Wake-on-LAN ⏰
The scanner already collects MAC addresses — sending a WoL magic packet is ~30 lines of Rust
and turns Lantenna from a passive observer into something genuinely useful ("the NAS is
asleep → click Wake"). **Status:** ✅ Implemented (feature PR) — "Wake" button in the host
inspector for any host with a known MAC.

### M3. Export scan results
No way to get results out of the app (CSV/JSON to clipboard or file). Useful for diffing,
documentation, and home-lab inventory chores.

### M4. Scan history & diffing
Only the latest scan is persisted. Keeping the last N scans would enable "what changed since
last week", first-seen dates per MAC, and uptime patterns. The NEW-badge comparison logic
already exists; it just has nothing historical to compare against beyond the previous run.

### M5. Latency column
The TCP connect already measures round-trip time implicitly — record `Instant::elapsed` on the
first successful connect and show an RTT column. Cheap and surprisingly informative
(spot the powerline adapter at a glance).

### M6. Custom port set / port range input
Quick/Standard/Deep are good defaults, but there's no way to say "just check 8123 and 1883 on
my IoT VLAN".

### M7. mDNS hostname resolution
Hostnames come from reverse DNS only; many home devices only answer via mDNS
(`hostname.local`). The mDNS plumbing from B2/B3 could also issue PTR lookups for nicer names.

### M8. IPv6 awareness
Everything is IPv4-only (`IfAddr::V4` is filtered explicitly). Even just *listing* v6
neighbors from the NDP table alongside v4 results would be a start.

### M9. Keyboard shortcuts for primary actions
The host table has lovely keyboard navigation, but starting a scan (⌘R) and focusing the
filter field (⌘F) still require the mouse.

---

## 4. Novel / delightful / quirky ideas

### D1. Sonar ping sound 🔊
A soft submarine-sonar "ping" (with a System 7-appropriate 8-bit crunch) each time a new host
surfaces during a scan. Obviously with a mute toggle. The app is called Lantenna; it should
*sound* like it's listening.

### D2. Radar sweep idle animation
While scanning with zero results yet, replace the "Scanning…" text with a tiny 1-bit radar
sweep (a rotating line in a circle, dithered System 7 style). Pure CSS, pure joy.

### D3. Network weather report ☀️
After each scan, a one-line human summary in the footer or as a notification:
*"Quiet evening on 192.168.1.0/24 — 12 regulars, 1 stranger (NEW), printer still pretending
to be asleep."* Generated from the diff data the store already computes.

### D4. "Stranger danger" watch mode
A periodic background re-scan (every N minutes) that only alerts when a never-before-seen MAC
joins the network. Turns the app into a lightweight intrusion noticer. Pairs perfectly with
M4 (history) and D1 (the ping gets *louder*… kidding. Same ping.).

### D5. Per-device first-seen "birthday"
With M4's history: "First seen 212 days ago". Devices quietly accumulate seniority. Your
oldest IoT lightbulb deserves recognition.

### D6. Printed-report export 🖨️
Export the host table as a retro monospaced "NETWORK SURVEY" report (think 1992 dot-matrix
aesthetic, complete with `========` rules) — fits the System 7 vibe and is genuinely a nice
shareable artifact for home-lab forums.

### D7. Menu-bar (tray) quick glance
A macOS menu-bar item showing the current host count, with a dropdown of NEW devices since the
last scan. The full window stays closed; the antenna keeps listening.

### D8. ASCII subnet map
A 16×16 grid view of a /24 where each cell is a host octet — filled cells are alive, hollow
ones silent. Click a cell to select the host. Equal parts useful heat-map and Defender-era
aesthetics.

---

*Review performed June 2026. Status markers: ✅ implemented in an accompanying PR,
💤 documented only.*
