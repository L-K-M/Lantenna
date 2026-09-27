// Owner: unit B (spec 8.4). Spec: 2.6, 2.8, 3.1 (1.9 to 1.14, 1.22,
// 1.25), 3.4 (placeholders).
//
// The hosts as both views, the pane, the header and the menus see them:
// one row per host with its display texts and state, the rows the list
// shows (the hidden rule, then the Show scope, then the Find query,
// sorted by ui.listSort), the counts the header needs, the selected
// host, and the list's placeholder texts.
//
// Rows are immutable and cached per Host object (a WeakMap, checked
// against the row's state), so a store update hands the list view the
// same object for every unchanged host and Osmium skips it. The store
// replaces a Host object whenever its data changes and keeps it
// otherwise. Relative "Last Seen" texts depend on the clock, so they are
// worked out by the views when they draw, not kept here.
//
// Import direction: this module imports ui, scanStore, hostSort, leaves
// and modules that import no app module (the util helpers, sprites.ts);
// none of those may import it back as a value.

import { readable, type Readable } from 'svelte/store';
import type { ListViewSort } from 'osmium-ui';
import { SMALL_ICON, type HostIconKind } from '$lib/osm/sprites';
import type { Host } from '$lib/types';
import { EMPTY_VALUE, formatCount, normalizeDisplayText, shortVendorName } from '$lib/util/format';
import { getHostIcon } from '$lib/util/hostIcons';
import { hostMatchesQuery } from '$lib/util/hostSearch';
import { isPrivateMac } from '$lib/util/mac';
import { getPortTarget, primaryPortTarget, type PortTarget } from '$lib/util/portTargets';
import { scanStore, type ScanStoreState } from '$lib/util/scanStore';
import { customNameFor, iconName, listName } from './hostNames';
import { sortRows } from './hostSort';
import { ui, type ShowScope } from './ui';

/** The Status column (2.6): a host found new by the last scan, one the
 * running scan hasn't confirmed yet, a favorite the last scan didn't
 * find, a hidden host shown by "Show hidden hosts", or nothing. */
export type RowStatus = '' | 'New' | 'Checking…' | 'Not seen' | 'Hidden';

export interface HostRow {
  readonly ip: string;
  readonly host: Host;
  /** The trimmed custom name, or null. */
  readonly customName: string | null;
  /** Display rules of 3.1 (hostNames.ts): the list's Name cell and the
   * icon tile's label. */
  readonly listName: string;
  readonly iconName: string;
  /** `small` is a CSS image (the 16 x 16 sprite, for the list),
   * `large` the URL of the 32 x 32 SVG (an img src; wrap it in url()
   * for CSS), for tiles and the General tab. `label` names the icon
   * ("Printer"). */
  readonly icon: {
    readonly kind: HostIconKind;
    readonly label: string;
    readonly small: string;
    readonly large: string;
  };
  /** Kind column: the device type, else the OS guess, else the model
   * guess (normalized); "Unknown" when fingerprinted without any, "--"
   * without a fingerprint. */
  readonly kind: string;
  /** Vendor column: the short vendor name, else "Private address"
   * (locally administered MAC), else "Unknown"; "--" without a
   * fingerprint. */
  readonly vendor: string;
  /** The full vendor name for the pane: vendor, else manufacturer, else
   * "Private address", else "Unknown". */
  readonly vendorFull: string;
  /** Up to six port numbers, then "+N"; "--" when none. */
  readonly portsText: string;
  readonly portCount: number;
  /** host.last_seen in ms since the epoch; 0 when unknown. */
  readonly lastSeenMs: number;
  readonly status: RowStatus;
  readonly favorite: boolean;
  readonly hidden: boolean;
  /** A favorite the last scan didn't find (listed from its snapshot). */
  readonly stale: boolean;
  /** Not yet confirmed by the running scan. */
  readonly pending: boolean;
  readonly isNew: boolean;
  /** Every port's target, in port order, one per URL. */
  readonly targets: readonly PortTarget[];
  /** What opening the host opens (HTTP, HTTPS, SMB, SSH, VNC first). */
  readonly primaryTarget: PortTarget | null;
}

export interface HostModel {
  /** Hidden rule + scope + query, sorted by ui.listSort. */
  readonly rows: readonly HostRow[];
  /** Hosts under the current hidden rule (N of 5.2). */
  readonly universe: number;
  /** New hosts among them (k of 5.2). */
  readonly newCount: number;
  /** Hidden hosts in the store (h of 5.2). */
  readonly hiddenCount: number;
  /** The selected host while it is in the store and not removed by the
   * hidden rule; the Show scope and the query don't hide it (the pane
   * keeps showing a host the query filters out). */
  readonly selected: HostRow | null;
  /** Whether the views show loadingText rather than emptyText while
   * they have no rows. */
  readonly loading: boolean;
  readonly loadingText: string;
  readonly emptyText: string;
}

// ---- texts (3.4) --------------------------------------------------------

const READING_TEXT = 'Reading the last scan…';
const SCANNING_TEXT = 'Scanning…';
const NO_FAVORITES_TEXT = 'No favorite hosts. To add one, click the star next to a host.';
const NO_NEW_TEXT = 'No new hosts since the previous scan.';
const NO_HOSTS_TEXT = 'No hosts yet. Click Scan to search your network.';
const ONLY_HOST_HIDDEN_TEXT = 'The only host is hidden. To see it, check “Show hidden hosts”.';

function noMatchText(query: string): string {
  return `No hosts match “${query}”.`;
}

function allHiddenText(n: number): string {
  return `All ${formatCount(n)} hosts are hidden. To see them, check “Show hidden hosts”.`;
}

// ---- rows ---------------------------------------------------------------

/** What a row shows besides its Host. */
interface RowState {
  readonly customName: string | null;
  readonly favorite: boolean;
  readonly hidden: boolean;
  readonly stale: boolean;
  readonly pending: boolean;
  readonly isNew: boolean;
}

/** The pre-port list showed six ports and "+N" for the rest. */
const MAX_LISTED_PORTS = 6;

/** Status precedence: the order of the column's normal sort (2.6). */
function rowStatus(s: RowState): RowStatus {
  if (s.isNew) return 'New';
  if (s.pending) return 'Checking…';
  if (s.stale) return 'Not seen';
  if (s.hidden) return 'Hidden';
  return '';
}

function kindText(host: Host): string {
  const fp = host.fingerprint;
  if (!fp) return EMPTY_VALUE;
  return normalizeDisplayText(fp.device_type || fp.os_guess || fp.model_guess || '') || 'Unknown';
}

function vendorText(host: Host): string {
  const fp = host.fingerprint;
  if (!fp) return EMPTY_VALUE;

  const raw = fp.vendor || fp.manufacturer;
  const short = raw ? shortVendorName(normalizeDisplayText(raw)) : '';
  if (short) return short;
  return isPrivateMac(fp.mac_address) ? 'Private address' : 'Unknown';
}

function vendorFullText(host: Host): string {
  const fp = host.fingerprint;
  return fp?.vendor || fp?.manufacturer || (isPrivateMac(fp?.mac_address) ? 'Private address' : 'Unknown');
}

function portsText(host: Host): string {
  const ports = host.open_ports;
  if (ports.length === 0) return EMPTY_VALUE;

  const shown = ports.slice(0, MAX_LISTED_PORTS).map((p) => String(p.port));
  if (ports.length > MAX_LISTED_PORTS) shown.push(`+${ports.length - MAX_LISTED_PORTS}`);
  return shown.join(', ');
}

function portTargets(host: Host): PortTarget[] {
  const targets: PortTarget[] = [];
  for (const port of host.open_ports) {
    const target = getPortTarget(host.ip, port.port, port.service);
    if (target && !targets.some((t) => t.url === target.url)) targets.push(target);
  }
  return targets;
}

function timeOf(iso: string): number {
  const ms = iso ? Date.parse(iso) : Number.NaN;
  return Number.isNaN(ms) ? 0 : ms;
}

const rowCache = new WeakMap<Host, HostRow>();

function sameState(row: HostRow, s: RowState): boolean {
  return (
    row.customName === s.customName &&
    row.favorite === s.favorite &&
    row.hidden === s.hidden &&
    row.stale === s.stale &&
    row.pending === s.pending &&
    row.isNew === s.isNew
  );
}

/** `host`'s row in state `s`: the cached object while neither changed. */
function hostRow(host: Host, s: RowState): HostRow {
  const cached = rowCache.get(host);
  if (cached && sameState(cached, s)) return cached;

  const icon = getHostIcon(host, s.customName ?? '');
  const row: HostRow = Object.freeze({
    ip: host.ip,
    host,
    customName: s.customName,
    listName: listName(host, s.customName),
    iconName: iconName(host, s.customName),
    icon: Object.freeze({ kind: icon.kind, label: icon.label, small: SMALL_ICON[icon.kind], large: icon.src }),
    kind: kindText(host),
    vendor: vendorText(host),
    vendorFull: vendorFullText(host),
    portsText: portsText(host),
    portCount: host.open_ports.length,
    lastSeenMs: timeOf(host.last_seen),
    status: rowStatus(s),
    favorite: s.favorite,
    hidden: s.hidden,
    stale: s.stale,
    pending: s.pending,
    isNew: s.isNew,
    targets: Object.freeze(portTargets(host)),
    primaryTarget: primaryPortTarget(host)
  });
  rowCache.set(host, row);
  return row;
}

// ---- the model ----------------------------------------------------------

function emptyTextFor(state: ScanStoreState, scope: ShowScope, hidden: ReadonlySet<string>): string {
  const query = state.query.trim();
  const hosts = state.hosts;
  if (query && hosts.length > 0) return noMatchText(query);
  if (scope === 'favorites') return NO_FAVORITES_TEXT;
  if (scope === 'new') return NO_NEW_TEXT;

  const allHidden = !state.showHiddenEntries && hosts.length > 0 && hosts.every((h) => hidden.has(h.ip));
  if (allHidden) return hosts.length === 1 ? ONLY_HOST_HIDDEN_TEXT : allHiddenText(hosts.length);
  return NO_HOSTS_TEXT;
}

/** The model for a store state, a Show scope and a sort. Pure but for
 * the row cache. */
export function buildHostModel(state: ScanStoreState, scope: ShowScope, sort: ListViewSort): HostModel {
  const favorites = new Set(state.favoriteIps);
  const hidden = new Set(state.hiddenIps);
  const stale = new Set(state.staleFavoriteIps);
  const pending = new Set(state.pendingIps);
  const fresh = new Set(state.newHostIps);

  const rowFor = (host: Host): HostRow => {
    const ip = host.ip;
    return hostRow(host, {
      customName: customNameFor(state.customNames, ip),
      favorite: favorites.has(ip),
      hidden: hidden.has(ip),
      stale: stale.has(ip),
      pending: pending.has(ip),
      isNew: fresh.has(ip)
    });
  };

  const underHiddenRule = state.showHiddenEntries ? state.hosts : state.hosts.filter((h) => !hidden.has(h.ip));
  const query = state.query;
  const blankQuery = query.trim() === '';
  const listed = underHiddenRule.filter(
    (h) =>
      (scope === 'all' || (scope === 'favorites' ? favorites.has(h.ip) : fresh.has(h.ip))) &&
      (blankQuery || hostMatchesQuery(h, customNameFor(state.customNames, h.ip) ?? '', query))
  );

  const selectedHost =
    state.selectedHostIp === null ? undefined : underHiddenRule.find((h) => h.ip === state.selectedHostIp);

  return {
    rows: sortRows(listed.map(rowFor), sort),
    universe: underHiddenRule.length,
    newCount: underHiddenRule.reduce((n, h) => n + Number(fresh.has(h.ip)), 0),
    hiddenCount: state.hosts.reduce((n, h) => n + Number(hidden.has(h.ip)), 0),
    selected: selectedHost ? rowFor(selectedHost) : null,
    // "Scanning…" only while the scan hasn't found anything yet; hosts
    // the filters hide get the more specific empty texts.
    loading: state.loading || (state.scanning && state.hosts.length === 0),
    loadingText: state.loading ? READING_TEXT : SCANNING_TEXT,
    emptyText: emptyTextFor(state, scope, hidden)
  };
}

const EMPTY_MODEL: HostModel = {
  rows: [],
  universe: 0,
  newCount: 0,
  hiddenCount: 0,
  selected: null,
  loading: false,
  loadingText: SCANNING_TEXT,
  emptyText: NO_HOSTS_TEXT
};

/**
 * The model, rebuilt when the store changes or the Show scope or sort
 * does (other ui changes, such as the window's activity, leave it and
 * its subscribers alone).
 */
export const hostModel: Readable<HostModel> = readable(EMPTY_MODEL, (set) => {
  let state: ScanStoreState | null = null;
  let scope: ShowScope | null = null;
  let sort: ListViewSort | null = null;

  const rebuild = () => {
    if (state && scope && sort) set(buildHostModel(state, scope, sort));
  };

  const stopUi = ui.subscribe((u) => {
    if (u.scope === scope && u.listSort === sort) return;
    scope = u.scope;
    sort = u.listSort;
    rebuild();
  });
  const stopStore = scanStore.subscribe((s) => {
    state = s;
    rebuild();
  });

  return () => {
    stopUi();
    stopStore();
  };
});
