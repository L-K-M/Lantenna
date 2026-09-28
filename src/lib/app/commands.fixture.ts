// Owner: unit E (spec 8.4, tests). Builders for the unit E tests: hosts,
// rows and whole CommandContexts in any state, without the stores.

import type { Host, NetworkInterface } from '$lib/types';
import type { ScanProgressState, ScanStoreState } from '$lib/util/scanStore';
import { getPortTarget, primaryPortTarget } from '$lib/util/portTargets';
import type { CommandContext } from './commands';
import type { FocusKind } from './focus';
import type { HostModel, HostRow } from './hostModel';
import { ipOrder } from './hostSort';
import type { Platform } from './platform';
import type { UiState } from './ui';

export const EN0: NetworkInterface = {
  name: 'en0',
  ip: '192.168.1.23',
  cidr: 24,
  subnet: '192.168.1.0/24',
  host_count: 254,
  is_default_route: true
};

export const EN7: NetworkInterface = {
  name: 'en7',
  ip: '10.0.0.5',
  cidr: 16,
  subnet: '10.0.0.0/16',
  host_count: 65534,
  is_default_route: false
};

/** A host with open ports `ports` (service from a small table). */
export function host(ip: string, over: Partial<Host> & { ports?: number[]; mac?: string | null } = {}): Host {
  const { ports = [], mac = null, ...rest } = over;
  const services: Record<number, string> = { 22: 'ssh', 80: 'http', 445: 'microsoft-ds', 8080: 'http-alt' };
  return {
    ip,
    name: null,
    reachable: true,
    open_ports: ports.map((port) => ({ port, state: 'open', service: services[port] ?? null, banner: null })),
    last_seen: '2026-09-27T13:42:00Z',
    fingerprint:
      mac === null
        ? null
        : {
            mac_address: mac,
            oui: null,
            vendor: null,
            manufacturer: null,
            model_guess: null,
            device_type: null,
            os_guess: null,
            confidence: 50,
            sources: [],
            notes: [],
            discovered_services: [],
            last_updated: '2026-09-27T13:42:00Z'
          },
    ...rest
  };
}

/** The row the host model would build for `h` (only the fields the
 * commands read are meaningful). */
export function row(h: Host, over: Partial<HostRow> = {}): HostRow {
  const targets = h.open_ports.flatMap((p) => getPortTarget(h.ip, p.port, p.service) ?? []);
  const customName = over.customName ?? null;
  return {
    ip: h.ip,
    ipNum: ipOrder(h.ip),
    host: h,
    customName,
    listName: customName || h.name || 'Unknown',
    iconName: customName || h.name?.replace(/\.local$/, '') || h.ip,
    icon: { kind: 'pc-generic', label: 'Unknown host', small: '', large: '' },
    kind: '--',
    vendor: '--',
    vendorFull: 'Unknown',
    portsText: '--',
    portCount: h.open_ports.length,
    lastSeenMs: 0,
    status: '',
    favorite: false,
    hidden: false,
    stale: false,
    pending: false,
    isNew: false,
    targets,
    primaryTarget: primaryPortTarget(h),
    ...over
  };
}

export const IDLE_STORE: ScanStoreState = {
  interfaces: [EN0],
  selectedInterface: 'en0|192.168.1.23',
  scanApproach: 'balanced',
  hosts: [],
  newHostIps: [],
  customNames: {},
  favoriteIps: [],
  hiddenIps: [],
  showHiddenEntries: false,
  staleFavoriteIps: [],
  scanning: false,
  stopping: false,
  pendingIps: [],
  loading: false,
  error: null,
  query: '',
  selectedHostIp: null,
  lastScanAt: null,
  lastScanCancelled: false
};

export const IDLE_UI: UiState = {
  viewMode: 'list',
  scope: 'all',
  infoPaneShown: true,
  infoTab: 'general',
  listSort: { column: 'favorite', order: 'normal' },
  columnWidths: null,
  balloons: 'hidden',
  active: true,
  shaded: false
};

export const EMPTY_MODEL: HostModel = {
  rows: [],
  universe: 0,
  newCount: 0,
  hiddenCount: 0,
  selected: null,
  loading: false,
  loadingText: '',
  emptyText: ''
};

export interface ContextParts {
  store?: Partial<ScanStoreState>;
  progress?: Partial<ScanProgressState>;
  ui?: Partial<UiState>;
  model?: Partial<HostModel>;
  focus?: FocusKind;
  modal?: boolean;
  wakingIp?: string | null;
  textSelected?: boolean;
  platform?: Platform;
}

/** An idle Linux context with one interface and nothing selected, with
 * `parts` laid over it. `shaded` follows `ui.shaded`, as the real one. */
export function context(parts: ContextParts = {}): CommandContext {
  const ui = { ...IDLE_UI, ...parts.ui };
  return {
    store: { ...IDLE_STORE, ...parts.store },
    progress: { progress: null, hostScanProgress: null, ...parts.progress },
    ui,
    model: { ...EMPTY_MODEL, ...parts.model },
    focus: parts.focus ?? 'other',
    modal: parts.modal ?? false,
    wakingIp: parts.wakingIp ?? null,
    textSelected: parts.textSelected ?? false,
    shaded: ui.shaded,
    platform: parts.platform ?? 'linux'
  };
}

/** A context with `r` selected and listed. */
export function selecting(r: HostRow, parts: ContextParts = {}): CommandContext {
  return context({
    ...parts,
    store: { hosts: [r.host], selectedHostIp: r.ip, ...parts.store },
    model: { rows: [r], universe: 1, selected: r, ...parts.model }
  });
}
