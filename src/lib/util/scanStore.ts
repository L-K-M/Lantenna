import { writable } from 'svelte/store';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { TauriService } from '$lib/tauri';
import type {
  DiscoveryMode,
  Host,
  NetworkInterface,
  PortProfile,
  ScanApproach,
  ScanErrorPayload,
  ScanProgress,
  ScanResult
} from '$lib/types';
import { errorMessage } from './errors';
import { scanEvents } from './scanEvents';

export interface ScanStoreState {
  interfaces: NetworkInterface[];
  selectedInterface: string | null;
  scanApproach: ScanApproach;
  hosts: Host[];
  newHostIps: string[];
  customNames: Record<string, string>;
  favoriteIps: string[];
  hiddenIps: string[];
  showHiddenEntries: boolean;
  staleFavoriteIps: string[];
  scanning: boolean;
  stopping: boolean;
  /** Hosts from the previous results not yet confirmed by the running scan. */
  pendingIps: string[];
  loading: boolean;
  error: string | null;
  query: string;
  selectedHostIp: string | null;
  lastScanAt: string | null;
  /** Whether the scan that set lastScanAt was stopped before it finished. */
  lastScanCancelled: boolean;
}

type FavoriteHostSnapshots = Record<string, Host>;

const FAVORITE_IPS_STORAGE_KEY = 'lantenna.favoriteIps';
const FAVORITE_HOSTS_STORAGE_KEY = 'lantenna.favoriteHosts';
const HIDDEN_IPS_STORAGE_KEY = 'lantenna.hiddenIps';
const CUSTOM_NAMES_STORAGE_KEY = 'lantenna.customNames';
const SELECTED_INTERFACE_STORAGE_KEY = 'lantenna.selectedInterface';
const MAX_SCAN_HOSTS = 4096;

interface ScanApproachSettings {
  portProfile: PortProfile;
  discoveryMode: DiscoveryMode;
  timeoutMs: number;
}

const DEFAULT_SCAN_APPROACH: ScanApproach = 'balanced';

function approachToSettings(approach: ScanApproach): ScanApproachSettings {
  switch (approach) {
    case 'fast':
      return {
        portProfile: 'quick',
        discoveryMode: 'tcp',
        timeoutMs: 350
      };
    case 'thorough':
      return {
        portProfile: 'deep',
        discoveryMode: 'hybrid',
        timeoutMs: 600
      };
    case 'balanced':
    default:
      return {
        portProfile: 'standard',
        discoveryMode: 'hybrid',
        timeoutMs: 450
      };
  }
}

function settingsToApproach(portProfile: PortProfile, discoveryMode: DiscoveryMode): ScanApproach {
  if (portProfile === 'deep') {
    return 'thorough';
  }

  if (portProfile === 'quick' || discoveryMode === 'tcp') {
    return 'fast';
  }

  return 'balanced';
}

function canUseStorage(): boolean {
  return typeof window !== 'undefined' && typeof window.localStorage !== 'undefined';
}

function loadFavoriteIps(): string[] {
  if (!canUseStorage()) {
    return [];
  }

  try {
    const raw = window.localStorage.getItem(FAVORITE_IPS_STORAGE_KEY);
    if (!raw) {
      return [];
    }

    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed.filter((item): item is string => typeof item === 'string');
  } catch {
    return [];
  }
}

function loadHiddenIps(): string[] {
  if (!canUseStorage()) {
    return [];
  }

  try {
    const raw = window.localStorage.getItem(HIDDEN_IPS_STORAGE_KEY);
    if (!raw) {
      return [];
    }

    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed.filter((item): item is string => typeof item === 'string');
  } catch {
    return [];
  }
}

function saveFavoriteIps(favoriteIps: string[]) {
  if (!canUseStorage()) {
    return;
  }

  window.localStorage.setItem(FAVORITE_IPS_STORAGE_KEY, JSON.stringify(favoriteIps));
}

function saveHiddenIps(hiddenIps: string[]) {
  if (!canUseStorage()) {
    return;
  }

  window.localStorage.setItem(HIDDEN_IPS_STORAGE_KEY, JSON.stringify(hiddenIps));
}

function loadFavoriteHostSnapshots(): FavoriteHostSnapshots {
  if (!canUseStorage()) {
    return {};
  }

  try {
    const raw = window.localStorage.getItem(FAVORITE_HOSTS_STORAGE_KEY);
    if (!raw) {
      return {};
    }

    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') {
      return {};
    }

    return parsed as FavoriteHostSnapshots;
  } catch {
    return {};
  }
}

function saveFavoriteHostSnapshots(snapshots: FavoriteHostSnapshots) {
  if (!canUseStorage()) {
    return;
  }

  window.localStorage.setItem(FAVORITE_HOSTS_STORAGE_KEY, JSON.stringify(snapshots));
}

function normalizeIpList(ips: string[]): string[] {
  const unique = Array.from(new Set(ips));
  return unique.sort((a, b) => ipToNumber(a) - ipToNumber(b));
}

function loadCustomNames(): Record<string, string> {
  if (!canUseStorage()) {
    return {};
  }

  try {
    const raw = window.localStorage.getItem(CUSTOM_NAMES_STORAGE_KEY);
    if (!raw) {
      return {};
    }

    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') {
      return {};
    }

    const entries = Object.entries(parsed).filter(
      (entry): entry is [string, string] => typeof entry[0] === 'string' && typeof entry[1] === 'string'
    );

    return Object.fromEntries(entries);
  } catch {
    return {};
  }
}

function saveCustomNames(customNames: Record<string, string>) {
  if (!canUseStorage()) {
    return;
  }

  window.localStorage.setItem(CUSTOM_NAMES_STORAGE_KEY, JSON.stringify(customNames));
}

function loadSelectedInterfaceKey(): string | null {
  if (!canUseStorage()) {
    return null;
  }

  const raw = window.localStorage.getItem(SELECTED_INTERFACE_STORAGE_KEY);
  return raw && raw.length > 0 ? raw : null;
}

function saveSelectedInterfaceKey(selectedInterface: string | null) {
  if (!canUseStorage()) {
    return;
  }

  if (!selectedInterface) {
    window.localStorage.removeItem(SELECTED_INTERFACE_STORAGE_KEY);
    return;
  }

  window.localStorage.setItem(SELECTED_INTERFACE_STORAGE_KEY, selectedInterface);
}

/** The `name|ip` key that identifies an interface in the store, the
 * Interface pop-up and the Scan menu (spec 3.1 1.6). */
export function interfaceKey(item: NetworkInterface): string {
  return `${item.name}|${item.ip}`;
}

function splitInterfaceKey(value: string): { name: string; ip: string } {
  const [name, ...rest] = value.split('|');
  return {
    name,
    ip: rest.join('|')
  };
}

/** The interface a stored key names: the exact `name|ip`, else the only
 * interface with that name (also for legacy keys without `|`), else null. */
export function findInterfaceByKey(
  interfaces: readonly NetworkInterface[],
  selectedInterface: string | null
): NetworkInterface | null {
  if (!selectedInterface) {
    return null;
  }

  if (selectedInterface.includes('|')) {
    const exact = interfaces.find((item) => interfaceKey(item) === selectedInterface);
    if (exact) {
      return exact;
    }

    const fallback = splitInterfaceKey(selectedInterface);
    const nameMatches = interfaces.filter((item) => item.name === fallback.name);
    return nameMatches.length === 1 ? nameMatches[0] : null;
  }

  const legacyMatches = interfaces.filter((item) => item.name === selectedInterface);
  return legacyMatches.length === 1 ? legacyMatches[0] : null;
}

function isPrivateAddress(ip: string): boolean {
  const [a, b] = ip.split('.').map((part) => Number(part));
  if (Number.isNaN(a) || Number.isNaN(b)) {
    return false;
  }

  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function isLinkLocalAddress(ip: string): boolean {
  const [a, b] = ip.split('.').map((part) => Number(part));
  if (Number.isNaN(a) || Number.isNaN(b)) {
    return false;
  }

  return a === 169 && b === 254;
}

/**
 * Name prefixes of interfaces that are rarely the LAN you mean to scan: VM and
 * Internet Sharing bridges (including Parallels' vnic adapters), VPN tunnels,
 * Apple Wireless Direct Link, container and tap/tun devices.
 */
const VIRTUAL_INTERFACE_PREFIXES = [
  'bridge',
  'utun',
  'vmnet',
  'vboxnet',
  'awdl',
  'llw',
  'docker',
  'veth',
  'tap',
  'tun',
  'wg',
  'tailscale',
  'ppp',
  'ipsec',
  'zt',
  'feth',
  'vnic'
];

function isVirtualInterface(item: NetworkInterface): boolean {
  return VIRTUAL_INTERFACE_PREFIXES.some((prefix) => item.name.startsWith(prefix));
}

function pickDefaultInterface(interfaces: NetworkInterface[]): NetworkInterface | null {
  const scannable = interfaces.filter((item) => item.host_count > 0 && !isLinkLocalAddress(item.ip));

  // The interface that carries the default route is the network in use, unless
  // it is a full-tunnel VPN, or has a public address: never start out aimed at
  // someone else's address space.
  const defaultRoute = scannable.find(
    (item) => item.is_default_route && !isVirtualInterface(item) && isPrivateAddress(item.ip)
  );
  if (defaultRoute) {
    return defaultRoute;
  }

  const preferred = scannable.filter((item) => isPrivateAddress(item.ip));

  if (preferred.length > 0) {
    return [...preferred].sort((a, b) => {
      const aVirtual = Number(isVirtualInterface(a));
      const bVirtual = Number(isVirtualInterface(b));
      const aDistance = Math.abs(a.host_count - 254);
      const bDistance = Math.abs(b.host_count - 254);
      return (
        aVirtual - bVirtual ||
        aDistance - bDistance ||
        a.name.localeCompare(b.name) ||
        a.ip.localeCompare(b.ip)
      );
    })[0];
  }

  return interfaces.find((item) => item.host_count > 0) || interfaces[0] || null;
}

function resolveSelectedInterfaceKey(
  interfaces: NetworkInterface[],
  preferredInterfaceKey: string | null
): string | null {
  const selected = findInterfaceByKey(interfaces, preferredInterfaceKey);
  if (selected) {
    return interfaceKey(selected);
  }

  const fallback = pickDefaultInterface(interfaces);
  return fallback ? interfaceKey(fallback) : null;
}

function makeFallbackHost(ip: string): Host {
  return {
    ip,
    name: null,
    reachable: false,
    open_ports: [],
    last_seen: '',
    fingerprint: null
  };
}

function mergeStaleFavoritesIntoHosts(
  hosts: Host[],
  staleFavoriteIps: string[],
  snapshots: FavoriteHostSnapshots
): Host[] {
  const nextHosts = [...hosts];
  const existingIps = new Set(hosts.map((host) => host.ip));

  for (const ip of staleFavoriteIps) {
    if (existingIps.has(ip)) {
      continue;
    }

    const snapshot = snapshots[ip];
    nextHosts.push(snapshot ? { ...snapshot, ip } : makeFallbackHost(ip));
  }

  return sortHosts(nextHosts);
}

function calculateStaleFavoriteIps(favoriteIps: string[], hosts: Host[]): string[] {
  const visibleIps = new Set(hosts.map((host) => host.ip));
  return favoriteIps.filter((ip) => !visibleIps.has(ip));
}

const initialFavoriteIps = normalizeIpList(loadFavoriteIps());
const initialHiddenIps = normalizeIpList(loadHiddenIps());
const initialFavoriteHostSnapshots = loadFavoriteHostSnapshots();
const initialStaleFavoriteIps = [...initialFavoriteIps];
const initialCustomNames = loadCustomNames();
const initialSelectedInterface = loadSelectedInterfaceKey();

const initialState: ScanStoreState = {
  interfaces: [],
  selectedInterface: initialSelectedInterface,
  scanApproach: DEFAULT_SCAN_APPROACH,
  hosts: mergeStaleFavoritesIntoHosts([], initialStaleFavoriteIps, initialFavoriteHostSnapshots),
  newHostIps: [],
  customNames: initialCustomNames,
  favoriteIps: initialFavoriteIps,
  hiddenIps: initialHiddenIps,
  showHiddenEntries: false,
  staleFavoriteIps: initialStaleFavoriteIps,
  scanning: false,
  stopping: false,
  pendingIps: [],
  // True until init() settles, so the first paint says "Reading the last
  // scan…" (spec 2.9) rather than "no interfaces" (5.2 row 12).
  loading: true,
  error: null,
  query: '',
  selectedHostIp: null,
  lastScanAt: null,
  lastScanCancelled: false
};

function ipToNumber(ip: string): number {
  const parts = ip.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) {
    return Number.MAX_SAFE_INTEGER;
  }

  return parts[0] * 256 ** 3 + parts[1] * 256 ** 2 + parts[2] * 256 + parts[3];
}

function sortHosts(hosts: Host[]): Host[] {
  return [...hosts].sort((a, b) => ipToNumber(a.ip) - ipToNumber(b.ip));
}

function sortIps(ips: string[]): string[] {
  return [...ips].sort((a, b) => ipToNumber(a) - ipToNumber(b));
}

function uniqueSortedIps(ips: string[]): string[] {
  return sortIps(Array.from(new Set(ips)));
}

function scanTargetKey(interfaceName: string, subnet?: string | null): string {
  return `${interfaceName}|${subnet || ''}`;
}

function scanTargetMatches(previousTarget: string | null, interfaceName: string, subnet?: string | null): boolean {
  if (!previousTarget) {
    return false;
  }

  const exactTarget = scanTargetKey(interfaceName, subnet);
  if (previousTarget === exactTarget) {
    return true;
  }

  return previousTarget === `${interfaceName}|` || previousTarget === interfaceName;
}

/** Replaces or appends `host`; callers sort (via mergeStaleFavoritesIntoHosts). */
function upsertHost(hosts: Host[], host: Host): Host[] {
  const index = hosts.findIndex((item) => item.ip === host.ip);
  if (index >= 0) {
    const next = [...hosts];
    next[index] = host;
    return next;
  }

  return [...hosts, host];
}

export interface ScanProgressState {
  progress: ScanProgress | null;
  hostScanProgress: ScanProgress | null;
}

/**
 * Progress lives apart from the main scan state. A scan sends many progress
 * events, and routing them through the main store made every one re-derive
 * and re-render the whole host table.
 */
export const scanProgress = writable<ScanProgressState>({ progress: null, hostScanProgress: null });

function createScanStore() {
  const { subscribe, update } = writable<ScanStoreState>(initialState);
  let currentProgress: ScanProgressState = { progress: null, hostScanProgress: null };
  scanProgress.subscribe((value) => {
    currentProgress = value;
  });
  let currentState = initialState;
  let favoriteHostSnapshots: FavoriteHostSnapshots = { ...initialFavoriteHostSnapshots };
  let latestScanTarget: string | null = null;
  let latestScanHostIps: string[] = [];
  let activeComparisonEnabled = false;
  let activeBaselineIps = new Set<string>();

  function rememberFavoriteHost(host: Host, favoriteIps: string[]) {
    if (!favoriteIps.includes(host.ip)) {
      return;
    }

    favoriteHostSnapshots = {
      ...favoriteHostSnapshots,
      [host.ip]: host
    };
    saveFavoriteHostSnapshots(favoriteHostSnapshots);
  }

  subscribe((state) => {
    currentState = state;
  });

  let listenersAttached = false;
  const unlisteners: UnlistenFn[] = [];

  async function attachListeners() {
    if (listenersAttached) {
      return;
    }

    unlisteners.push(
      await listen<Host>('host-found', (event) => {
        update((state) => {
          rememberFavoriteHost(event.payload, state.favoriteIps);
          const staleFavoriteIps = state.staleFavoriteIps.filter((ip) => ip !== event.payload.ip);
          const pendingIps = state.pendingIps.includes(event.payload.ip)
            ? state.pendingIps.filter((ip) => ip !== event.payload.ip)
            : state.pendingIps;
          // Found hosts arrive unfingerprinted; enrichment runs at the end of the
          // scan. Keep the previous fingerprint until then so rows don't flip to
          // "Not fingerprinted yet" and back.
          const previous = event.payload.fingerprint
            ? null
            : state.hosts.find((host) => host.ip === event.payload.ip);
          const found = previous?.fingerprint
            ? { ...event.payload, fingerprint: previous.fingerprint }
            : event.payload;
          const hosts = upsertHost(state.hosts, found);
          const shouldMarkNew = activeComparisonEnabled && !activeBaselineIps.has(event.payload.ip);
          const newHostIps = shouldMarkNew
            ? uniqueSortedIps([...state.newHostIps, event.payload.ip])
            : state.newHostIps;

          return {
            ...state,
            hosts: mergeStaleFavoritesIntoHosts(hosts, staleFavoriteIps, favoriteHostSnapshots),
            staleFavoriteIps,
            pendingIps,
            newHostIps
          };
        });
      })
    );

    unlisteners.push(
      await listen<ScanProgress>('scan-progress', (event) => {
        scanProgress.update((value) => ({ ...value, progress: event.payload }));

        // Only scan-complete and scan-error end a scan: the backend keeps
        // fingerprinting after the last progress event, even when cancelled.
        if (event.payload.running && !currentState.scanning) {
          update((state) => ({ ...state, scanning: true }));
        }
      })
    );

    unlisteners.push(
      await listen<ScanProgress>('host-scan-progress', (event) => {
        scanProgress.update((value) => ({ ...value, hostScanProgress: event.payload }));
      })
    );

    unlisteners.push(
      await listen<ScanResult>('scan-complete', (event) => {
        const completedTarget = scanTargetKey(event.payload.options.interface_name, event.payload.options.subnet);
        const wasCancelled = event.payload.cancelled;

        update((state) => {
          const scannedHosts = sortHosts(event.payload.hosts);
          const completedHostIps = uniqueSortedIps(scannedHosts.map((host) => host.ip));

          const newHostIps = activeComparisonEnabled
            ? completedHostIps.filter((ip) => !activeBaselineIps.has(ip))
            : [];

          for (const host of scannedHosts) {
            rememberFavoriteHost(host, state.favoriteIps);
          }

          const staleFavoriteIps = calculateStaleFavoriteIps(state.favoriteIps, scannedHosts);

          return {
            ...state,
            hosts: mergeStaleFavoritesIntoHosts(scannedHosts, staleFavoriteIps, favoriteHostSnapshots),
            staleFavoriteIps,
            newHostIps,
            pendingIps: [],
            scanning: false,
            stopping: false,
            lastScanAt: event.payload.completed_at,
            lastScanCancelled: wasCancelled,
            error: null
          };
        });

        scanProgress.update((value) => ({
          ...value,
          progress: value.progress
            ? { ...value.progress, running: false, current_ip: null }
            : {
                phase: 'fingerprint',
                scanned: event.payload.hosts.length,
                total: event.payload.hosts.length,
                found: event.payload.hosts.length,
                running: false,
                current_ip: null
              }
        }));

        if (!wasCancelled) {
          latestScanTarget = completedTarget;
          latestScanHostIps = uniqueSortedIps(event.payload.hosts.map((host) => host.ip));
        }
        activeComparisonEnabled = false;
        activeBaselineIps = new Set();

        scanEvents.emit({
          type: 'scan-complete',
          hostCount: event.payload.hosts.length,
          cancelled: wasCancelled
        });
      })
    );

    unlisteners.push(
      await listen<ScanErrorPayload>('scan-error', (event) => {
        activeComparisonEnabled = false;
        activeBaselineIps = new Set();
        update((state) => ({
          ...state,
          scanning: false,
          stopping: false,
          pendingIps: [],
          error: event.payload.message,
          newHostIps: []
        }));
        scanProgress.update((value) => ({
          ...value,
          progress: value.progress ? { ...value.progress, running: false, current_ip: null } : null
        }));
        scanEvents.emit({ type: 'scan-error', message: event.payload.message });
      })
    );

    listenersAttached = true;
  }

  return {
    subscribe,
    init: async () => {
      update((state) => ({ ...state, loading: true, error: null }));

      try {
        await attachListeners();

        const [interfaces, previous] = await Promise.all([
          TauriService.getNetworkInterfaces(),
          TauriService.getScanResults()
        ]);

        latestScanTarget = previous ? scanTargetKey(previous.options.interface_name, previous.options.subnet) : null;
        latestScanHostIps = previous ? uniqueSortedIps(previous.hosts.map((host) => host.ip)) : [];

        update((state) => {
          const knownHosts = previous ? sortHosts(previous.hosts) : [];
          for (const host of knownHosts) {
            rememberFavoriteHost(host, state.favoriteIps);
          }

          const staleFavoriteIps = calculateStaleFavoriteIps(state.favoriteIps, knownHosts);
          const selectedInterface = resolveSelectedInterfaceKey(interfaces, state.selectedInterface);
          saveSelectedInterfaceKey(selectedInterface);

          return {
            ...state,
            interfaces,
            selectedInterface,
            scanApproach: previous
              ? settingsToApproach(previous.options.port_profile, previous.options.discovery_mode)
              : state.scanApproach,
            hosts: mergeStaleFavoritesIntoHosts(knownHosts, staleFavoriteIps, favoriteHostSnapshots),
            staleFavoriteIps,
            newHostIps: [],
            lastScanAt: previous?.completed_at || state.lastScanAt,
            lastScanCancelled: previous?.completed_at ? previous.cancelled : state.lastScanCancelled,
            loading: false,
            error: null
          };
        });
      } catch (error) {
        const message = errorMessage(error, 'Failed to initialize scanner');
        update((state) => ({ ...state, loading: false, error: message }));
        scanEvents.emit({ type: 'init-failed', message });
      }
    },
    destroy: () => {
      while (unlisteners.length > 0) {
        const unlisten = unlisteners.pop();
        if (unlisten) {
          unlisten();
        }
      }
      listenersAttached = false;
    },
    setInterface: (selectedInterface: string) => {
      saveSelectedInterfaceKey(selectedInterface);
      update((state) => ({ ...state, selectedInterface }));
    },
    setScanApproach: (scanApproach: ScanApproach) => {
      update((state) => ({ ...state, scanApproach }));
    },
    setQuery: (query: string) => {
      update((state) => ({ ...state, query }));
    },
    setCustomName: (ip: string, nextName: string) => {
      update((state) => {
        const trimmed = nextName.trim();
        const customNames = { ...state.customNames };

        if (trimmed.length === 0) {
          delete customNames[ip];
        } else {
          customNames[ip] = trimmed;
        }

        saveCustomNames(customNames);

        return {
          ...state,
          customNames
        };
      });
    },
    toggleFavorite: (ip: string) => {
      update((state) => {
        const currentlyFavorite = state.favoriteIps.includes(ip);

        if (currentlyFavorite) {
          const favoriteIps = normalizeIpList(state.favoriteIps.filter((item) => item !== ip));
          const staleFavoriteIps = state.staleFavoriteIps.filter((item) => item !== ip);

          const snapshots = { ...favoriteHostSnapshots };
          delete snapshots[ip];
          favoriteHostSnapshots = snapshots;

          saveFavoriteIps(favoriteIps);
          saveFavoriteHostSnapshots(favoriteHostSnapshots);

          const hosts = state.staleFavoriteIps.includes(ip)
            ? state.hosts.filter((host) => host.ip !== ip)
            : state.hosts;

          return {
            ...state,
            favoriteIps,
            staleFavoriteIps,
            hosts: sortHosts(hosts)
          };
        }

        const favoriteIps = normalizeIpList([...state.favoriteIps, ip]);
        const staleFavoriteIps = state.staleFavoriteIps.includes(ip)
          ? state.staleFavoriteIps
          : state.hosts.some((host) => host.ip === ip)
            ? state.staleFavoriteIps
            : [...state.staleFavoriteIps, ip];

        const host = state.hosts.find((item) => item.ip === ip);
        if (host) {
          rememberFavoriteHost(host, favoriteIps);
        }

        saveFavoriteIps(favoriteIps);

        return {
          ...state,
          favoriteIps,
          staleFavoriteIps,
          hosts: mergeStaleFavoritesIntoHosts(state.hosts, staleFavoriteIps, favoriteHostSnapshots)
        };
      });
    },
    toggleHidden: (ip: string) => {
      update((state) => {
        const currentlyHidden = state.hiddenIps.includes(ip);

        if (currentlyHidden) {
          const hiddenIps = normalizeIpList(state.hiddenIps.filter((item) => item !== ip));
          saveHiddenIps(hiddenIps);

          return {
            ...state,
            hiddenIps
          };
        }

        const hiddenIps = normalizeIpList([...state.hiddenIps, ip]);
        saveHiddenIps(hiddenIps);

        return {
          ...state,
          hiddenIps,
          selectedHostIp: state.showHiddenEntries
            ? state.selectedHostIp
            : state.selectedHostIp === ip
              ? null
              : state.selectedHostIp
        };
      });
    },
    setShowHiddenEntries: (showHiddenEntries: boolean) => {
      update((state) => ({
        ...state,
        showHiddenEntries,
        selectedHostIp:
          !showHiddenEntries && state.selectedHostIp && state.hiddenIps.includes(state.selectedHostIp)
            ? null
            : state.selectedHostIp
      }));
    },
    setSelectedHost: (ip: string | null) => {
      update((state) => ({ ...state, selectedHostIp: ip }));
    },
    clearError: () => {
      update((state) => ({ ...state, error: null }));
    },
    startScan: async () => {
      const selectedInterface = findInterfaceByKey(currentState.interfaces, currentState.selectedInterface);

      if (!selectedInterface) {
        scanEvents.emit({ type: 'no-interface' });
        return;
      }

      const previousNewHostIps = currentState.newHostIps;
      const previousProgress = currentProgress.progress;
      const previousHostScanProgress = currentProgress.hostScanProgress;
      const maxHosts = selectedInterface.host_count > 0 ? Math.min(selectedInterface.host_count, MAX_SCAN_HOSTS) : null;

      activeComparisonEnabled = scanTargetMatches(latestScanTarget, selectedInterface.name, selectedInterface.subnet);
      activeBaselineIps = new Set(activeComparisonEnabled ? latestScanHostIps : []);

      // Keep the current rows and dim them until the scan confirms each one,
      // instead of emptying the table and refilling it row by row.
      update((next) => {
        const staleIps = new Set(next.staleFavoriteIps);

        return {
          ...next,
          scanning: true,
          stopping: false,
          error: null,
          pendingIps: next.hosts.map((host) => host.ip).filter((ip) => !staleIps.has(ip)),
          newHostIps: []
        };
      });
      scanProgress.set({
        hostScanProgress: null,
        progress: {
          phase: 'discovery',
          scanned: 0,
          total: 0,
          found: 0,
          running: true,
          current_ip: null
        }
      });

      try {
        const scanSettings = approachToSettings(currentState.scanApproach);

        await TauriService.startScan({
          interface_name: selectedInterface.name,
          subnet: selectedInterface.subnet,
          port_profile: scanSettings.portProfile,
          discovery_mode: scanSettings.discoveryMode,
          timeout_ms: scanSettings.timeoutMs,
          max_hosts: maxHosts
        });
      } catch (error) {
        activeComparisonEnabled = false;
        activeBaselineIps = new Set();
        const message = errorMessage(error, 'Failed to start scan');
        update((next) => ({
          ...next,
          scanning: false,
          error: message,
          pendingIps: [],
          newHostIps: previousNewHostIps
        }));
        scanProgress.set({ progress: previousProgress, hostScanProgress: previousHostScanProgress });
        scanEvents.emit({ type: 'start-failed', message });
      }
    },
    cancelScan: async () => {
      if (!currentState.scanning || currentState.stopping) {
        return;
      }

      // Stay in the scanning state until scan-complete arrives: the backend
      // still finishes the current phase and fingerprints what it found, and
      // starting another scan before then fails with "already running".
      update((state) => ({ ...state, stopping: true }));

      try {
        await TauriService.cancelScan();
      } catch (error) {
        update((state) => ({ ...state, stopping: false }));
        scanEvents.emit({ type: 'cancel-failed', message: errorMessage(error, 'Failed to cancel scan') });
      }
    },
    refreshHostPorts: async (ip: string, profile: PortProfile = 'deep') => {
      if (currentProgress.hostScanProgress?.running) {
        scanEvents.emit({ type: 'deep-scan-busy', ip });
        return;
      }

      scanProgress.update((value) => ({
        ...value,
        hostScanProgress: {
          phase: 'ports',
          scanned: 0,
          total: 0,
          found: 0,
          running: true,
          current_ip: ip
        }
      }));

      const finishHostScan = (found: number | null) => {
        scanProgress.update((value) => {
          if (!value.hostScanProgress || value.hostScanProgress.current_ip !== ip) {
            return value;
          }

          const finished =
            found === null
              ? { ...value.hostScanProgress, running: false }
              : { ...value.hostScanProgress, scanned: 1, total: 1, found, running: false };
          return { ...value, hostScanProgress: finished };
        });
      };

      try {
        const host = await TauriService.scanHostPorts(ip, profile);
        update((state) => {
          rememberFavoriteHost(host, state.favoriteIps);
          const staleFavoriteIps = state.staleFavoriteIps.filter((item) => item !== host.ip);

          return {
            ...state,
            staleFavoriteIps,
            hosts: mergeStaleFavoritesIntoHosts(
              upsertHost(state.hosts, host),
              staleFavoriteIps,
              favoriteHostSnapshots
            )
          };
        });
        finishHostScan(host.open_ports.length);
        scanEvents.emit({ type: 'deep-scan-done', ip, openPorts: host.open_ports.length });
      } catch (error) {
        finishHostScan(null);
        scanEvents.emit({
          type: 'deep-scan-failed',
          ip,
          message: errorMessage(error, 'Failed to scan host ports')
        });
      }
    }
  };
}

export const scanStore = createScanStore();
