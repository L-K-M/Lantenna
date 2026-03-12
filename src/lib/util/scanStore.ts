import { writable } from 'svelte/store';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { TauriService } from '$lib/tauri';
import type {
  DiscoveryMode,
  Host,
  NetworkInterface,
  PortProfile,
  ScanErrorPayload,
  ScanProgress,
  ScanResult
} from '$lib/types';
import { notifications } from './notifications';

interface ScanStoreState {
  interfaces: NetworkInterface[];
  selectedInterface: string | null;
  portProfile: PortProfile;
  discoveryMode: DiscoveryMode;
  hosts: Host[];
  newHostIps: string[];
  customNames: Record<string, string>;
  favoriteIps: string[];
  staleFavoriteIps: string[];
  progress: ScanProgress | null;
  scanning: boolean;
  loading: boolean;
  error: string | null;
  query: string;
  selectedHostIp: string | null;
  lastScanAt: string | null;
}

type FavoriteHostSnapshots = Record<string, Host>;

const FAVORITE_IPS_STORAGE_KEY = 'lantenna.favoriteIps';
const FAVORITE_HOSTS_STORAGE_KEY = 'lantenna.favoriteHosts';
const CUSTOM_NAMES_STORAGE_KEY = 'lantenna.customNames';
const SELECTED_INTERFACE_STORAGE_KEY = 'lantenna.selectedInterface';
const MAX_SCAN_HOSTS = 4096;

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

function saveFavoriteIps(favoriteIps: string[]) {
  if (!canUseStorage()) {
    return;
  }

  window.localStorage.setItem(FAVORITE_IPS_STORAGE_KEY, JSON.stringify(favoriteIps));
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

function normalizeFavoriteIps(favoriteIps: string[]): string[] {
  const unique = Array.from(new Set(favoriteIps));
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

function interfaceKey(item: NetworkInterface): string {
  return `${item.name}|${item.ip}`;
}

function splitInterfaceKey(value: string): { name: string; ip: string } {
  const [name, ...rest] = value.split('|');
  return {
    name,
    ip: rest.join('|')
  };
}

function findInterfaceByKey(interfaces: NetworkInterface[], selectedInterface: string | null): NetworkInterface | null {
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

function pickDefaultInterface(interfaces: NetworkInterface[]): NetworkInterface | null {
  const preferred = interfaces.filter(
    (item) => isPrivateAddress(item.ip) && !isLinkLocalAddress(item.ip) && item.host_count > 0
  );

  if (preferred.length > 0) {
    return [...preferred].sort((a, b) => {
      const aDistance = Math.abs(a.host_count - 254);
      const bDistance = Math.abs(b.host_count - 254);
      return aDistance - bDistance || a.name.localeCompare(b.name) || a.ip.localeCompare(b.ip);
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

const initialFavoriteIps = normalizeFavoriteIps(loadFavoriteIps());
const initialFavoriteHostSnapshots = loadFavoriteHostSnapshots();
const initialStaleFavoriteIps = [...initialFavoriteIps];
const initialCustomNames = loadCustomNames();
const initialSelectedInterface = loadSelectedInterfaceKey();

const initialState: ScanStoreState = {
  interfaces: [],
  selectedInterface: initialSelectedInterface,
  portProfile: 'quick',
  discoveryMode: 'hybrid',
  hosts: mergeStaleFavoritesIntoHosts([], initialStaleFavoriteIps, initialFavoriteHostSnapshots),
  newHostIps: [],
  customNames: initialCustomNames,
  favoriteIps: initialFavoriteIps,
  staleFavoriteIps: initialStaleFavoriteIps,
  progress: null,
  scanning: false,
  loading: false,
  error: null,
  query: '',
  selectedHostIp: null,
  lastScanAt: null
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

function upsertHost(hosts: Host[], host: Host): Host[] {
  const index = hosts.findIndex((item) => item.ip === host.ip);
  if (index >= 0) {
    const next = [...hosts];
    next[index] = host;
    return sortHosts(next);
  }

  return sortHosts([...hosts, host]);
}

function createScanStore() {
  const { subscribe, update } = writable<ScanStoreState>(initialState);
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
          const hosts = upsertHost(state.hosts, event.payload);
          const shouldMarkNew = activeComparisonEnabled && !activeBaselineIps.has(event.payload.ip);
          const newHostIps = shouldMarkNew
            ? uniqueSortedIps([...state.newHostIps, event.payload.ip])
            : state.newHostIps;

          return {
            ...state,
            hosts: mergeStaleFavoritesIntoHosts(hosts, staleFavoriteIps, favoriteHostSnapshots),
            staleFavoriteIps,
            newHostIps
          };
        });
      })
    );

    unlisteners.push(
      await listen<ScanProgress>('scan-progress', (event) => {
        update((state) => ({
          ...state,
          progress: event.payload,
          scanning: event.payload.running
        }));
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
            scanning: false,
            progress: state.progress
              ? { ...state.progress, running: false, current_ip: null }
              : {
                  scanned: event.payload.hosts.length,
                  total: event.payload.hosts.length,
                  found: event.payload.hosts.length,
                  running: false,
                  current_ip: null
                },
            lastScanAt: event.payload.completed_at,
            error: null
          };
        });

        if (!wasCancelled) {
          latestScanTarget = completedTarget;
          latestScanHostIps = uniqueSortedIps(event.payload.hosts.map((host) => host.ip));
        }
        activeComparisonEnabled = false;
        activeBaselineIps = new Set();

        notifications.add(
          wasCancelled
            ? `Scan cancelled: ${event.payload.hosts.length} hosts discovered before stop.`
            : `Scan complete: ${event.payload.hosts.length} hosts found.`,
          wasCancelled ? 'info' : 'success'
        );
      })
    );

    unlisteners.push(
      await listen<ScanErrorPayload>('scan-error', (event) => {
        activeComparisonEnabled = false;
        activeBaselineIps = new Set();
        update((state) => ({ ...state, scanning: false, error: event.payload.message, newHostIps: [] }));
        notifications.add(event.payload.message, 'error');
      })
    );

    listenersAttached = true;
  }

  return {
    subscribe,
    init: async () => {
      await attachListeners();

      update((state) => ({ ...state, loading: true, error: null }));

      try {
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
            discoveryMode: previous?.options.discovery_mode || state.discoveryMode,
            hosts: mergeStaleFavoritesIntoHosts(knownHosts, staleFavoriteIps, favoriteHostSnapshots),
            staleFavoriteIps,
            newHostIps: [],
            lastScanAt: previous?.completed_at || state.lastScanAt,
            loading: false,
            error: null
          };
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to initialize scanner';
        update((state) => ({ ...state, loading: false, error: message }));
        notifications.add(message, 'error');
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
    setProfile: (profile: PortProfile) => {
      update((state) => ({ ...state, portProfile: profile }));
    },
    setDiscoveryMode: (mode: DiscoveryMode) => {
      update((state) => ({ ...state, discoveryMode: mode }));
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
          const favoriteIps = normalizeFavoriteIps(state.favoriteIps.filter((item) => item !== ip));
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

        const favoriteIps = normalizeFavoriteIps([...state.favoriteIps, ip]);
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
    setSelectedHost: (ip: string | null) => {
      update((state) => ({ ...state, selectedHostIp: ip }));
    },
    clearError: () => {
      update((state) => ({ ...state, error: null }));
    },
    startScan: async () => {
      const selectedInterface = findInterfaceByKey(currentState.interfaces, currentState.selectedInterface);

      if (!selectedInterface) {
        notifications.add('Choose a network interface first.', 'error');
        return;
      }

      const previousHosts = currentState.hosts;
      const previousStaleFavoriteIps = currentState.staleFavoriteIps;
      const previousNewHostIps = currentState.newHostIps;
      const previousProgress = currentState.progress;
      const maxHosts = selectedInterface.host_count > 0 ? Math.min(selectedInterface.host_count, MAX_SCAN_HOSTS) : null;

      if (selectedInterface.host_count > MAX_SCAN_HOSTS) {
        notifications.add(
          `Large subnet detected (${selectedInterface.host_count} hosts). Scanning first ${MAX_SCAN_HOSTS} hosts.`,
          'info'
        );
      }

      activeComparisonEnabled = scanTargetMatches(latestScanTarget, selectedInterface.name, selectedInterface.subnet);
      activeBaselineIps = new Set(activeComparisonEnabled ? latestScanHostIps : []);

      update((next) => {
        const staleFavoriteIps = [...next.favoriteIps];

        return {
          ...next,
          scanning: true,
          error: null,
          hosts: mergeStaleFavoritesIntoHosts([], staleFavoriteIps, favoriteHostSnapshots),
          staleFavoriteIps,
          newHostIps: [],
          progress: {
            scanned: 0,
            total: 0,
            found: 0,
            running: true,
            current_ip: null
          }
        };
      });

      try {
        const timeoutByProfile: Record<PortProfile, number> = {
          quick: 350,
          standard: 450,
          deep: 600
        };

        await TauriService.startScan({
          interface_name: selectedInterface.name,
          subnet: selectedInterface.subnet,
          port_profile: currentState.portProfile,
          discovery_mode: currentState.discoveryMode,
          timeout_ms: timeoutByProfile[currentState.portProfile],
          max_hosts: maxHosts
        });
        notifications.add('Scan started.', 'info');
      } catch (error) {
        activeComparisonEnabled = false;
        activeBaselineIps = new Set();
        const message = error instanceof Error ? error.message : 'Failed to start scan';
        update((next) => ({
          ...next,
          scanning: false,
          error: message,
          hosts: previousHosts,
          staleFavoriteIps: previousStaleFavoriteIps,
          newHostIps: previousNewHostIps,
          progress: previousProgress
        }));
        notifications.add(message, 'error');
      }
    },
    cancelScan: async () => {
      try {
        await TauriService.cancelScan();
        update((state) => ({ ...state, scanning: false }));
        notifications.add('Stopping scan...', 'info');
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to cancel scan';
        notifications.add(message, 'error');
      }
    },
    refreshHostPorts: async (ip: string, profile: PortProfile = 'deep') => {
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
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to scan host ports';
        notifications.add(message, 'error');
      }
    }
  };
}

export const scanStore = createScanStore();
