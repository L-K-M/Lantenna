import { writable } from 'svelte/store';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { TauriService } from '$lib/tauri';
import type { Host, NetworkInterface, PortProfile, ScanErrorPayload, ScanProgress, ScanResult } from '$lib/types';
import { notifications } from './notifications';

interface ScanStoreState {
  interfaces: NetworkInterface[];
  selectedInterface: string | null;
  portProfile: PortProfile;
  hosts: Host[];
  progress: ScanProgress | null;
  scanning: boolean;
  loading: boolean;
  error: string | null;
  query: string;
  selectedHostIp: string | null;
  lastScanAt: string | null;
}

const initialState: ScanStoreState = {
  interfaces: [],
  selectedInterface: null,
  portProfile: 'quick',
  hosts: [],
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
        update((state) => ({ ...state, hosts: upsertHost(state.hosts, event.payload) }));
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
        update((state) => ({
          ...state,
          hosts: sortHosts(event.payload.hosts),
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
        }));
        notifications.add(`Scan complete: ${event.payload.hosts.length} hosts found.`, 'success');
      })
    );

    unlisteners.push(
      await listen<ScanErrorPayload>('scan-error', (event) => {
        update((state) => ({ ...state, scanning: false, error: event.payload.message }));
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

        update((state) => ({
          ...state,
          interfaces,
          selectedInterface: state.selectedInterface || interfaces[0]?.name || null,
          hosts: previous ? sortHosts(previous.hosts) : state.hosts,
          lastScanAt: previous?.completed_at || state.lastScanAt,
          loading: false,
          error: null
        }));
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
    setInterface: (name: string) => {
      update((state) => ({ ...state, selectedInterface: name }));
    },
    setProfile: (profile: PortProfile) => {
      update((state) => ({ ...state, portProfile: profile }));
    },
    setQuery: (query: string) => {
      update((state) => ({ ...state, query }));
    },
    setSelectedHost: (ip: string | null) => {
      update((state) => ({ ...state, selectedHostIp: ip }));
    },
    clearError: () => {
      update((state) => ({ ...state, error: null }));
    },
    startScan: async () => {
      if (!currentState.selectedInterface) {
        notifications.add('Choose a network interface first.', 'error');
        return;
      }

      update((next) => ({
        ...next,
        scanning: true,
        error: null,
        hosts: [],
        progress: {
          scanned: 0,
          total: 0,
          found: 0,
          running: true,
          current_ip: null
        }
      }));

      try {
        await TauriService.startScan({
          interface_name: currentState.selectedInterface,
          subnet: null,
          port_profile: currentState.portProfile,
          timeout_ms: 350,
          max_hosts: 512
        });
        notifications.add('Scan started.', 'info');
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to start scan';
        update((next) => ({ ...next, scanning: false, error: message }));
        notifications.add(message, 'error');
      }
    },
    cancelScan: async () => {
      try {
        await TauriService.cancelScan();
        update((state) => ({ ...state, scanning: false }));
        notifications.add('Scan cancelled.', 'info');
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to cancel scan';
        notifications.add(message, 'error');
      }
    },
    refreshHostPorts: async (ip: string, profile: PortProfile = 'deep') => {
      try {
        const host = await TauriService.scanHostPorts(ip, profile);
        update((state) => ({ ...state, hosts: upsertHost(state.hosts, host) }));
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to scan host ports';
        notifications.add(message, 'error');
      }
    }
  };
}

export const scanStore = createScanStore();
