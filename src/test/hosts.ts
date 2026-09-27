// Owner: unit B (spec 8.4, 8.5). Test support: hosts, fingerprints and
// store states for the host model, sort and view tests.

import type { ScanStoreState } from '$lib/util/scanStore';
import type { DeviceFingerprint, Host, PortInfo } from '$lib/types';

export function makeFingerprint(over: Partial<DeviceFingerprint> = {}): DeviceFingerprint {
  return {
    mac_address: null,
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
    last_updated: '2026-09-27T12:00:00Z',
    ...over
  };
}

export function makePorts(...ports: (number | [number, string])[]): PortInfo[] {
  return ports.map((p) => {
    const [port, service] = typeof p === 'number' ? [p, null] : p;
    return { port, state: 'open', service, banner: null };
  });
}

export function makeHost(ip: string, over: Partial<Host> = {}): Host {
  return {
    ip,
    name: null,
    reachable: true,
    open_ports: [],
    last_seen: '2026-09-27T12:00:00Z',
    fingerprint: null,
    ...over
  };
}

/** A settled store (init done, idle) holding `over`. */
export function makeState(over: Partial<ScanStoreState> = {}): ScanStoreState {
  return {
    interfaces: [],
    selectedInterface: null,
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
    lastScanCancelled: false,
    ...over
  };
}
