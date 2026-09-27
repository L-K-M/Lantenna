// Owner: scaffold (spec 8.3); unit D extends it (8.4: the store emits the
// right events; 3.5: its storage goes through storage.ts).
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import type { Host, NetworkInterface, ScanResult } from '$lib/types';
import type { ScanEvent } from './scanEvents';
import { refuseStorage } from './storage.fixture';

type Handler = (event: { payload: unknown }) => void;

const native = vi.hoisted(() => {
  const handlers = new Map<string, (event: { payload: unknown }) => void>();
  return {
    handlers,
    listen: vi.fn(async (event: string, handler: (event: { payload: unknown }) => void) => {
      handlers.set(event, handler);
      return () => {};
    }),
    invoke: vi.fn()
  };
});

vi.mock('@tauri-apps/api/event', () => ({ listen: native.listen }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: native.invoke }));

const EN0: NetworkInterface = {
  name: 'en0',
  ip: '192.168.1.23',
  cidr: 24,
  subnet: '192.168.1.0/24',
  host_count: 254,
  is_default_route: true
};

function host(ip: string): Host {
  return { ip, name: null, reachable: true, open_ports: [], last_seen: '', fingerprint: null };
}

function result(over: Partial<ScanResult> = {}): ScanResult {
  return {
    started_at: '2026-09-27T13:00:00Z',
    completed_at: '2026-09-27T13:42:00Z',
    cancelled: false,
    hosts: [host('192.168.1.1'), host('192.168.1.31')],
    options: {
      interface_name: 'en0',
      subnet: '192.168.1.0/24',
      port_profile: 'standard',
      discovery_mode: 'hybrid',
      timeout_ms: 450,
      max_hosts: 254
    },
    ...over
  };
}

/** Backend answers by command; a function answer is called (and may throw). */
let answers: Record<string, unknown> = {};

/** A store as the page gets it at launch, with its own scanEvents. */
async function freshStore() {
  vi.resetModules();
  const { scanStore, scanProgress } = await import('./scanStore');
  const { scanEvents } = await import('./scanEvents');
  const events: ScanEvent[] = [];
  scanEvents.subscribe((e) => events.push(e));
  return { scanStore, scanProgress, events };
}

function emit(event: string, payload: unknown) {
  (native.handlers.get(event) as Handler)({ payload });
}

let restoreStorage: (() => void) | null = null;

beforeEach(() => {
  localStorage.clear();
  native.listen.mockClear();
  native.handlers.clear();
  answers = { get_network_interfaces: [], get_scan_results: null };
  native.invoke.mockReset();
  native.invoke.mockImplementation(async (command: string) => {
    const answer = answers[command];
    return typeof answer === 'function' ? (answer as () => unknown)() : (answer ?? null);
  });
});

afterEach(() => {
  restoreStorage?.();
  restoreStorage = null;
  vi.restoreAllMocks();
});

it('reads as loading from launch until init settles', async () => {
  const { scanStore } = await freshStore();
  expect(get(scanStore)).toMatchObject({ loading: true, interfaces: [], error: null });

  const init = scanStore.init();
  expect(get(scanStore).loading).toBe(true);
  await init;

  expect(get(scanStore)).toMatchObject({ loading: false, error: null });
  expect(native.listen).toHaveBeenCalledTimes(5);
  scanStore.destroy();
});

it('reports a listener that fails to attach as an init failure', async () => {
  native.listen.mockRejectedValueOnce(new Error('event plugin unavailable'));
  const { scanStore, events } = await freshStore();

  await expect(scanStore.init()).resolves.toBeUndefined();

  expect(get(scanStore)).toMatchObject({ loading: false, error: 'event plugin unavailable' });
  expect(events).toEqual([{ type: 'init-failed', message: 'event plugin unavailable' }]);
  scanStore.destroy();
});

it('reports an init failure with the fallback message', async () => {
  // Tauri rejects with the command's error value; here, not a string.
  answers.get_network_interfaces = () => {
    throw {};
  };
  const { scanStore, events } = await freshStore();

  await scanStore.init();

  expect(events).toEqual([{ type: 'init-failed', message: 'Failed to initialize scanner' }]);
  expect(get(scanStore).error).toBe('Failed to initialize scanner');
  scanStore.destroy();
});

it('reads the last scan, stopped or not, at init', async () => {
  answers = { get_network_interfaces: [EN0], get_scan_results: result({ cancelled: true }) };
  const { scanStore, events } = await freshStore();

  await scanStore.init();

  expect(get(scanStore)).toMatchObject({
    lastScanAt: '2026-09-27T13:42:00Z',
    lastScanCancelled: true,
    selectedInterface: 'en0|192.168.1.23'
  });
  expect(events).toEqual([]);
  expect(localStorage.getItem('lantenna.selectedInterface')).toBe('en0|192.168.1.23');
  scanStore.destroy();
});

it('emits scan-complete with the host count and whether it was stopped', async () => {
  answers = { get_network_interfaces: [EN0], get_scan_results: null, start_scan: null };
  const { scanStore, events } = await freshStore();
  await scanStore.init();
  await scanStore.startScan();

  emit('scan-complete', result({ cancelled: true, hosts: [host('192.168.1.1')] }));

  expect(events).toEqual([{ type: 'scan-complete', hostCount: 1, cancelled: true }]);
  expect(get(scanStore)).toMatchObject({ scanning: false, lastScanCancelled: true, error: null });

  emit('scan-complete', result());
  expect(events.at(-1)).toEqual({ type: 'scan-complete', hostCount: 2, cancelled: false });
  expect(get(scanStore).lastScanCancelled).toBe(false);
  scanStore.destroy();
});

it('emits scan-error with the backend message', async () => {
  answers = { get_network_interfaces: [EN0], get_scan_results: null, start_scan: null };
  const { scanStore, events } = await freshStore();
  await scanStore.init();
  await scanStore.startScan();

  emit('scan-error', { message: "Interface 'en0' not found" });

  expect(events).toEqual([{ type: 'scan-error', message: "Interface 'en0' not found" }]);
  expect(get(scanStore)).toMatchObject({ scanning: false, error: "Interface 'en0' not found" });
  scanStore.destroy();
});

it('emits no-interface when there is nothing to scan', async () => {
  const { scanStore, events } = await freshStore();
  await scanStore.init();

  await scanStore.startScan();

  expect(events).toEqual([{ type: 'no-interface' }]);
  expect(native.invoke).not.toHaveBeenCalledWith('start_scan', expect.anything());
  scanStore.destroy();
});

it('emits start-failed and rolls back when the scan can’t start', async () => {
  answers = {
    get_network_interfaces: [EN0],
    get_scan_results: null,
    start_scan: () => {
      throw 'A scan is already running';
    }
  };
  const { scanStore, events } = await freshStore();
  await scanStore.init();

  await scanStore.startScan();

  expect(events).toEqual([{ type: 'start-failed', message: 'A scan is already running' }]);
  expect(get(scanStore)).toMatchObject({ scanning: false, error: 'A scan is already running', pendingIps: [] });
  scanStore.destroy();
});

it('emits cancel-failed and keeps scanning when the stop is refused', async () => {
  answers = {
    get_network_interfaces: [EN0],
    get_scan_results: null,
    start_scan: null,
    cancel_scan: () => {
      throw {};
    }
  };
  const { scanStore, events } = await freshStore();
  await scanStore.init();
  await scanStore.startScan();

  await scanStore.cancelScan();

  expect(events).toEqual([{ type: 'cancel-failed', message: 'Failed to cancel scan' }]);
  expect(get(scanStore)).toMatchObject({ scanning: true, stopping: false });
  scanStore.destroy();
});

it('emits the deep scan’s outcome', async () => {
  const scanned: Host = { ...host('192.168.1.31'), open_ports: [{ port: 22, state: 'open', service: 'ssh', banner: null }] };
  answers = { get_network_interfaces: [EN0], get_scan_results: null, scan_host_ports: scanned };
  const { scanStore, scanProgress, events } = await freshStore();
  await scanStore.init();

  await scanStore.refreshHostPorts('192.168.1.31');
  expect(events).toEqual([{ type: 'deep-scan-done', ip: '192.168.1.31', openPorts: 1 }]);
  expect(get(scanProgress).hostScanProgress).toMatchObject({ running: false, found: 1 });

  answers.scan_host_ports = () => {
    throw "Invalid IPv4 address '192.168.1.300'";
  };
  await scanStore.refreshHostPorts('192.168.1.300');
  expect(events.at(-1)).toEqual({
    type: 'deep-scan-failed',
    ip: '192.168.1.300',
    message: "Invalid IPv4 address '192.168.1.300'"
  });

  // One at a time: a second request while one runs is refused.
  let finish!: (h: Host) => void;
  answers.scan_host_ports = () => new Promise<Host>((r) => (finish = r));
  const running = scanStore.refreshHostPorts('192.168.1.31');
  await scanStore.refreshHostPorts('192.168.1.1');
  expect(events.at(-1)).toEqual({ type: 'deep-scan-busy', ip: '192.168.1.1' });
  finish(scanned);
  await running;
  scanStore.destroy();
});

it('reads its saved state through storage.ts, garbage as defaults', async () => {
  localStorage.setItem('lantenna.favoriteIps', '["192.168.1.9", 7, "192.168.1.2"]');
  localStorage.setItem('lantenna.hiddenIps', '{not json');
  localStorage.setItem('lantenna.customNames', '{"192.168.1.2": "NAS", "192.168.1.3": 5}');
  localStorage.setItem('lantenna.favoriteHosts', '"a string"');
  localStorage.setItem('lantenna.selectedInterface', 'en0');
  const { scanStore } = await freshStore();

  expect(get(scanStore)).toMatchObject({
    favoriteIps: ['192.168.1.2', '192.168.1.9'],
    hiddenIps: [],
    customNames: { '192.168.1.2': 'NAS' },
    selectedInterface: 'en0',
    staleFavoriteIps: ['192.168.1.2', '192.168.1.9']
  });
  // Favorites without snapshots start as blank stale rows.
  expect(get(scanStore).hosts.map((h) => h.ip)).toEqual(['192.168.1.2', '192.168.1.9']);
});

it('keeps working when storage is refused (spec 3.5)', async () => {
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
  restoreStorage = refuseStorage({
    getItem: new DOMException('denied', 'SecurityError'),
    setItem: new DOMException('full', 'QuotaExceededError'),
    removeItem: new DOMException('full', 'QuotaExceededError')
  });
  answers = { get_network_interfaces: [EN0], get_scan_results: result() };
  const { scanStore } = await freshStore();
  expect(get(scanStore).favoriteIps).toEqual([]);
  await scanStore.init();

  expect(() => scanStore.toggleFavorite('192.168.1.31')).not.toThrow();
  expect(() => scanStore.toggleHidden('192.168.1.1')).not.toThrow();
  expect(() => scanStore.setCustomName('192.168.1.31', 'Printer')).not.toThrow();
  expect(() => scanStore.setInterface('en0|192.168.1.23')).not.toThrow();

  expect(get(scanStore)).toMatchObject({
    favoriteIps: ['192.168.1.31'],
    hiddenIps: ['192.168.1.1'],
    customNames: { '192.168.1.31': 'Printer' }
  });
  expect(warn).toHaveBeenCalledWith('Lantenna couldn’t save lantenna.favoriteIps:', expect.any(DOMException));
  scanStore.destroy();
});

it('saves its state under the unchanged keys and formats', async () => {
  answers = { get_network_interfaces: [EN0], get_scan_results: result() };
  const { scanStore } = await freshStore();
  await scanStore.init();

  scanStore.toggleFavorite('192.168.1.31');
  scanStore.toggleHidden('192.168.1.1');
  scanStore.setCustomName('192.168.1.31', ' Printer ');

  expect(JSON.parse(localStorage.getItem('lantenna.favoriteIps')!)).toEqual(['192.168.1.31']);
  expect(Object.keys(JSON.parse(localStorage.getItem('lantenna.favoriteHosts')!))).toEqual(['192.168.1.31']);
  expect(JSON.parse(localStorage.getItem('lantenna.hiddenIps')!)).toEqual(['192.168.1.1']);
  expect(JSON.parse(localStorage.getItem('lantenna.customNames')!)).toEqual({ '192.168.1.31': 'Printer' });

  scanStore.setInterface('');
  expect(localStorage.getItem('lantenna.selectedInterface')).toBeNull();
  scanStore.destroy();
});
