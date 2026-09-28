// Owner: unit G. The reload that makes scanStore read the seed when the
// page's modules load before the mock (Chromium, scaffold notes 4.2):
// the doomed page must not write over the seed before the reload
// commits, the new load must seed the same data, and a store that still
// misses the seed must fail loudly.

import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import type { Host } from '$lib/types';

const SCENARIO = '?scenario=idle&platform=mac&speed=0';
const SEEDED_IFACE = 'en0|192.168.1.23';
const TV = '192.168.1.61';

/** What earlier scenarios left: the /16 selected (many), and the TV's
 * snapshot as a deep scan of it stored it (deep-scan). */
function leaveOtherScenarioData(): void {
  localStorage.setItem('lantenna.selectedInterface', 'en7|10.20.4.17');
  localStorage.setItem('lantenna.favoriteIps', JSON.stringify(['192.168.1.10', '192.168.1.31', TV]));
  localStorage.setItem(
    'lantenna.favoriteHosts',
    JSON.stringify({
      [TV]: { ip: TV, name: null, reachable: false, open_ports: [], last_seen: new Date().toISOString(), fingerprint: null }
    })
  );
}

/** One page load in the order the reload guards against (the layout's
 * load() before src/hooks.client.ts): the page's modules (scanStore)
 * first, then the mock. */
async function load() {
  vi.resetModules();
  const { scanStore } = await import('$lib/util/scanStore');
  const { installMockBackend, parseScenario } = await import('./mockBackend');
  installMockBackend(parseScenario(SCENARIO, 'mac'));
  // drive() compares the store with the seed after one dynamic import.
  await new Promise((resolve) => setTimeout(resolve, 20));
  return scanStore;
}

let reload: ReturnType<typeof vi.fn<() => void>>;

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  vi.spyOn(console, 'info').mockImplementation(() => {});
  reload = vi.fn<() => void>();
  vi.spyOn(window.location, 'reload').mockImplementation(reload);
});

afterEach(() => {
  vi.restoreAllMocks();
});

it('reloads once, and the doomed page cannot overwrite the seed', async () => {
  const errors = vi.spyOn(console, 'error');
  leaveOtherScenarioData();

  const doomed = await load();
  expect(reload).toHaveBeenCalledOnce();
  expect(localStorage.getItem('lantenna.selectedInterface')).toBe(SEEDED_IFACE);
  const seededSnapshots = localStorage.getItem('lantenna.favoriteHosts');

  // The page runs on until the reload commits and starts up: the halted
  // backend never answers, so init() writes nothing ...
  void doomed.init();
  await new Promise((resolve) => setTimeout(resolve, 50));
  expect(get(doomed).loading).toBe(true);
  expect(localStorage.getItem('lantenna.selectedInterface')).toBe(SEEDED_IFACE);

  // ... and whatever it writes anyway is undone as it goes.
  localStorage.setItem('lantenna.selectedInterface', 'en7|10.20.4.17');
  dispatchEvent(new Event('pagehide'));
  expect(localStorage.getItem('lantenna.selectedInterface')).toBe(SEEDED_IFACE);
  expect(localStorage.getItem('lantenna.favoriteHosts')).toBe(seededSnapshots);

  // The new load reads the seed, and its own seed is the same data.
  const store = await load();
  expect(reload).toHaveBeenCalledOnce();
  expect(localStorage.getItem('lantenna.favoriteHosts')).toBe(seededSnapshots);
  expect(get(store).selectedInterface).toBe(SEEDED_IFACE);
  const tv = get(store).hosts.find((host: Host) => host.ip === TV);
  expect(tv).toMatchObject({ reachable: true, fingerprint: { mac_address: '58:FD:B1:3C:77:0E' } });
  expect(errors).not.toHaveBeenCalled();
});

it('reports a store that still misses the seed after the reload', async () => {
  const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
  leaveOtherScenarioData();
  await load();
  expect(reload).toHaveBeenCalledOnce();

  // Something wrote over the seed before the new page read it.
  leaveOtherScenarioData();
  await load();

  expect(reload).toHaveBeenCalledOnce();
  expect(errors).toHaveBeenCalledOnce();
  expect(errors.mock.calls[0][0]).toContain('does not hold the seeded user data');
});

it('does not reload when scanStore read the seed', async () => {
  // The mock first, as in WebKit and in mockBoot.test.ts.
  vi.resetModules();
  const { installMockBackend, parseScenario } = await import('./mockBackend');
  installMockBackend(parseScenario(SCENARIO, 'mac'));
  await new Promise((resolve) => setTimeout(resolve, 20));

  expect(reload).not.toHaveBeenCalled();
  expect(sessionStorage.getItem('lantenna.mockReload')).toBeNull();
});
