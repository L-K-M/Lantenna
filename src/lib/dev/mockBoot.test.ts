// Owner: unit G. Spec 8.4 row G: "the mock boots the app in `vite dev
// --mode mock` without errors". Here the real page boots on the mock in
// happy-dom (the Chromium check is the scratch harness): the mock seeds
// the user data before scanStore loads, answers everything the page
// invokes at launch, and drives a rescan to the "rescanned" picture.

import { afterAll, expect, it, vi } from 'vitest';
import { cleanup, render } from '@testing-library/svelte';
import { get } from 'svelte/store';
import { ui } from '$lib/app/ui';
import { installMockBackend, parseScenario } from './mockBackend';

afterAll(() => cleanup());

it('boots the page and drives a rescan without console errors', async () => {
  const errors = vi.spyOn(console, 'error');
  vi.spyOn(console, 'info').mockImplementation(() => {});

  // As +layout.ts does: the mock first, then (in parallel) the page.
  const mock = installMockBackend(parseScenario('?scenario=rescanned&view=icons&pane=0&balloons=1', 'linux'));
  expect(get(ui)).toMatchObject({ viewMode: 'icons', infoPaneShown: false, balloons: 'shown' });

  const { default: Page } = await import('../../routes/+page.svelte');
  const { container } = render(Page);
  await mock.whenReady();

  expect(container.querySelector('.osm-page-window.osm-window .osm-title')?.textContent).toBe('Lantenna');
  // The icon view and the hidden pane came from the query parameters.
  expect(container.querySelector('.lan-view .lan-icons')).not.toBeNull();
  expect(container.querySelector('.lan-pane')?.hasAttribute('hidden')).toBe(true);
  expect(mock.ready).toBe(true);

  // Startup reads what it needs from the mock (the calls the scaffold
  // makes; units A to F add theirs) ...
  const commands = new Set(mock.calls().map((call) => call.cmd));
  for (const cmd of ['is_window_active', 'get_network_interfaces', 'get_scan_results', 'start_scan']) {
    expect(commands).toContain(cmd);
  }

  // ... and the rescan leaves the picture the fixtures promise: two new
  // hosts, the sleeping favorite stale, the departed guest gone.
  const { store } = mock.state() as { store: import('$lib/util/scanStore').ScanStoreState; progress: unknown };
  expect(store.loading).toBe(false);
  expect(store.scanning).toBe(false);
  expect(store.selectedInterface).toBe('wlp2s0|192.168.1.23');
  expect(store.newHostIps).toEqual(['192.168.1.80', '192.168.1.81']);
  expect(store.staleFavoriteIps).toEqual(['192.168.1.61']);
  expect(store.hiddenIps).toEqual(['192.168.1.101', '192.168.1.120']);
  expect(store.hosts.map((host) => host.ip)).not.toContain('192.168.1.160');
  expect(store.hosts.find((host) => host.ip === '192.168.1.61')?.fingerprint?.mac_address).toBe('58:FD:B1:3C:77:0E');
  expect(store.lastScanCancelled).toBe(false);

  expect(errors).not.toHaveBeenCalled();
});
