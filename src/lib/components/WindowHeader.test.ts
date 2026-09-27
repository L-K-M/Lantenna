// Owner: unit D (spec 8.4). Spec: 2.3 (window header), 5.2, 5.6.
//
// The scan stores, the host model (unit B) and lastError are writables
// the tests set; the header's wording itself is headerText.test.ts's.
import { render } from '@testing-library/svelte';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Writable } from 'svelte/store';
import type { HostModel, HostRow } from '$lib/app/hostModel';
import type { NetworkInterface, ScanProgress } from '$lib/types';
import type { ScanProgressState, ScanStoreState } from '$lib/util/scanStore';
import { formatClock } from '$lib/util/format';

const fake = vi.hoisted(() => ({
  store: null as unknown as Writable<ScanStoreState>,
  progress: null as unknown as Writable<ScanProgressState>,
  model: null as unknown as Writable<HostModel>
}));

vi.mock('$lib/util/scanStore', async (importOriginal) => {
  const actual = await importOriginal<typeof import('$lib/util/scanStore')>();
  const { get, writable } = await import('svelte/store');
  fake.store = writable(get(actual.scanStore));
  fake.progress = writable<ScanProgressState>({ progress: null, hostScanProgress: null });
  return { ...actual, scanStore: { subscribe: fake.store.subscribe }, scanProgress: fake.progress };
});

vi.mock('$lib/app/hostModel', async () => {
  const { writable } = await import('svelte/store');
  fake.model = writable<HostModel>({
    rows: [],
    universe: 0,
    newCount: 0,
    hiddenCount: 0,
    selected: null,
    loading: false,
    loadingText: '',
    emptyText: ''
  });
  return { hostModel: fake.model };
});

vi.mock('$lib/app/feedback', async () => {
  const { readable } = await import('svelte/store');
  return { lastError: readable(null) };
});

import WindowHeader from './WindowHeader.svelte';
import { ui } from '$lib/app/ui';

const EN0: NetworkInterface = {
  name: 'en0',
  ip: '192.168.1.23',
  cidr: 24,
  subnet: '192.168.1.0/24',
  host_count: 254,
  is_default_route: true
};

function rows(n: number): HostRow[] {
  return Array.from({ length: n }, (_, i) => ({ ip: `192.168.1.${i + 1}` }) as HostRow);
}

function setStore(p: Partial<ScanStoreState>) {
  fake.store.update((s) => ({ ...s, ...p }));
}

function discovery(scanned: number, found: number): ScanProgress {
  return { phase: 'discovery', scanned, total: 254, found, running: true, current_ip: null };
}

const settle = () => new Promise((r) => setTimeout(r, 0));

function describedText(el: Element): string {
  const ids = el.getAttribute('aria-describedby')?.split(/\s+/) ?? [];
  return ids.map((id) => document.getElementById(id)?.textContent ?? '').join(' ');
}

beforeEach(() => {
  setStore({
    interfaces: [EN0],
    selectedInterface: 'en0|192.168.1.23',
    loading: false,
    scanning: false,
    stopping: false,
    error: null,
    hosts: [],
    lastScanAt: new Date(Date.now() - 60_000).toISOString(),
    lastScanCancelled: false
  });
  fake.progress.set({ progress: null, hostScanProgress: null });
  fake.model.update((m) => ({ ...m, rows: rows(24), universe: 24, newCount: 2, hiddenCount: 3 }));
  ui.setBalloons('hidden');
});

afterEach(() => {
  vi.useRealTimers();
});

function mount() {
  const { container } = render(WindowHeader);
  const q = <T extends HTMLElement>(sel: string) => container.querySelector<T>(sel);
  return {
    header: q('.lan-header')!,
    text: q('.lan-header-text')!,
    live: q('.lan-announce')!,
    bar: () => q('.lan-header-progress')
  };
}

it('is a Finder window header with stopped chasing arrows and a live region', () => {
  const h = mount();

  expect(h.header.classList.contains('osm-placard')).toBe(true);
  // Osmium's arrows, a direct child of the placard (its measured spot),
  // blank and hidden from screen readers while idle.
  const arrows = h.header.querySelector(':scope > .lan-arrows')!;
  expect(arrows.classList.contains('osm-arrows')).toBe(true);
  expect(arrows.getAttribute('aria-hidden')).toBe('true');
  expect(arrows.hasAttribute('data-frame')).toBe(false);
  expect(arrows.childElementCount).toBe(0);

  expect(h.text.textContent).toMatch(/^24 hosts, 2 new, 3 hidden\. Last scan today at /);
  // centerText placed it on a whole pixel.
  expect(h.text.style.textAlign).toBe('left');
  expect(h.text.style.textIndent).toMatch(/^\d+px$/);
  expect(h.bar()).toBeNull();

  expect(h.live.getAttribute('role')).toBe('status');
  expect(h.live.getAttribute('aria-live')).toBe('polite');
  expect(h.live.textContent).toBe(h.text.textContent);
  expect(h.header.querySelector('[title]')).toBeNull();
});

it('reads the last scan first, then follows the store', async () => {
  setStore({ loading: true });
  const h = mount();
  expect(h.text.textContent).toBe('Reading the last scan…');

  setStore({ loading: false, lastScanAt: null, hosts: [] });
  await settle();
  expect(h.text.textContent).toBe(
    'Click Scan to search 253 addresses on en0 (192.168.1.0/24). This computer is 192.168.1.23. For help, choose Show Balloons from the Help menu.'
  );

  ui.setBalloons('shown');
  await settle();
  expect(h.text.textContent).toBe(
    'Click Scan to search 253 addresses on en0 (192.168.1.0/24). This computer is 192.168.1.23.'
  );
});

it('shows the scan’s progress bar with its ARIA values', async () => {
  const h = mount();
  setStore({ scanning: true });
  fake.progress.set({ progress: discovery(112, 9), hostScanProgress: null });
  await settle();

  const bar = h.bar()!;
  expect(h.text.textContent).toBe('Looking for hosts: 112 of 254 addresses, 9 hosts found.');
  expect(h.text.classList.contains('lan-with-bar')).toBe(true);
  expect(bar.classList.contains('osm-progress')).toBe(true);
  expect(bar.querySelector('.osm-progress-track > .osm-progress-fill')).not.toBeNull();
  expect(bar.getAttribute('role')).toBe('progressbar');
  expect(bar.getAttribute('aria-valuemin')).toBe('0');
  expect(bar.getAttribute('aria-valuemax')).toBe('254');
  expect(bar.getAttribute('aria-valuenow')).toBe('112');
  expect(bar.getAttribute('aria-label')).toBe('Scan progress: Looking for hosts: 112 of 254 addresses, 9 hosts found.');
  expect(Number(bar.style.getPropertyValue('--osm-value'))).toBeCloseTo(112 / 254);
  expect(describedText(bar)).toBe('Progress bar\n\nShows how far the current phase of the scan has come.');

  // The fingerprint phase has no counts: the indeterminate bar (N2),
  // without ARIA values, and no fill.
  fake.progress.set({ progress: { ...discovery(0, 11), phase: 'fingerprint', total: 11 }, hostScanProgress: null });
  await settle();
  expect(h.text.textContent).toBe('Identifying 11 hosts…');
  const pole = h.bar()!;
  expect(pole.classList.contains('osm-indeterminate')).toBe(true);
  expect(pole.getAttribute('role')).toBe('progressbar');
  expect(pole.getAttribute('aria-label')).toBe('Scan progress: Identifying 11 hosts…');
  for (const name of ['aria-valuenow', 'aria-valuemin', 'aria-valuemax']) expect(pole.hasAttribute(name)).toBe(false);
  expect(pole.style.getPropertyValue('--osm-value')).toBe('');
  expect(h.text.classList.contains('lan-with-bar')).toBe(true);

  // Idle again: no bar.
  setStore({ scanning: false });
  fake.progress.set({ progress: null, hostScanProgress: null });
  await settle();
  expect(h.bar()).toBeNull();
  expect(h.text.classList.contains('lan-with-bar')).toBe(false);
});

it('turns the chasing arrows while busy and stops them when idle (5.2)', async () => {
  const h = mount();
  const arrows = h.header.querySelector<HTMLElement>('.lan-arrows')!;
  expect(arrows.hasAttribute('data-frame')).toBe(false);

  setStore({ scanning: true });
  fake.progress.set({ progress: discovery(112, 9), hostScanProgress: null });
  await settle();
  expect(arrows.getAttribute('data-frame')).toBe('0');
  expect(arrows.hasAttribute('aria-hidden')).toBe(false);
  expect(arrows.getAttribute('role')).toBe('img');

  setStore({ scanning: false });
  fake.progress.set({ progress: null, hostScanProgress: null });
  await settle();
  expect(arrows.hasAttribute('data-frame')).toBe(false);
  expect(arrows.getAttribute('aria-hidden')).toBe('true');
});

it('announces state changes, not counts', async () => {
  const h = mount();
  const said: string[] = [];
  const step = async (change: () => void) => {
    change();
    await settle();
    said.push(h.live.textContent ?? '');
  };

  await step(() => {
    setStore({ scanning: true });
    fake.progress.set({ progress: { ...discovery(0, 0), total: 0 }, hostScanProgress: null });
  });
  await step(() => fake.progress.set({ progress: discovery(10, 1), hostScanProgress: null }));
  await step(() => fake.progress.set({ progress: discovery(200, 7), hostScanProgress: null }));
  await step(() => fake.progress.set({ progress: { ...discovery(3, 7), phase: 'ports', total: 7 }, hostScanProgress: null }));
  await step(() => fake.progress.set({ progress: { ...discovery(5, 7), phase: 'ports', total: 7 }, hostScanProgress: null }));
  await step(() => {
    setStore({ scanning: false });
    fake.progress.set({ progress: null, hostScanProgress: null });
  });
  // Filtering while idle changes the text, not the announcement.
  await step(() => fake.model.update((m) => ({ ...m, rows: rows(4) })));

  const idle = expect.stringMatching(/^24 hosts, 2 new, 3 hidden\. Last scan today at /);
  expect(said).toEqual([
    'Starting scan…',
    'Looking for hosts…',
    'Looking for hosts…',
    'Probing ports…',
    'Probing ports…',
    idle,
    idle
  ]);
  expect(said[6]).toBe(said[5]);
  expect(h.text.textContent).toMatch(/^Showing 4 of 24 hosts\./);
});

it('carries the header balloon', () => {
  const h = mount();

  expect(describedText(h.header)).toBe('Window header\n\nShows how many hosts the list holds and what the scan is doing.');
});

it('moves "today" to "yesterday" at midnight without a store change', async () => {
  const lastScan = new Date(2026, 8, 27, 23, 0);
  vi.useFakeTimers({ now: new Date(2026, 8, 27, 23, 59, 30), toFake: ['Date', 'setInterval', 'clearInterval'] });
  setStore({ lastScanAt: lastScan.toISOString() });
  const h = mount();
  expect(h.text.textContent).toBe(`24 hosts, 2 new, 3 hidden. Last scan today at ${formatClock(lastScan)}.`);

  vi.advanceTimersByTime(60_000);
  await vi.waitFor(() =>
    expect(h.text.textContent).toBe(`24 hosts, 2 new, 3 hidden. Last scan yesterday at ${formatClock(lastScan)}.`)
  );
});

it('dates a scan by the clock at the store change, not the last tick', async () => {
  vi.useFakeTimers({ now: new Date(2026, 8, 27, 23, 59, 50), toFake: ['Date', 'setInterval', 'clearInterval'] });
  const h = mount();

  // Past midnight, before the next tick.
  const lastScan = new Date(2026, 8, 28, 0, 0, 30);
  vi.setSystemTime(new Date(2026, 8, 28, 0, 0, 40));
  setStore({ lastScanAt: lastScan.toISOString() });

  await vi.waitFor(() =>
    expect(h.text.textContent).toBe(`24 hosts, 2 new, 3 hidden. Last scan today at ${formatClock(lastScan)}.`)
  );
});

it('turns the arrows from the mount on while the last scan is read', () => {
  setStore({ loading: true });
  const h = mount();
  expect(h.header.querySelector('.lan-arrows')!.getAttribute('data-frame')).toBe('0');
});
