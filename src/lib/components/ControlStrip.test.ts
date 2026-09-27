// Owner: unit D (spec 8.4). Spec: 2.3 (strip), 2.9, 3.1 (1.5 to 1.9),
// 3.2 (Find keys), 4.5 (balloons).
//
// The command model (unit E) and the host model (unit B) are replaced by
// fakes that follow table 4.1's rules for the strip's commands; the scan
// store by a writable the tests set directly.
import { fireEvent, render } from '@testing-library/svelte';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { get, type Writable } from 'svelte/store';
import type { CommandContext, CommandRef } from '$lib/app/commands';
import type { HostModel, HostRow } from '$lib/app/hostModel';
import type { HostViewApi } from '$lib/app/views';
import type { NetworkInterface, ScanApproach } from '$lib/types';
import type { ScanStoreState } from '$lib/util/scanStore';

const fake = vi.hoisted(() => ({
  store: null as unknown as Writable<ScanStoreState>,
  model: null as unknown as Writable<HostModel>,
  modal: null as unknown as Writable<boolean>,
  /** Commands the fake run() refuses. */
  refuse: new Set<string>(),
  run: vi.fn(),
  describe: vi.fn()
}));

vi.mock('$lib/util/scanStore', async (importOriginal) => {
  const actual = await importOriginal<typeof import('$lib/util/scanStore')>();
  const { writable } = await import('svelte/store');
  const store = writable<ScanStoreState>(get(actual.scanStore));
  fake.store = store;
  const patch = (p: Partial<ScanStoreState>) => store.update((s) => ({ ...s, ...p }));
  return {
    ...actual,
    scanStore: {
      subscribe: store.subscribe,
      setQuery: vi.fn((query: string) => patch({ query })),
      setSelectedHost: vi.fn((selectedHostIp: string | null) => patch({ selectedHostIp })),
      setInterface: vi.fn((selectedInterface: string) => patch({ selectedInterface })),
      setScanApproach: vi.fn((scanApproach: ScanApproach) => patch({ scanApproach })),
      setShowHiddenEntries: vi.fn((showHiddenEntries: boolean) => patch({ showHiddenEntries }))
    }
  };
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

vi.mock('$lib/app/commands', async () => {
  const { derived, writable } = await import('svelte/store');
  const { scanStore } = await import('$lib/util/scanStore');
  fake.modal = writable(false);
  const commandContext = derived([scanStore, fake.modal], ([store, modal]) => ({ store, modal }));
  return { commandContext, describe: fake.describe, run: fake.run };
});

import ControlStrip from './ControlStrip.svelte';
import { scanStore } from '$lib/util/scanStore';
import { ui } from '$lib/app/ui';
import { activeView } from '$lib/app/views';

const EN0: NetworkInterface = {
  name: 'en0',
  ip: '192.168.1.23',
  cidr: 24,
  subnet: '192.168.1.0/24',
  host_count: 254,
  is_default_route: true
};
const EN7: NetworkInterface = { ...EN0, name: 'en7', ip: '10.0.4.2', subnet: '10.0.0.0/16', host_count: 65534 };

/** Table 4.1's enabled rules for the strip's commands (not modal). */
function enabledFor(ref: CommandRef, s: ScanStoreState): boolean {
  switch (ref.id) {
    case 'scan.toggle':
      return s.scanning ? !s.stopping : !s.loading && s.interfaces.length > 0;
    case 'scan.interface':
      return !s.scanning && s.interfaces.length > 0;
    case 'scan.depth':
      return !s.scanning;
    case 'view.showHidden':
      return s.hiddenIps.length > 0 || s.showHiddenEntries;
    default:
      return true;
  }
}

function runCommand(ref: CommandRef) {
  if (fake.refuse.has(ref.id)) return;
  switch (ref.id) {
    case 'scan.interface':
      scanStore.setInterface(ref.arg!);
      return;
    case 'scan.depth':
      scanStore.setScanApproach(ref.arg as ScanApproach);
      return;
    case 'view.scope':
      ui.setScope(ref.arg as 'all' | 'favorites' | 'new');
      return;
    case 'view.showHidden':
      scanStore.setShowHiddenEntries(!get(fake.store).showHiddenEntries);
      return;
  }
}

function setStore(p: Partial<ScanStoreState>) {
  fake.store.update((s) => ({ ...s, ...p }));
}

const IDLE: Partial<ScanStoreState> = {
  interfaces: [EN0, EN7],
  selectedInterface: 'en0|192.168.1.23',
  scanApproach: 'balanced',
  loading: false,
  scanning: false,
  stopping: false,
  hiddenIps: [],
  showHiddenEntries: false,
  query: '',
  selectedHostIp: null
};

const settle = () => new Promise((r) => setTimeout(r, 0));

/** Choose a pop-up item from the keyboard: open, step, Return; the menu
 * blinks the item for 100ms before it reports the choice. */
async function chooseFromKeyboard(popup: HTMLElement, steps: number, key = 'ArrowDown') {
  await fireEvent.keyDown(popup, { key: 'ArrowDown' });
  const menu = document.querySelector<HTMLElement>('.osm-menu')!;
  for (let i = 0; i < steps; i++) await fireEvent.keyDown(menu, { key });
  await fireEvent.keyDown(menu, { key: 'Enter' });
  await new Promise((r) => setTimeout(r, 150));
}

function describedText(el: Element): string {
  const ids = el.getAttribute('aria-describedby')?.split(/\s+/) ?? [];
  return ids.map((id) => document.getElementById(id)?.textContent ?? '').join(' ');
}

beforeEach(() => {
  fake.refuse.clear();
  fake.run.mockReset();
  fake.run.mockImplementation(runCommand);
  fake.describe.mockReset();
  fake.describe.mockImplementation((ref: CommandRef, ctx: CommandContext) => ({
    title: ref.id,
    enabled: !ctx.modal && enabledFor(ref, ctx.store)
  }));
  fake.modal.set(false);
  setStore(IDLE);
  fake.model.update((m) => ({ ...m, rows: [] }));
  ui.setScope('all');
  activeView.set(null);
});

afterEach(() => {
  vi.restoreAllMocks();
});

function mount() {
  const { container } = render(ControlStrip);
  const q = <T extends HTMLElement>(sel: string) => container.querySelector<T>(sel)!;
  return {
    container,
    strip: q('.lan-strip'),
    iface: q<HTMLButtonElement>('#lan-interface'),
    depth: q<HTMLButtonElement>('#lan-depth'),
    show: q<HTMLButtonElement>('#lan-show'),
    scan: q<HTMLButtonElement>('.lan-scan'),
    hidden: q<HTMLInputElement>('.lan-show-hidden input'),
    find: q<HTMLInputElement>('#lan-find'),
    label: (id: string) => container.querySelector<HTMLLabelElement>(`label[for=${id}]`)!
  };
}

it('lays out the strip with its labels and Osmium controls', () => {
  const s = mount();

  expect(s.label('lan-interface').textContent).toBe('Interface:');
  expect(s.label('lan-depth').textContent).toBe('Depth:');
  expect(s.label('lan-show').textContent).toBe('Show:');
  expect(s.label('lan-find').textContent).toBe('Find:');
  for (const id of ['lan-interface', 'lan-depth', 'lan-show']) {
    expect(s.label(id).classList.contains('osm-popup-title')).toBe(true);
  }

  expect(s.iface.classList.contains('osm-popup')).toBe(true);
  expect(s.iface.textContent).toBe('en0 (192.168.1.0/24)');
  expect(s.iface.getAttribute('aria-label')).toBe('Interface en0 (192.168.1.0/24)');
  expect(s.depth.textContent).toBe('Balanced');
  expect(s.show.textContent).toBe('All Hosts');

  expect(s.scan.textContent).toBe('Scan');
  expect(s.scan.classList.contains('osm-button')).toBe(true);
  expect(s.scan.dataset.width).toBe('82');

  expect(s.hidden.closest('label')!.classList.contains('osm-checkbox')).toBe(true);
  expect(s.hidden.closest('label')!.textContent!.trim()).toBe('Show hidden hosts');

  expect(s.find.classList.contains('osm-edit')).toBe(true);
  expect(s.find.classList.contains('osm-compact')).toBe(true);
  expect(s.find.placeholder).toBe('');
  expect(s.find.getAttribute('aria-label')).toBe('Filter hosts by name, IP, vendor, type, MAC, port or service');

  expect(s.container.querySelector('[title]')).toBeNull();
});

it('keeps the tab order of spec 3.2', () => {
  const s = mount();
  const focusable = [...s.strip.querySelectorAll('button, input')];

  expect(focusable).toEqual([s.iface, s.depth, s.scan, s.show, s.hidden, s.find]);
});

it('lists the interfaces, or says there are none', async () => {
  const s = mount();

  await fireEvent.keyDown(s.iface, { key: 'ArrowDown' });
  const items = [...document.querySelectorAll('.osm-menu .osm-menu-item')].map((li) => li.textContent);
  expect(items).toEqual(['en0 (192.168.1.0/24)', 'en7 (10.0.0.0/16)']);
  await fireEvent.keyDown(document.querySelector('.osm-menu')!, { key: 'Escape' });

  setStore({ interfaces: [], selectedInterface: null });
  await settle();
  expect(s.iface.textContent).toBe('No interfaces found');
  expect(s.iface.disabled).toBe(true);
  expect(s.label('lan-interface').classList.contains('osm-disabled')).toBe(true);

  // While the store still reads them: an empty, dimmed pop-up.
  setStore({ loading: true });
  await settle();
  expect(s.iface.textContent).toBe('');
  expect(s.iface.disabled).toBe(true);
});

it('dims Interface and Depth (with their labels) while scanning; Show stays live', async () => {
  const s = mount();
  expect(s.iface.disabled).toBe(false);
  expect(s.depth.disabled).toBe(false);

  setStore({ scanning: true });
  await settle();

  expect(s.iface.disabled).toBe(true);
  expect(s.depth.disabled).toBe(true);
  expect(s.label('lan-interface').classList.contains('osm-disabled')).toBe(true);
  expect(s.label('lan-depth').classList.contains('osm-disabled')).toBe(true);
  expect(s.show.disabled).toBe(false);
  expect(s.label('lan-show').classList.contains('osm-disabled')).toBe(false);
  expect(s.find.disabled).toBe(false);
  expect(describedText(s.iface)).toContain('Not available while a scan is running.');
});

it('dims Show with its label when the command model does', () => {
  fake.describe.mockImplementation((ref: CommandRef) => ({ title: ref.id, enabled: ref.id !== 'view.scope' }));
  const s = mount();

  expect(s.show.disabled).toBe(true);
  expect(s.label('lan-show').classList.contains('osm-disabled')).toBe(true);
  expect(s.label('lan-interface').classList.contains('osm-disabled')).toBe(false);
});

it('titles the button Scan, Stop and Stopping…, enabled per the command model', async () => {
  const s = mount();
  expect(s.scan.textContent).toBe('Scan');
  expect(s.scan.disabled).toBe(false);
  expect(describedText(s.scan)).toMatch(/^Scan button\n\nSearches/);

  setStore({ scanning: true });
  await settle();
  expect(s.scan.textContent).toBe('Stop');
  expect(s.scan.disabled).toBe(false);
  expect(describedText(s.scan)).toMatch(/^Stop button\n\nStops the scan\./);

  setStore({ stopping: true });
  await settle();
  expect(s.scan.textContent).toBe('Stopping…');
  expect(s.scan.disabled).toBe(true);
  expect(describedText(s.scan)).toMatch(/^Stop button\n\nLantenna is finishing/);

  setStore({ scanning: false, stopping: false, interfaces: [], selectedInterface: null });
  await settle();
  expect(s.scan.textContent).toBe('Scan');
  expect(s.scan.disabled).toBe(true);
  expect(describedText(s.scan)).toBe('Scan button\n\nNot available because no network interface was found.');

  // Loading: dimmed, with the ordinary Scan balloon.
  setStore({ loading: true, interfaces: [EN0], selectedInterface: 'en0|192.168.1.23' });
  await settle();
  expect(s.scan.disabled).toBe(true);
  expect(describedText(s.scan)).toMatch(/^Scan button\n\nSearches/);
});

it('runs Scan / Stop through the command model', async () => {
  const s = mount();

  await fireEvent.click(s.scan, { detail: 0 });

  expect(fake.run).toHaveBeenCalledExactlyOnceWith({ id: 'scan.toggle' });
});

it('ignores the alert rule, which the inactive window already shows', async () => {
  const s = mount();
  fake.modal.set(true);
  await settle();

  expect(s.scan.disabled).toBe(false);
  expect(s.iface.disabled).toBe(false);
  expect(fake.describe).toHaveBeenLastCalledWith(expect.anything(), expect.objectContaining({ modal: false }));
});

it('chooses an interface, a depth and a scope through their commands', async () => {
  const s = mount();

  await chooseFromKeyboard(s.iface, 1);
  expect(fake.run).toHaveBeenLastCalledWith({ id: 'scan.interface', arg: 'en7|10.0.4.2' });
  expect(get(fake.store).selectedInterface).toBe('en7|10.0.4.2');

  await chooseFromKeyboard(s.depth, 1);
  expect(fake.run).toHaveBeenLastCalledWith({ id: 'scan.depth', arg: 'thorough' });
  expect(s.depth.textContent).toBe('Thorough');

  await chooseFromKeyboard(s.show, 2);
  expect(fake.run).toHaveBeenLastCalledWith({ id: 'view.scope', arg: 'new' });
  expect(get(ui).scope).toBe('new');
  expect(s.show.textContent).toBe('New Hosts');
});

it('follows the store when something else changes a setting', async () => {
  const s = mount();

  setStore({ scanApproach: 'fast', selectedInterface: 'en7|10.0.4.2' });
  ui.setScope('favorites');
  await settle();

  expect(s.depth.textContent).toBe('Fast');
  expect(s.iface.textContent).toBe('en7 (10.0.0.0/16)');
  expect(s.show.textContent).toBe('Favorite Hosts');
});

it('puts a pop-up back when its command refuses the choice', async () => {
  const s = mount();
  fake.refuse.add('scan.depth');

  await chooseFromKeyboard(s.depth, 1);
  await settle();

  expect(fake.run).toHaveBeenCalledWith({ id: 'scan.depth', arg: 'thorough' });
  expect(get(fake.store).scanApproach).toBe('balanced');
  expect(s.depth.textContent).toBe('Balanced');
});

it('dims Show hidden hosts while nothing is hidden and it is off', async () => {
  const s = mount();
  const box = s.hidden.closest('label')!;
  expect(s.hidden.disabled).toBe(true);
  expect(box.classList.contains('osm-disabled')).toBe(true);
  expect(describedText(s.hidden)).toContain('Not available because no hosts are hidden.');

  setStore({ hiddenIps: ['192.168.1.1'] });
  await settle();
  expect(s.hidden.disabled).toBe(false);
  expect(box.classList.contains('osm-disabled')).toBe(false);
  expect(describedText(s.hidden)).not.toContain('Not available');

  await fireEvent.click(s.hidden);
  expect(fake.run).toHaveBeenCalledWith({ id: 'view.showHidden' });
  expect(get(fake.store).showHiddenEntries).toBe(true);
  expect(s.hidden.checked).toBe(true);

  // On with nothing hidden any more: stays enabled, so it can go off.
  setStore({ hiddenIps: [] });
  await settle();
  expect(s.hidden.disabled).toBe(false);
});

it('shows the store’s answer when the checkbox command is refused', async () => {
  const s = mount();
  setStore({ hiddenIps: ['192.168.1.1'] });
  await settle();
  fake.refuse.add('view.showHidden');

  await fireEvent.click(s.hidden);

  expect(s.hidden.checked).toBe(false);
});

it('filters as you type and follows the query set elsewhere', async () => {
  const s = mount();

  await fireEvent.input(s.find, { target: { value: 'printer 631' } });
  expect(scanStore.setQuery).toHaveBeenLastCalledWith('printer 631');

  setStore({ query: '' });
  await settle();
  expect(s.find.value).toBe('');
});

it('clears Find with Escape, unless a balloon took the key', async () => {
  const s = mount();
  setStore({ query: 'nas' });
  await settle();
  expect(s.find.value).toBe('nas');

  const taken = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true });
  taken.preventDefault();
  s.find.dispatchEvent(taken);
  expect(get(fake.store).query).toBe('nas');

  const escape = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true });
  s.find.dispatchEvent(escape);
  await settle();

  expect(escape.defaultPrevented).toBe(true);
  expect(get(fake.store).query).toBe('');
  expect(s.find.value).toBe('');
});

function fakeView(): HostViewApi & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    element: document.createElement('div'),
    focus: () => calls.push('focus'),
    reveal: (ip: string) => calls.push(`reveal ${ip}`),
    extraHeight: () => 0,
    idealColumnsWidth: () => null
  };
}

function rows(...ips: string[]): HostRow[] {
  return ips.map((ip) => ({ ip }) as HostRow);
}

it('moves to the list with Return, selecting its first row if none is', async () => {
  const s = mount();
  const view = fakeView();
  activeView.set(view);
  fake.model.update((m) => ({ ...m, rows: rows('192.168.1.31', '192.168.1.40') }));

  const enter = new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true });
  s.find.dispatchEvent(enter);

  expect(enter.defaultPrevented).toBe(true);
  expect(scanStore.setSelectedHost).toHaveBeenCalledWith('192.168.1.31');
  expect(view.calls).toEqual(['reveal 192.168.1.31', 'focus']);
});

it('keeps a listed selection on Return, and replaces one the query hides', async () => {
  const s = mount();
  const view = fakeView();
  activeView.set(view);
  fake.model.update((m) => ({ ...m, rows: rows('192.168.1.31', '192.168.1.40') }));
  setStore({ selectedHostIp: '192.168.1.40' });

  await fireEvent.keyDown(s.find, { key: 'Enter' });
  expect(scanStore.setSelectedHost).not.toHaveBeenCalled();
  expect(view.calls).toEqual(['focus']);

  setStore({ selectedHostIp: '192.168.1.99' });
  await fireEvent.keyDown(s.find, { key: 'Enter' });
  expect(scanStore.setSelectedHost).toHaveBeenCalledWith('192.168.1.31');
});

it('moves to an empty list with Return, and leaves composing and Command keys alone', async () => {
  const s = mount();
  const view = fakeView();
  activeView.set(view);

  const enter = new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true });
  s.find.dispatchEvent(enter);
  expect(enter.defaultPrevented).toBe(true);
  expect(view.calls).toEqual(['focus']);
  expect(scanStore.setSelectedHost).not.toHaveBeenCalled();

  const composing = new KeyboardEvent('keydown', { key: 'Enter', isComposing: true, bubbles: true, cancelable: true });
  s.find.dispatchEvent(composing);
  // WebKit (WKWebView) ends a composition with a keydown whose
  // isComposing is false; only keyCode 229 gives it away.
  const committing = new KeyboardEvent('keydown', { key: 'Enter', keyCode: 229, bubbles: true, cancelable: true });
  expect(committing.keyCode).toBe(229);
  s.find.dispatchEvent(committing);
  const command = new KeyboardEvent('keydown', { key: 'Enter', metaKey: true, bubbles: true, cancelable: true });
  s.find.dispatchEvent(command);
  expect(composing.defaultPrevented).toBe(false);
  expect(committing.defaultPrevented).toBe(false);
  expect(command.defaultPrevented).toBe(false);
  expect(view.calls).toEqual(['focus']);
});

it('attaches Balloon Help to every control', () => {
  const s = mount();

  expect(describedText(s.iface)).toMatch(/^Interface pop-up menu\n\n/);
  expect(describedText(s.depth)).toMatch(/^Depth pop-up menu\n\n/);
  expect(describedText(s.show)).toMatch(/^Show pop-up menu\n\n/);
  expect(describedText(s.hidden)).toMatch(/^Show hidden hosts checkbox\n\n/);
  expect(describedText(s.find)).toMatch(/^Find field\n\n/);
});
