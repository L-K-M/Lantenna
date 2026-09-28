// The contextual menus of 4.4, drawn by Osmium's showContextMenu, and
// the guard that keeps the browser's own menu away.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { get, writable } from 'svelte/store';
import { showAlert } from 'osmium-ui';
import type { HostModel } from './hostModel';

const fake = vi.hoisted(() => ({
  model: null as unknown as import('svelte/store').Writable<HostModel>
}));

vi.mock('./hostModel', async () => {
  const { EMPTY_MODEL } = await import('./commands.fixture');
  fake.model = writable(EMPTY_MODEL);
  return { hostModel: fake.model };
});

const { closeContextMenu, installContextMenuGuard, keyMenuWait, openHostMenu, openViewMenu } = await import('./contextMenus');
const { EMPTY_MODEL, host, row } = await import('./commands.fixture');
const { scanStore } = await import('$lib/util/scanStore');
const { ui } = await import('./ui');

const printer = row(host('192.168.1.31', { name: 'BRN30055C.local', ports: [80, 445] }), {
  customName: 'Office Printer'
});

function menu(): HTMLElement | null {
  return document.querySelector<HTMLElement>('.osm-menu.osm-contextmenu');
}

/** Items as text: '-' separators, '[x]' dimmed, '✓' checked. */
function items(el: HTMLElement): string[] {
  return Array.from(el.children).map((li) => {
    if (!li.classList.contains('osm-menu-item')) return '-';
    const title = li.getAttribute('aria-disabled') === 'true' ? `[${li.textContent}]` : li.textContent;
    return `${title}${li.getAttribute('aria-checked') === 'true' ? ' ✓' : ''}`;
  });
}

function key(k: string) {
  document.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true }));
}

beforeEach(() => {
  fake.model.set({ ...EMPTY_MODEL, rows: [printer], universe: 1, selected: printer });
});

afterEach(() => {
  if (menu()) key('Escape');
  vi.restoreAllMocks();
});

it('selects the host, then shows its menu', () => {
  const select = vi.spyOn(scanStore, 'setSelectedHost');
  openHostMenu('192.168.1.31', { x: 40, y: 60 });

  expect(select).toHaveBeenCalledWith('192.168.1.31');
  const el = menu()!;
  expect(el.getAttribute('role')).toBe('menu');
  expect(el.getAttribute('aria-label')).toBe('Office Printer');
  expect(items(el)).toEqual([
    'Help',
    '-',
    'Open',
    'http://192.168.1.31',
    'smb://192.168.1.31',
    'Get Info',
    '-',
    'Copy IP Address',
    'Copy Host Name',
    '[Copy MAC Address]',
    '-',
    'Add to Favorites',
    'Rename…',
    'Clear Custom Name',
    'Hide Host',
    '-',
    'Deep Scan',
    '[Wake]'
  ]);
  // Contextual menus draw no keys.
  expect(el.querySelector('.osm-menu-key')).toBeNull();
});

it('names the menu of a nameless host by its IP address, not “Unknown”', () => {
  const nameless = row(host('192.168.1.77'));
  fake.model.set({ ...EMPTY_MODEL, rows: [nameless], universe: 1, selected: nameless });
  openHostMenu('192.168.1.77', { x: 40, y: 60 });

  expect(menu()!.getAttribute('aria-label')).toBe('192.168.1.77');
});

it('closes the open menu on request, without choosing', () => {
  const run = vi.spyOn(scanStore, 'startScan');
  openViewMenu({ x: 300, y: 200 });
  expect(menu()).not.toBeNull();

  closeContextMenu();
  expect(menu()).toBeNull();
  expect(run).not.toHaveBeenCalled();
  closeContextMenu(); // nothing open: nothing happens
});

it('shows the empty-space menu and runs the chosen item', async () => {
  openViewMenu({ x: 300, y: 200 });
  const el = menu()!;
  expect(el.getAttribute('aria-label')).toBe('Hosts');
  expect(items(el)).toEqual([
    'Help',
    '-',
    '[Scan Network]', // no interface in this store
    '-',
    'as List ✓',
    'as Icons',
    '-',
    'All Hosts ✓',
    'Favorite Hosts',
    'New Hosts',
    '[Show Hidden Hosts]'
  ]);

  // Type-select "as Icons" and choose it.
  key('a');
  key('a');
  key('Enter');
  await vi.waitFor(() => expect(get(ui).viewMode).toBe('icons'));
  expect(menu()).toBeNull();
  ui.setViewMode('list');
});

it('opens nothing while an alert is up', async () => {
  const alert = showAlert({ kind: 'stop', message: 'Lantenna couldn’t start its scanner.' });
  openViewMenu({ x: 10, y: 10 });
  openHostMenu('192.168.1.31', { x: 10, y: 10 });
  expect(menu()).toBeNull();
  alert.close();
  await alert.result;
});

it('keeps the browser’s menu away after every other handler', () => {
  const dispose = installContextMenuGuard();
  const field = document.createElement('input');
  document.body.append(field);
  let seenByView: boolean | null = null;
  field.addEventListener('contextmenu', (e) => {
    seenByView = e.defaultPrevented;
  });

  const e = new MouseEvent('contextmenu', { bubbles: true, cancelable: true });
  field.dispatchEvent(e);
  expect(seenByView).toBe(false);
  expect(e.defaultPrevented).toBe(true);

  dispose();
  const after = new MouseEvent('contextmenu', { bubbles: true, cancelable: true });
  field.dispatchEvent(after);
  expect(after.defaultPrevented).toBe(false);
  field.remove();
});

it('drops the one contextmenu event that follows the menu key, and no other', () => {
  let now = 1000;
  vi.spyOn(performance, 'now').mockImplementation(() => now);
  const wait = keyMenuWait();
  expect(wait.takeKeyEvent()).toBe(false);

  wait.keyPressed();
  now += 100;
  expect(wait.takeKeyEvent()).toBe(true);
  expect(wait.takeKeyEvent()).toBe(false);

  // A press first: the right-click's event is not the key's.
  wait.keyPressed();
  wait.pressed();
  expect(wait.takeKeyEvent()).toBe(false);

  // Too late to be the key's (WebKit sends none).
  wait.keyPressed();
  now += 500;
  expect(wait.takeKeyEvent()).toBe(false);
});
