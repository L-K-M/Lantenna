// Owner: unit B (spec 8.4). HostIconView over the real stores, with the
// scan store loaded from a mocked Tauri backend: tiles, the roving
// tabindex, the keyboard, opening, contextual menus, the placeholder,
// the HostViewApi contract and a running scan's new and pending hosts.
//
// happy-dom lays nothing out: the grid has one column and no height,
// and presses that must land inside an element stub its rectangle.
import { fireEvent, render } from '@testing-library/svelte';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { tick } from 'svelte';
import { get } from 'svelte/store';
import type { NetworkInterface, ScanResult } from '$lib/types';

const native = vi.hoisted(() => {
  localStorage.setItem('lantenna.favoriteIps', JSON.stringify(['10.0.0.3', '10.0.0.50']));
  const handlers = new Map<string, (event: { payload: unknown }) => void>();
  return {
    handlers,
    interfaces: [] as unknown[],
    result: null as unknown,
    invoke: async (command: string): Promise<unknown> =>
      command === 'get_network_interfaces'
        ? native.interfaces
        : command === 'get_scan_results'
          ? native.result
          : null,
    listen: async (name: string, callback: (event: { payload: unknown }) => void) => {
      handlers.set(name, callback);
      return () => handlers.delete(name);
    }
  };
});

const spies = vi.hoisted(() => ({
  openHost: vi.fn(async (_ip: string) => {}),
  openHostMenu: vi.fn((_ip: string, _at: { x: number; y: number }) => {}),
  openViewMenu: vi.fn((_at: { x: number; y: number }) => {})
}));

vi.mock('@tauri-apps/api/core', () => ({ invoke: native.invoke }));
vi.mock('@tauri-apps/api/event', () => ({ listen: native.listen }));
vi.mock('$lib/app/actions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('$lib/app/actions')>()),
  openHost: spies.openHost
}));
vi.mock('$lib/app/contextMenus', async (importOriginal) => ({
  installControlClick: (await importOriginal<typeof import('$lib/app/contextMenus')>()).installControlClick,
  openHostMenu: spies.openHostMenu,
  openViewMenu: spies.openViewMenu,
  installContextMenuGuard: () => () => {}
}));

import HostIconView, { wrapLabel } from './HostIconView.svelte';
import { ui } from '$lib/app/ui';
import { activeView, type HostViewApi } from '$lib/app/views';
import { scanStore } from '$lib/util/scanStore';
import { makeFingerprint, makeHost, makePorts } from '../../test/hosts';

const SEEN = '2026-09-27T12:00:00Z';
const ORDER = ['10.0.0.3', '10.0.0.50', '10.0.0.1', '10.0.0.2', '10.0.0.10'];

beforeAll(async () => {
  const en0: NetworkInterface = {
    name: 'en0',
    ip: '10.0.0.20',
    cidr: 24,
    subnet: '10.0.0.0/24',
    host_count: 254,
    is_default_route: true
  };
  const result: ScanResult = {
    started_at: SEEN,
    completed_at: SEEN,
    cancelled: false,
    options: {
      interface_name: 'en0',
      subnet: '10.0.0.0/24',
      port_profile: 'standard',
      discovery_mode: 'hybrid',
      timeout_ms: 450,
      max_hosts: 254
    },
    hosts: [
      makeHost('10.0.0.1', {
        name: 'router',
        open_ports: makePorts(22, 53, 80),
        fingerprint: makeFingerprint({ vendor: 'Ubiquiti Inc.', device_type: 'Network device' })
      }),
      makeHost('10.0.0.2', { name: 'printer.local', open_ports: makePorts([631, 'ipp']) }),
      makeHost('10.0.0.3', { name: 'nas' }),
      makeHost('10.0.0.10')
    ]
  };
  native.interfaces = [en0];
  native.result = result;
  await scanStore.init();
});

beforeEach(() => {
  spies.openHost.mockClear();
  spies.openHostMenu.mockClear();
  spies.openViewMenu.mockClear();
});

afterEach(() => {
  scanStore.setQuery('');
  scanStore.setSelectedHost(null);
});

async function nextFrame(): Promise<void> {
  await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
}

function tiles(container: HTMLElement): HTMLElement[] {
  return [...container.querySelectorAll<HTMLElement>('.lan-tile')];
}

function tileOf(container: HTMLElement, ip: string): HTMLElement {
  const tile = container.querySelector<HTMLElement>(`.lan-tile[data-ip="${ip}"]`);
  if (!tile) throw new Error(`no tile for ${ip}`);
  return tile;
}

function gridOf(container: HTMLElement): HTMLElement {
  return container.querySelector<HTMLElement>('[role="listbox"]')!;
}

function text(el: Element, selector: string): string {
  return el.querySelector(selector)?.textContent ?? '';
}

describe('wrapLabel', () => {
  // Every character 5px wide: 10 fit in 50.
  const measure = (s: string) => 5 * s.length;

  it('keeps a label that fits on one line', () => {
    expect(wrapLabel('router', 50, measure)).toEqual(['router']);
    expect(wrapLabel('0123456789', 50, measure)).toEqual(['0123456789']);
  });

  it('breaks after the last space, hyphen, period or underscore that fits', () => {
    expect(wrapLabel('Living Room TV', 50, measure)).toEqual(['Living', 'Room TV']);
    expect(wrapLabel('living-room-tv', 50, measure)).toEqual(['living-', 'room-tv']);
    expect(wrapLabel('brn30055c.lan', 50, measure)).toEqual(['brn30055c.', 'lan']);
    expect(wrapLabel('my_printer_2', 50, measure)).toEqual(['my_', 'printer_2']);
  });

  it('breaks anywhere when nothing fits before a break', () => {
    expect(wrapLabel('abcdefghijklmnop', 50, measure)).toEqual(['abcdefghij', 'klmnop']);
  });

  it('ends a second line that doesn’t fit in an ellipsis', () => {
    expect(wrapLabel('living-room-media-center', 50, measure)).toEqual(['living-', 'room-medi…']);
    expect(wrapLabel('abcdefghijklmnopqrstuvwxyz', 50, measure)).toEqual(['abcdefghij', 'klmnopqrs…']);
  });
});

describe('tiles', () => {
  it('shows the hosts in the list’s order with their names and addresses', () => {
    const { container } = render(HostIconView);
    const grid = gridOf(container);

    expect(grid.getAttribute('aria-label')).toBe('Hosts');
    expect(tiles(container).map((t) => t.dataset.ip)).toEqual(ORDER);
    expect(tiles(container).map((t) => text(t, '.lan-tile-name'))).toEqual([
      'nas',
      '10.0.0.50',
      'router',
      'printer',
      '10.0.0.10'
    ]);
    expect(text(tileOf(container, '10.0.0.1'), '.lan-tile-ip')).toBe('10.0.0.1');
  });

  it('names each option with its state and marks favorites and stale hosts', () => {
    const { container } = render(HostIconView);

    const stale = tileOf(container, '10.0.0.50');
    expect(stale.getAttribute('role')).toBe('option');
    expect(stale.getAttribute('aria-label')).toBe('10.0.0.50, Unknown host, Not seen, Favorite');
    expect(stale.classList.contains('lan-dim')).toBe(true);
    expect(stale.querySelector('.lan-tile-badge')).not.toBeNull();

    const router = tileOf(container, '10.0.0.1');
    expect(router.getAttribute('aria-label')).toBe('router, 10.0.0.1, Network device');
    expect(router.classList.contains('lan-dim')).toBe(false);
    expect(router.querySelector('.lan-tile-badge')).toBeNull();
    expect(router.querySelector('img')?.getAttribute('alt')).toBe('');
  });

  it('puts only the selected tile, or the first, in the Tab order', async () => {
    const { container } = render(HostIconView);
    const inTabOrder = () => tiles(container).filter((t) => t.tabIndex === 0).map((t) => t.dataset.ip);

    expect(inTabOrder()).toEqual(['10.0.0.3']);
    expect(gridOf(container).tabIndex).toBe(-1);

    scanStore.setSelectedHost('10.0.0.2');
    await nextFrame();
    expect(inTabOrder()).toEqual(['10.0.0.2']);
    expect(tileOf(container, '10.0.0.2').getAttribute('aria-selected')).toBe('true');
    expect(tileOf(container, '10.0.0.2').classList.contains('lan-selected')).toBe(true);
  });

  it('keeps Osmium’s scroll bar in step with the tiles', async () => {
    const { container } = render(HostIconView);
    const host = container.querySelector('.lan-icons')!;
    const grid = gridOf(container);
    const bar = host.querySelector(':scope > .osm-scrollbar')!;
    expect(host.classList.contains('osm-has-scrollbar')).toBe(true);

    // One 86px row per tile (happy-dom's one column) in a 100px view:
    // the tiles change the grid's extent but not its box.
    Object.defineProperty(grid, 'clientHeight', { configurable: true, value: 100 });
    Object.defineProperty(grid, 'scrollHeight', {
      configurable: true,
      get: () => Math.max(100, 14 + 86 * tiles(container).length)
    });

    scanStore.setQuery('router');
    await nextFrame();
    expect(bar.classList.contains('osm-sb-off')).toBe(true);

    scanStore.setQuery('');
    await nextFrame();
    expect(bar.classList.contains('osm-sb-off')).toBe(false);

    scanStore.setQuery('zzz');
    await nextFrame();
    expect(bar.classList.contains('osm-sb-off')).toBe(true);
  });
});

describe('pointer', () => {
  it('selects on a press and opens the selected tile on a double-click', async () => {
    const { container } = render(HostIconView);
    const printer = tileOf(container, '10.0.0.2');

    await fireEvent.dblClick(printer);
    expect(spies.openHost).not.toHaveBeenCalled();

    await fireEvent.pointerDown(printer, { button: 0 });
    expect(get(scanStore).selectedHostIp).toBe('10.0.0.2');
    await fireEvent.dblClick(printer);
    expect(spies.openHost).toHaveBeenCalledWith('10.0.0.2');
  });

  it('leaves Control-presses to the contextual menu', async () => {
    const { container } = render(HostIconView);
    await fireEvent.pointerDown(tileOf(container, '10.0.0.2'), { button: 0, ctrlKey: true });
    expect(get(scanStore).selectedHostIp).toBeNull();
  });
});

describe('keyboard', () => {
  it('moves the selection and the focus with the arrows, Home and End', async () => {
    const { container } = render(HostIconView);
    const grid = gridOf(container);
    const selected = () => get(scanStore).selectedHostIp;

    await fireEvent.keyDown(grid, { key: 'ArrowRight' });
    expect(selected()).toBe('10.0.0.3');
    expect(document.activeElement).toBe(tileOf(container, '10.0.0.3'));

    await fireEvent.keyDown(document.activeElement!, { key: 'ArrowRight' });
    expect(selected()).toBe('10.0.0.50');
    await fireEvent.keyDown(document.activeElement!, { key: 'End' });
    expect(selected()).toBe('10.0.0.10');
    await fireEvent.keyDown(document.activeElement!, { key: 'ArrowRight' });
    expect(selected()).toBe('10.0.0.10');
    await fireEvent.keyDown(document.activeElement!, { key: 'ArrowLeft' });
    expect(selected()).toBe('10.0.0.2');
    await fireEvent.keyDown(document.activeElement!, { key: 'Home' });
    expect(selected()).toBe('10.0.0.3');
    expect(document.activeElement).toBe(tileOf(container, '10.0.0.3'));
    expect(tileOf(container, '10.0.0.3').tabIndex).toBe(0);
  });

  it('moves up and down by rows, staying put where no row is above or below', async () => {
    const { container } = render(HostIconView);
    const grid = gridOf(container);
    // Three tiles a row: 10.0.0.3, .50, .1 / .2, .10.
    Object.defineProperty(grid, 'clientWidth', { value: 380, configurable: true });
    const selected = () => get(scanStore).selectedHostIp;
    const key = (k: string) => fireEvent.keyDown(document.activeElement!, { key: k });

    await fireEvent.keyDown(grid, { key: 'ArrowRight' });
    await key('ArrowRight');
    expect(selected()).toBe('10.0.0.50');
    await key('ArrowUp'); // the top row
    expect(selected()).toBe('10.0.0.50');
    await key('ArrowDown');
    expect(selected()).toBe('10.0.0.10');
    await key('ArrowDown'); // the last row
    expect(selected()).toBe('10.0.0.10');
    await key('ArrowLeft');
    await key('ArrowDown');
    expect(selected()).toBe('10.0.0.2');

    // The next row is short of the column: its last tile.
    await key('Home');
    await key('ArrowRight');
    await key('ArrowRight');
    expect(selected()).toBe('10.0.0.1');
    await key('ArrowDown');
    expect(selected()).toBe('10.0.0.10');
    await key('ArrowUp');
    expect(selected()).toBe('10.0.0.50');
  });

  it('starts from the end going backward without a selection', async () => {
    const { container } = render(HostIconView);
    await fireEvent.keyDown(gridOf(container), { key: 'ArrowUp' });
    expect(get(scanStore).selectedHostIp).toBe('10.0.0.10');
  });

  it('opens the selected host on Return, and leaves Return alone without one', async () => {
    const { container } = render(HostIconView);
    const grid = gridOf(container);

    expect(await fireEvent.keyDown(grid, { key: 'Enter' })).toBe(true);
    expect(spies.openHost).not.toHaveBeenCalled();

    scanStore.setSelectedHost('10.0.0.1');
    expect(await fireEvent.keyDown(grid, { key: 'Enter' })).toBe(false);
    expect(spies.openHost).toHaveBeenCalledWith('10.0.0.1');
  });

  it('selects by typing the start of a name', async () => {
    const { container } = render(HostIconView);
    const grid = gridOf(container);

    await fireEvent.keyDown(grid, { key: 'p' });
    await fireEvent.keyDown(grid, { key: 'r' });
    expect(get(scanStore).selectedHostIp).toBe('10.0.0.2');
    expect(document.activeElement).toBe(tileOf(container, '10.0.0.2'));
  });

  it('selects a tile the keyboard reaches by Tab', async () => {
    const { container } = render(HostIconView);
    tileOf(container, '10.0.0.3').focus();
    expect(get(scanStore).selectedHostIp).toBe('10.0.0.3');
  });

  it('keeps the keyboard in the grid when the focused tile moves or goes', async () => {
    const { container } = render(HostIconView);
    const grid = gridOf(container);

    // Favorites first (ties by IP): the router's tile moves to the front.
    tileOf(container, '10.0.0.1').focus();
    scanStore.toggleFavorite('10.0.0.1');
    await nextFrame();
    expect(tiles(container).map((t) => t.dataset.ip)).toEqual(['10.0.0.1', '10.0.0.3', '10.0.0.50', '10.0.0.2', '10.0.0.10']);
    expect(document.activeElement).toBe(tileOf(container, '10.0.0.1'));
    scanStore.toggleFavorite('10.0.0.1');
    await nextFrame();

    // Hiding the host takes its tile and the selection away: the grid
    // keeps the keyboard, and no other host is selected.
    tileOf(container, '10.0.0.2').focus();
    scanStore.toggleHidden('10.0.0.2');
    await nextFrame();
    expect(tiles(container).map((t) => t.dataset.ip)).not.toContain('10.0.0.2');
    expect(document.activeElement).toBe(grid);
    expect(get(scanStore).selectedHostIp).toBeNull();
    scanStore.toggleHidden('10.0.0.2');
  });
});

describe('contextual menus', () => {
  it('selects a tile and opens its menu at the pointer', async () => {
    const { container } = render(HostIconView);
    const router = tileOf(container, '10.0.0.1');
    router.getBoundingClientRect = () => new DOMRect(0, 0, 112, 72);

    await fireEvent.contextMenu(router.querySelector('img')!, { clientX: 20, clientY: 30 });
    expect(get(scanStore).selectedHostIp).toBe('10.0.0.1');
    expect(spies.openHostMenu).toHaveBeenCalledWith('10.0.0.1', { x: 20, y: 30 });
  });

  it('opens the view’s menu on empty space', async () => {
    const { container } = render(HostIconView);
    const grid = gridOf(container);
    grid.getBoundingClientRect = () => new DOMRect(0, 0, 800, 600);

    await fireEvent.contextMenu(grid, { clientX: 400, clientY: 300 });
    expect(spies.openViewMenu).toHaveBeenCalledWith({ x: 400, y: 300 });
    expect(spies.openHostMenu).not.toHaveBeenCalled();
  });

  it('opens the menus on a Control-click, which Linux sends no contextmenu for', async () => {
    const { container } = render(HostIconView);
    const grid = gridOf(container);
    grid.getBoundingClientRect = () => new DOMRect(0, 0, 800, 600);
    const router = tileOf(container, '10.0.0.1');
    router.getBoundingClientRect = () => new DOMRect(0, 0, 112, 72);

    const onTile = await fireEvent.mouseDown(router.querySelector('img')!, { button: 0, ctrlKey: true, clientX: 20, clientY: 30 });
    expect(onTile).toBe(false);
    expect(get(scanStore).selectedHostIp).toBe('10.0.0.1');
    expect(spies.openHostMenu).toHaveBeenCalledExactlyOnceWith('10.0.0.1', { x: 20, y: 30 });
    expect(document.activeElement).toBe(router);

    await fireEvent.mouseDown(grid, { button: 0, ctrlKey: true, clientX: 400, clientY: 300 });
    expect(spies.openViewMenu).toHaveBeenCalledExactlyOnceWith({ x: 400, y: 300 });
  });

  it('opens the selection’s menu on Shift-F10 or the menu key, once', async () => {
    scanStore.setSelectedHost('10.0.0.2');
    const { container } = render(HostIconView);
    const printer = tileOf(container, '10.0.0.2');

    expect(await fireEvent.keyDown(printer, { key: 'F10', shiftKey: true })).toBe(false);
    expect(spies.openHostMenu).toHaveBeenCalledWith('10.0.0.2', { x: 0, y: 0 });

    // The system's own contextmenu event for the same key.
    await fireEvent.contextMenu(printer);
    expect(spies.openHostMenu).toHaveBeenCalledTimes(1);
  });

  it('opens a right-click’s menu that follows the key’s menu, after the key’s own event', async () => {
    scanStore.setSelectedHost('10.0.0.2');
    const { container } = render(HostIconView);
    const printer = tileOf(container, '10.0.0.2');
    const nas = tileOf(container, '10.0.0.3');
    nas.getBoundingClientRect = () => new DOMRect(0, 0, 112, 72);

    // WebKit sends no contextmenu for the key: the right-click is next.
    await fireEvent.keyDown(printer, { key: 'F10', shiftKey: true });
    await fireEvent.pointerDown(nas, { button: 2 });
    await fireEvent.contextMenu(nas, { button: 2, clientX: 20, clientY: 30 });
    expect(spies.openHostMenu.mock.calls.map(([ip]) => ip)).toEqual(['10.0.0.2', '10.0.0.3']);

    // Chromium's event for the key is dropped, and only that one.
    await fireEvent.keyDown(document.activeElement!, { key: 'ContextMenu' });
    await fireEvent.contextMenu(nas);
    await fireEvent.contextMenu(nas, { clientX: 20, clientY: 30 });
    expect(spies.openHostMenu.mock.calls.map(([ip]) => ip)).toEqual(['10.0.0.2', '10.0.0.3', '10.0.0.3', '10.0.0.3']);
  });

  it('shows the selected tile before opening its menu from the keyboard', async () => {
    scanStore.setSelectedHost('10.0.0.10');
    const { container } = render(HostIconView);
    const grid = gridOf(container);
    grid.scrollTop = 500;

    await fireEvent.keyDown(tileOf(container, '10.0.0.10'), { key: 'ContextMenu' });
    expect(grid.scrollTop).toBeLessThan(500);
    expect(spies.openHostMenu).toHaveBeenCalledTimes(1);
  });

  it('opens the view’s menu from the keyboard without a selection', async () => {
    const { container } = render(HostIconView);
    await fireEvent.keyDown(gridOf(container), { key: 'ContextMenu' });
    expect(spies.openViewMenu).toHaveBeenCalledTimes(1);
    expect(spies.openHostMenu).not.toHaveBeenCalled();
  });
});

describe('placeholder', () => {
  it('explains an empty grid and keeps it a tab stop', async () => {
    const { container } = render(HostIconView);
    const empty = container.querySelector<HTMLElement>('.lan-icons-empty')!;
    expect(empty.hidden).toBe(true);

    scanStore.setQuery('zzz');
    await nextFrame();
    expect(tiles(container)).toHaveLength(0);
    expect(empty.hidden).toBe(false);
    expect(empty.getAttribute('role')).toBe('status');
    expect(empty.textContent).toBe('No hosts match “zzz”.');
    expect(gridOf(container).tabIndex).toBe(0);
  });
});

describe('HostViewApi', () => {
  it('registers while mounted, without a column width', () => {
    const { container, unmount } = render(HostIconView);
    expect(get(activeView)?.element).toBe(gridOf(container));
    expect(get(activeView)?.idealColumnsWidth()).toBeNull();

    unmount();
    expect(get(activeView)).toBeNull();
  });

  it('draws rows still waiting for the frame before revealing or focusing', async () => {
    const { container } = render(HostIconView);

    scanStore.setQuery('router');
    await nextFrame();
    expect(tiles(container)).toHaveLength(1);

    scanStore.setQuery('');
    scanStore.setSelectedHost('10.0.0.10');
    expect(tiles(container)).toHaveLength(1);
    get(activeView)!.reveal('10.0.0.10');
    expect(tiles(container)).toHaveLength(5);

    get(activeView)!.focus();
    expect(document.activeElement).toBe(tileOf(container, '10.0.0.10'));
  });

  it('takes the keyboard without selecting a host', () => {
    const { container } = render(HostIconView);
    get(activeView)!.focus();
    expect(document.activeElement).toBe(gridOf(container));
    expect(get(scanStore).selectedHostIp).toBeNull();
  });

  it('hands the keyboard to the next view when the view changes', async () => {
    const { container } = render(HostIconView);
    ui.setViewMode('icons');
    scanStore.setSelectedHost('10.0.0.2');
    get(activeView)!.focus();
    expect(document.activeElement).toBe(tileOf(container, '10.0.0.2'));

    // The page swaps the views on Svelte's next update.
    const next: HostViewApi = { ...get(activeView)!, focus: vi.fn() };
    ui.setViewMode('list');
    activeView.set(next);
    await tick();
    expect(next.focus).toHaveBeenCalledTimes(1);
    activeView.set(null);
  });
});

// Last: the scan leaves the store scanning.
describe('a running scan', () => {
  it('dims the hosts it hasn’t confirmed and marks new ones', async () => {
    const { container } = render(HostIconView);

    await scanStore.startScan();
    native.handlers.get('host-found')!({ payload: makeHost('10.0.0.1', { name: 'router' }) });
    native.handlers.get('host-found')!({ payload: makeHost('10.0.0.77', { name: 'tablet' }) });
    await nextFrame();

    expect(tileOf(container, '10.0.0.2').classList.contains('lan-dim')).toBe(true);
    expect(tileOf(container, '10.0.0.2').getAttribute('aria-label')).toContain('Checking…');
    expect(tileOf(container, '10.0.0.1').classList.contains('lan-dim')).toBe(false);

    const tablet = tileOf(container, '10.0.0.77');
    expect(tablet.classList.contains('lan-new')).toBe(true);
    expect(text(tablet, '.lan-tile-ip')).toBe('10.0.0.77 New');
  });
});
