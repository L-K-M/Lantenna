// Owner: unit B (spec 8.4). HostList over the real stores, with the
// scan store loaded from a mocked Tauri backend: rows and cells, the
// star, the keyboard, opening, sorting, placeholders, contextual menus,
// the HostViewApi contract (pending rows applied at once), the minute
// refresh and remembered column widths.
//
// happy-dom lays nothing out: every box sits at the origin, 0 x 0, so a
// client y is a position in the rows (row i spans 19 i to 19 i + 18),
// and presses that must land inside an element stub its rectangle.
import { fireEvent, render } from '@testing-library/svelte';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { tick } from 'svelte';
import { get } from 'svelte/store';
import type { ScanResult } from '$lib/types';

const native = vi.hoisted(() => {
  // Two favorites before launch: 10.0.0.3 is in the stored scan, 10.0.0.50
  // is not (a stale favorite, "Not seen").
  localStorage.setItem('lantenna.favoriteIps', JSON.stringify(['10.0.0.3', '10.0.0.50']));
  return {
    result: null as unknown,
    invoke: async (command: string): Promise<unknown> =>
      command === 'get_network_interfaces' ? [] : command === 'get_scan_results' ? native.result : null
  };
});

const spies = vi.hoisted(() => ({
  openHost: vi.fn(async (_ip: string) => {}),
  openHostMenu: vi.fn((_ip: string, _at: { x: number; y: number }) => {}),
  openViewMenu: vi.fn((_at: { x: number; y: number }) => {})
}));

vi.mock('@tauri-apps/api/core', () => ({ invoke: native.invoke }));
vi.mock('@tauri-apps/api/event', () => ({ listen: async () => () => {} }));
vi.mock('$lib/app/actions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('$lib/app/actions')>()),
  openHost: spies.openHost
}));
vi.mock('$lib/app/contextMenus', () => ({
  openHostMenu: spies.openHostMenu,
  openViewMenu: spies.openViewMenu,
  installContextMenuGuard: () => () => {}
}));

import HostList from './HostList.svelte';
import { ui } from '$lib/app/ui';
import { activeView, type HostViewApi } from '$lib/app/views';
import { scanStore } from '$lib/util/scanStore';
import { makeFingerprint, makeHost, makePorts } from '../../test/hosts';

const SEEN = '2026-09-27T12:00:00Z';
const DEFAULT_ORDER = ['10.0.0.3', '10.0.0.50', '10.0.0.1', '10.0.0.2', '10.0.0.10'];
const LAUNCH_FAVORITES = ['10.0.0.3', '10.0.0.50'];

beforeAll(async () => {
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
        fingerprint: makeFingerprint({ vendor: 'Ubiquiti Inc.', device_type: 'Network device' }),
        last_seen: SEEN
      }),
      makeHost('10.0.0.2', { name: 'printer', open_ports: makePorts([631, 'ipp']), last_seen: SEEN }),
      makeHost('10.0.0.3', { name: 'nas', last_seen: SEEN }),
      makeHost('10.0.0.10', { last_seen: SEEN })
    ]
  };
  native.result = result;
  await scanStore.init();
});

beforeEach(() => {
  spies.openHost.mockClear();
  spies.openHostMenu.mockClear();
  spies.openViewMenu.mockClear();
});

afterEach(() => {
  vi.useRealTimers();
  // Put the favorites back as they were at launch.
  const favorites = get(scanStore).favoriteIps;
  for (const ip of new Set([...favorites, ...LAUNCH_FAVORITES])) {
    if (favorites.includes(ip) !== LAUNCH_FAVORITES.includes(ip)) scanStore.toggleFavorite(ip);
  }
  scanStore.setQuery('');
  scanStore.setSelectedHost(null);
  ui.setListSort({ column: 'favorite', order: 'normal' });
});

/** After the view's animation frame, and after the list's own flush
 * of updates it held back during a press (a zero timeout). */
async function nextFrame(): Promise<void> {
  await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

function rows(container: HTMLElement): HTMLElement[] {
  return [...container.querySelectorAll<HTMLElement>('.osm-lv-row')];
}

function ipsOf(container: HTMLElement): string[] {
  return rows(container).map((r) => r.querySelectorAll('.osm-lv-cell')[2].textContent ?? '');
}

function rowOf(container: HTMLElement, ip: string): HTMLElement {
  const row = rows(container).find((r) => r.querySelectorAll('.osm-lv-cell')[2].textContent === ip);
  if (!row) throw new Error(`no row for ${ip}`);
  return row;
}

function cells(row: HTMLElement): string[] {
  return [...row.querySelectorAll('.osm-lv-cell')].map((c) => c.textContent ?? '');
}

function starOf(container: HTMLElement, ip: string): HTMLButtonElement {
  return rowOf(container, ip).querySelector<HTMLButtonElement>('button[data-fav]')!;
}

function parts(container: HTMLElement) {
  return {
    grid: container.querySelector<HTMLElement>('.osm-lv-grid')!,
    scroller: container.querySelector<HTMLElement>('.osm-lv-body > .osm-list-view')!
  };
}

/** A press that lands inside `el` (stubbed at 0,0, 20 x 20). */
async function press(el: HTMLElement): Promise<void> {
  el.getBoundingClientRect = () => new DOMRect(0, 0, 20, 20);
  const at = { button: 0, pointerId: 7, pointerType: 'mouse', clientX: 5, clientY: 5 };
  await fireEvent.pointerDown(el, at);
  await fireEvent.pointerUp(el, at);
}

describe('rows', () => {
  it('lists the hosts favorites first, with the cells of 2.6', () => {
    const { container } = render(HostList);

    expect(ipsOf(container)).toEqual(DEFAULT_ORDER);
    expect(cells(rowOf(container, '10.0.0.1'))).toEqual([
      '',
      'router',
      '10.0.0.1',
      '',
      'Network device',
      'Ubiquiti',
      '22, 53, 80',
      expect.any(String)
    ]);
    expect(cells(rowOf(container, '10.0.0.10')).slice(1, 8)).toEqual([
      'Unknown',
      '10.0.0.10',
      '',
      '--',
      '--',
      '--',
      expect.any(String)
    ]);
    // A favorite the last scan didn't find: listed, grayed, "Not seen".
    expect(cells(rowOf(container, '10.0.0.50'))[3]).toBe('Not seen');
    expect(rowOf(container, '10.0.0.50').classList.contains('lan-dim')).toBe(true);
    expect(rowOf(container, '10.0.0.1').classList.contains('lan-dim')).toBe(false);
  });

  it('draws a star per row with its state and name', () => {
    const { container } = render(HostList);

    const on = starOf(container, '10.0.0.3');
    expect(on.type).toBe('button');
    expect(on.tabIndex).toBe(-1);
    expect(on.getAttribute('aria-pressed')).toBe('true');
    expect(on.getAttribute('aria-label')).toBe('Unfavorite 10.0.0.3');

    const off = starOf(container, '10.0.0.1');
    expect(off.getAttribute('aria-pressed')).toBe('false');
    expect(off.getAttribute('aria-label')).toBe('Favorite 10.0.0.1');
  });

  it('titles the columns and the grid', () => {
    const { container } = render(HostList);
    const { grid } = parts(container);

    expect(grid.getAttribute('aria-label')).toBe('Hosts');
    const titles = [...container.querySelectorAll('.osm-lv-head .osm-colhead')].map(
      (h) => h.getAttribute('aria-label') ?? h.textContent
    );
    expect(titles).toEqual(['Favorite', 'Name', 'IP Address', 'Status', 'Kind', 'Vendor', 'Ports', 'Last Seen']);
    // Balloon Help describes the grid, every header and the sort order
    // button, even while balloons are hidden.
    for (const el of [grid, ...container.querySelectorAll('.osm-colhead, .osm-lv-sortdir')]) {
      expect(el.getAttribute('aria-describedby'), el.className).toBeTruthy();
    }
  });

  it('gives the rows the icon of their kind', () => {
    const { container } = render(HostList);
    const icon = rowOf(container, '10.0.0.2').querySelector('.osm-lv-icon')!;
    expect(icon.getAttribute('aria-label')).toBe('Printer');
  });
});

describe('favorites', () => {
  it('toggles a star on a press without moving the selection', async () => {
    scanStore.setSelectedHost('10.0.0.1');
    const { container } = render(HostList);

    await press(starOf(container, '10.0.0.2'));
    expect(get(scanStore).favoriteIps).toContain('10.0.0.2');
    expect(get(scanStore).selectedHostIp).toBe('10.0.0.1');

    await nextFrame();
    expect(starOf(container, '10.0.0.2').getAttribute('aria-pressed')).toBe('true');
    expect(ipsOf(container)).toEqual(['10.0.0.2', '10.0.0.3', '10.0.0.50', '10.0.0.1', '10.0.0.10']);
    expect(rowOf(container, '10.0.0.1').classList.contains('osm-selected')).toBe(true);
  });

  it('toggles the selected row’s star with Space', async () => {
    scanStore.setSelectedHost('10.0.0.1');
    const { container } = render(HostList);
    const { grid } = parts(container);

    grid.focus();
    await fireEvent.keyDown(grid, { key: ' ' });
    expect(get(scanStore).favoriteIps).toContain('10.0.0.1');

    await nextFrame();
    await fireEvent.keyDown(grid, { key: ' ' });
    expect(get(scanStore).favoriteIps).not.toContain('10.0.0.1');
  });
});

describe('selection and opening', () => {
  it('follows the store’s selection and reports the list’s', async () => {
    const { container } = render(HostList);
    const { scroller } = parts(container);

    scanStore.setSelectedHost('10.0.0.2');
    expect(rowOf(container, '10.0.0.2').getAttribute('aria-selected')).toBe('true');

    // A press on the third row (10.0.0.1), from the top of the (0 px
    // tall) view that selecting scrolled.
    scroller.scrollTop = 0;
    const at = { button: 0, pointerId: 3, pointerType: 'mouse', clientX: 60, clientY: 2 * 19 + 5 };
    await fireEvent.pointerDown(scroller, at);
    await fireEvent.pointerUp(scroller, at);
    expect(get(scanStore).selectedHostIp).toBe('10.0.0.1');
    expect(rowOf(container, '10.0.0.2').getAttribute('aria-selected')).toBe('false');
  });

  it('marks having no listed selection, for the focus ring (WCAG 2.4.7)', async () => {
    const { container } = render(HostList);
    const list = container.querySelector('.lan-list')!;
    expect(list.classList.contains('lan-unselected')).toBe(true);

    scanStore.setSelectedHost('10.0.0.2');
    expect(list.classList.contains('lan-unselected')).toBe(false);

    // Selected, but filtered out of the rows: nothing marks it.
    scanStore.setQuery('router');
    await nextFrame();
    expect(list.classList.contains('lan-unselected')).toBe(true);
  });

  it('opens the selected host on Return and double-click', async () => {
    scanStore.setSelectedHost('10.0.0.2');
    const { container } = render(HostList);
    const { grid, scroller } = parts(container);

    await fireEvent.keyDown(grid, { key: 'Enter' });
    expect(spies.openHost).toHaveBeenCalledWith('10.0.0.2');

    // Selecting scrolled the (0 px tall) view to the row; back to the top.
    scroller.scrollTop = 0;
    await fireEvent.dblClick(scroller, { clientY: 3 * 19 + 5 });
    expect(spies.openHost).toHaveBeenCalledTimes(2);
    expect(spies.openHost).toHaveBeenLastCalledWith('10.0.0.2');
  });

  it('selects by typing a name', async () => {
    const { container } = render(HostList);
    const { grid } = parts(container);

    await fireEvent.keyDown(grid, { key: 'p' });
    expect(get(scanStore).selectedHostIp).toBe('10.0.0.2');
  });
});

describe('sorting', () => {
  it('sorts by a header and reverses with the sort order button', async () => {
    const { container } = render(HostList);

    await fireEvent.click(container.querySelector('[data-column="ip"] > .osm-colhead')!, { detail: 0 });
    expect(get(ui).listSort).toEqual({ column: 'ip', order: 'normal' });
    expect(ipsOf(container)).toEqual(['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.10', '10.0.0.50']);

    await fireEvent.click(container.querySelector('.osm-lv-sortdir')!, { detail: 0 });
    expect(get(ui).listSort).toEqual({ column: 'ip', order: 'reversed' });
    expect(ipsOf(container)).toEqual(['10.0.0.50', '10.0.0.10', '10.0.0.3', '10.0.0.2', '10.0.0.1']);
  });

  it('shows the remembered sort', () => {
    ui.setListSort({ column: 'name', order: 'normal' });
    const { container } = render(HostList);

    expect(container.querySelector('[data-column="name"] > .osm-colhead')!.classList.contains('osm-sorted')).toBe(
      true
    );
    expect(ipsOf(container)).toEqual(['10.0.0.3', '10.0.0.2', '10.0.0.1', '10.0.0.10', '10.0.0.50']);
  });
});

describe('placeholders', () => {
  it('explains an empty list', async () => {
    const { container } = render(HostList);

    scanStore.setQuery('  zzz ');
    await nextFrame();
    expect(rows(container)).toHaveLength(0);
    const empty = container.querySelector<HTMLElement>('.osm-lv-empty')!;
    expect(empty.hidden).toBe(false);
    expect(empty.textContent).toBe('No hosts match “zzz”.');
  });
});

describe('contextual menus', () => {
  it('opens a row’s menu at the pointer, selecting the row', async () => {
    const { container } = render(HostList);
    const label = rowOf(container, '10.0.0.1').querySelector('.osm-lv-label')!;

    await fireEvent.contextMenu(label, { clientX: 70, clientY: 45 });
    expect(get(scanStore).selectedHostIp).toBe('10.0.0.1');
    expect(spies.openHostMenu).toHaveBeenCalledWith('10.0.0.1', { x: 70, y: 45 });
    expect(spies.openViewMenu).not.toHaveBeenCalled();
  });

  it('opens the view’s menu on empty space', async () => {
    const { container } = render(HostList);

    await fireEvent.contextMenu(parts(container).scroller, { clientX: 300, clientY: 400 });
    expect(spies.openViewMenu).toHaveBeenCalledWith({ x: 300, y: 400 });
    expect(spies.openHostMenu).not.toHaveBeenCalled();
  });

  it('answers the keyboard’s request for the selection, else for the view', async () => {
    const { container } = render(HostList);
    const { grid } = parts(container);

    await fireEvent.contextMenu(grid);
    expect(spies.openViewMenu).toHaveBeenCalledTimes(1);

    scanStore.setSelectedHost('10.0.0.2');
    await fireEvent.contextMenu(grid);
    expect(spies.openHostMenu).toHaveBeenCalledWith('10.0.0.2', { x: 0, y: 0 });
  });

  it('opens the menus from the menu key and Shift-F10 itself (WebKit sends no contextmenu)', async () => {
    const { container } = render(HostList);
    const { grid } = parts(container);

    const shiftF10 = new KeyboardEvent('keydown', { key: 'F10', shiftKey: true, bubbles: true, cancelable: true });
    grid.dispatchEvent(shiftF10);
    expect(shiftF10.defaultPrevented).toBe(true);
    expect(spies.openViewMenu).toHaveBeenCalledTimes(1);

    scanStore.setSelectedHost('10.0.0.2');
    await nextFrame();
    grid.dispatchEvent(new KeyboardEvent('keydown', { key: 'ContextMenu', bubbles: true, cancelable: true }));
    expect(spies.openHostMenu).toHaveBeenCalledExactlyOnceWith('10.0.0.2', { x: 0, y: 0 });

    // Chromium also sends a contextmenu event for the key: one menu only.
    await fireEvent.contextMenu(grid);
    expect(spies.openHostMenu).toHaveBeenCalledTimes(1);
    expect(spies.openViewMenu).toHaveBeenCalledTimes(1);
  });

  it('leaves the headers to the page', async () => {
    const { container } = render(HostList);

    await fireEvent.contextMenu(container.querySelector('[data-column="name"] > .osm-colhead')!);
    expect(spies.openHostMenu).not.toHaveBeenCalled();
    expect(spies.openViewMenu).not.toHaveBeenCalled();
  });
});

describe('HostViewApi', () => {
  it('registers while mounted', () => {
    const { container, unmount } = render(HostList);
    expect(get(activeView)?.element).toBe(parts(container).grid);
    expect(get(activeView)?.idealColumnsWidth()).toBe(790);

    unmount();
    expect(get(activeView)).toBeNull();
  });

  it('applies rows still waiting for the frame before revealing', async () => {
    const { container } = render(HostList);
    const { scroller } = parts(container);
    Object.defineProperty(scroller, 'clientHeight', { configurable: true, value: 2 * 19 });

    scanStore.setQuery('printer');
    await nextFrame();
    expect(ipsOf(container)).toEqual(['10.0.0.2']);

    // In one task: the row comes back to the model, and the view shows it.
    scanStore.setQuery('');
    expect(ipsOf(container)).toEqual(['10.0.0.2']);
    get(activeView)!.reveal('10.0.0.10');
    expect(ipsOf(container)).toEqual(DEFAULT_ORDER);
    expect(scroller.scrollTop).toBe(5 * 19 - 2 * 19);
  });

  it('applies waiting rows before focusing and measuring', async () => {
    const { container } = render(HostList);
    const { grid, scroller } = parts(container);
    Object.defineProperty(scroller, 'clientHeight', { configurable: true, value: 2 * 19 });

    scanStore.setQuery('router');
    get(activeView)!.focus();
    expect(ipsOf(container)).toEqual(['10.0.0.1']);
    expect(document.activeElement).toBe(grid);

    scanStore.setQuery('');
    expect(get(activeView)!.extraHeight()).toBe(5 * 19 - 2 * 19);
  });

  it('hands the keyboard to the next view when the view changes', async () => {
    const { container } = render(HostList);
    const next: HostViewApi = { ...get(activeView)!, focus: vi.fn() };
    get(activeView)!.focus();
    expect(document.activeElement).toBe(parts(container).grid);

    // The page swaps the views on Svelte's next update.
    ui.setViewMode('icons');
    activeView.set(next);
    await tick();
    expect(next.focus).toHaveBeenCalledTimes(1);

    // Back, without the keyboard: nothing to hand over.
    (document.activeElement as HTMLElement).blur();
    ui.setViewMode('list');
    await tick();
    expect(next.focus).toHaveBeenCalledTimes(1);
    activeView.set(null);
  });
});

describe('Last Seen', () => {
  it('counts the minutes as they pass', () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] });
    vi.setSystemTime(Date.parse(SEEN) + 30_000);
    const { container } = render(HostList);
    expect(cells(rowOf(container, '10.0.0.1'))[7]).toBe('just now');

    vi.advanceTimersByTime(60_000);
    expect(cells(rowOf(container, '10.0.0.1'))[7]).toBe('1 min ago');
  });
});

// Last: widths stay in ui for the rest of the file.
describe('column widths', () => {
  it('stores every width after a divider drag and builds the columns from them', async () => {
    const first = render(HostList);
    const divider = first.container.querySelector<HTMLElement>('[data-column="name"] .osm-lv-divider')!;

    await fireEvent.pointerDown(divider, { button: 0, pointerId: 9, clientX: 100 });
    await fireEvent.pointerMove(divider, { pointerId: 9, clientX: 130 });
    await fireEvent.pointerUp(divider, { pointerId: 9, clientX: 130 });

    expect(get(ui).columnWidths).toEqual({
      favorite: 22,
      name: 230,
      ip: 100,
      status: 64,
      kind: 124,
      vendor: 112,
      ports: 96,
      lastSeen: 72
    });
    expect(get(activeView)!.idealColumnsWidth()).toBe(820);
    first.unmount();

    render(HostList);
    expect(get(activeView)!.idealColumnsWidth()).toBe(820);
  });
});
