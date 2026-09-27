// Owner: unit A (spec 8.4, 8.5). The page's window: Osmium's chrome
// around the regions, activity from the backend, and the boxes' window
// ops on a mocked Tauri window (spec 2.10, 8.5).
import { fireEvent, render, waitFor } from '@testing-library/svelte';
import { LogicalPosition, LogicalSize, type Monitor } from '@tauri-apps/api/window';
import { getAppearance, setAppearance } from 'osmium-ui';
import { flushSync } from 'svelte';
import { get } from 'svelte/store';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ui } from '$lib/app/ui';
import { activeView, type HostViewApi } from '$lib/app/views';
import type { SystemColors } from '$lib/types';
import { windowManager } from '$lib/windowManager';
import Page from './+page.svelte';

const DEFAULT_APPEARANCE = getAppearance();

const native = vi.hoisted(() => {
  const listeners = new Map<string, (event: { payload: boolean }) => void>();
  const listen = vi.fn(async (event: string, callback: (event: { payload: boolean }) => void) => {
    listeners.set(event, callback);
    return () => { listeners.delete(event); };
  });
  return {
    listeners,
    listen,
    active: true,
    startDragging: vi.fn(async () => {
      // Linux's move grab takes keyboard focus, not active decorations:
      // the page loses focus, the backend sends no activity change.
      vi.spyOn(document, 'hasFocus').mockReturnValue(false);
      listeners.get('tauri://blur')?.({ payload: false });
      window.dispatchEvent(new Event('blur'));
    }),
    close: vi.fn(async () => {}),
    // The window follows setSize and setPosition, as a real one does.
    position: { x: 100, y: 80 },
    setSize: vi.fn(async (size: { width: number; height: number }) => {
      (window as unknown as HappyWindow).happyDOM.setViewport({ width: size.width, height: size.height });
    }),
    setMinSize: vi.fn(async () => {}),
    setPosition: vi.fn(async (at: { x: number; y: number }) => {
      native.position = { x: at.x, y: at.y };
    }),
    startResizeDragging: vi.fn(async () => {}),
    /** get_system_colors: Linux reports no accent. */
    colors: null as SystemColors | null,
    /** A 1440 x 900 screen with a 25 px menu bar. */
    monitor: {
      name: 'Built-in',
      scaleFactor: 1,
      size: { width: 1440, height: 900 },
      position: { x: 0, y: 0 },
      workArea: { position: { x: 0, y: 25 }, size: { width: 1440, height: 875 } }
    } as unknown as Monitor
  };
});

interface HappyWindow {
  happyDOM: { setViewport(v: { width: number; height: number }): void };
}

vi.mock('@tauri-apps/api/window', async (importOriginal) => ({
  ...await importOriginal<typeof import('@tauri-apps/api/window')>(),
  getCurrentWindow: () => ({
    listen: native.listen,
    startDragging: native.startDragging,
    close: native.close,
    setSize: native.setSize,
    setMinSize: native.setMinSize,
    setPosition: native.setPosition,
    startResizeDragging: native.startResizeDragging,
    scaleFactor: async () => 1,
    outerPosition: async () => native.position
  }),
  currentMonitor: async () => native.monitor
}));

vi.mock('@tauri-apps/api/event', () => ({ listen: native.listen }));
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(async (command: string) => {
    if (command === 'is_window_active') return native.active;
    if (command === 'get_network_interfaces') return [];
    if (command === 'get_system_colors') return native.colors;
    // get_scan_results, check_self_update: nothing to report.
    return null;
  })
}));

beforeEach(() => {
  // svelteTesting() must clean up even with Vitest globals disabled.
  expect(document.querySelector('.osm-page-window')).toBeNull();
  expect(native.listeners.size).toBe(0);

  vi.restoreAllMocks();
  native.startDragging.mockClear();
  native.close.mockClear();
  native.active = true;

  // The window as Tauri opens it. The window manager is shared by all
  // tests; every test that folds the window unfolds it again.
  (window as unknown as HappyWindow).happyDOM.setViewport({ width: 1200, height: 760 });
  native.position = { x: 100, y: 80 };
  native.colors = null;
  for (const call of [native.setSize, native.setMinSize, native.setPosition, native.startResizeDragging]) {
    call.mockClear();
  }
});

afterEach(() => {
  activeView.set(null);
  setAppearance(DEFAULT_APPEARANCE);
});

function mountedWindow(container: HTMLElement): HTMLElement {
  return container.querySelector<HTMLElement>('.osm-page-window.osm-window')!;
}

it('hosts an Osmium window around the regions', async () => {
  const { container } = render(Page);
  const win = mountedWindow(container);
  await waitFor(() => expect(native.listeners.has('window-activity-changed')).toBe(true));

  expect(win.querySelector('.osm-titlebar')).not.toBeNull();
  expect(win.querySelector('.osm-title')?.textContent).toBe('Lantenna');
  for (const box of ['.osm-close', '.osm-zoom', '.osm-collapse', '.osm-grow']) {
    expect(win.querySelector(box), box).not.toBeNull();
  }

  const content = win.querySelector('.osm-content.lan-content')!;
  for (const region of ['.lan-strip', '.lan-header', '.lan-main .lan-view', '.lan-main .lan-pane']) {
    expect(content.querySelector(region), region).not.toBeNull();
  }
  expect(content.querySelector('.lan-view .lan-list')).not.toBeNull();
});

it('keeps the window active during a native Linux drag', async () => {
  const { container } = render(Page);
  const win = mountedWindow(container);
  await waitFor(() => expect(native.listeners.has('window-activity-changed')).toBe(true));

  await fireEvent.pointerDown(win.querySelector('.osm-titlebar')!, { button: 0, pointerId: 1 });

  expect(native.startDragging).toHaveBeenCalledOnce();
  expect(win.classList.contains('osm-inactive')).toBe(false);
});

it('follows the backend’s activity changes', async () => {
  const { container } = render(Page);
  const win = mountedWindow(container);
  await waitFor(() => expect(native.listeners.has('window-activity-changed')).toBe(true));

  native.listeners.get('window-activity-changed')!({ payload: false });
  expect(win.classList.contains('osm-inactive')).toBe(true);

  native.listeners.get('window-activity-changed')!({ payload: true });
  expect(win.classList.contains('osm-inactive')).toBe(false);
});

it('reads the initial inactive state without waiting for an event', async () => {
  native.active = false;
  const { container } = render(Page);

  await waitFor(() => expect(mountedWindow(container).classList.contains('osm-inactive')).toBe(true));
});

it('never closes the window on Escape', async () => {
  const apply = vi.spyOn(windowManager, 'apply');
  const { container } = render(Page);
  await waitFor(() => expect(native.listeners.has('window-activity-changed')).toBe(true));

  await fireEvent.keyDown(document.body, { key: 'Escape' });
  await new Promise((resolve) => setTimeout(resolve, 10));

  expect(apply).not.toHaveBeenCalledWith({ op: 'winClose' });
  expect(native.close).not.toHaveBeenCalled();
  expect(mountedWindow(container).isConnected).toBe(true);
});

it('closes the window from the close box', async () => {
  const { container } = render(Page);

  await fireEvent.click(mountedWindow(container).querySelector('.osm-close')!, { detail: 0 });

  expect(native.close).toHaveBeenCalledOnce();
});

it('folds to the title bar from the collapse box and unfolds again', async () => {
  const { container } = render(Page);
  const win = mountedWindow(container);
  await waitFor(() => expect(native.listeners.has('window-activity-changed')).toBe(true));

  // hostWindow's startup winShade { on: false } finds nothing to undo.
  expect(native.setSize).not.toHaveBeenCalled();
  expect(native.setMinSize).not.toHaveBeenCalled();

  const collapse = win.querySelector('.osm-collapse')!;
  await fireEvent.click(collapse, { detail: 0 });

  expect(win.classList.contains('osm-shaded')).toBe(true);
  expect(get(ui).shaded).toBe(true);
  await waitFor(() => expect(native.setSize).toHaveBeenCalledWith(new LogicalSize(1200, 23)));
  expect(native.setMinSize).toHaveBeenCalledWith(null);
  expect(native.setMinSize.mock.invocationCallOrder[0]).toBeLessThan(native.setSize.mock.invocationCallOrder[0]);

  await fireEvent.click(collapse, { detail: 0 });

  expect(win.classList.contains('osm-shaded')).toBe(false);
  expect(get(ui).shaded).toBe(false);
  await waitFor(() => expect(native.setMinSize).toHaveBeenLastCalledWith(new LogicalSize(840, 560)));
  expect(native.setSize).toHaveBeenLastCalledWith(new LogicalSize(1200, 760));
});

it('zooms to show every host and back from the zoom box', async () => {
  const { container } = render(Page);
  const zoom = mountedWindow(container).querySelector('.osm-zoom')!;
  const view: HostViewApi = {
    element: document.createElement('div'),
    focus() {},
    reveal() {},
    extraHeight: () => 1000,
    idealColumnsWidth: () => 790
  };
  activeView.set(view);

  await fireEvent.click(zoom, { detail: 0 });

  // Every column and the pane (1119 wide), as tall as the screen allows:
  // the window moves up under the menu bar first.
  await waitFor(() => expect(native.setSize).toHaveBeenCalledWith(new LogicalSize(1119, 875)));
  expect(native.setPosition).toHaveBeenCalledWith(new LogicalPosition(100, 25));

  await fireEvent.click(zoom, { detail: 0 });

  await waitFor(() => expect(native.setPosition).toHaveBeenLastCalledWith(new LogicalPosition(100, 80)));
  expect(native.setSize).toHaveBeenLastCalledWith(new LogicalSize(1200, 760));
});

it('resizes from the grow box through the OS on Linux', async () => {
  const { container } = render(Page);

  await fireEvent.pointerDown(mountedWindow(container).querySelector('.osm-grow')!, { button: 0, pointerId: 1 });

  expect(native.startResizeDragging).toHaveBeenCalledExactlyOnceWith('SouthEast');
});

it('re-reads the system accent whenever the window becomes active', async () => {
  const { container } = render(Page);
  await waitFor(() => expect(native.listeners.has('window-activity-changed')).toBe(true));
  expect(getAppearance()).toEqual(DEFAULT_APPEARANCE);

  // The user picks the Green accent while another app is in front.
  native.listeners.get('window-activity-changed')!({ payload: false });
  native.colors = {
    accent_color: '#62BA46',
    accent_text_color: '#000000',
    highlight_color: '#c8e6bd',
    highlight_text_color: '#000000'
  };
  native.listeners.get('window-activity-changed')!({ payload: true });

  await waitFor(() => expect(getAppearance().accent).toEqual({ release: '8.5', name: 'Emerald' }));
  expect(getAppearance().highlight).toEqual({ release: '8.5', name: 'Green' });
  expect(mountedWindow(container).classList.contains('osm-inactive')).toBe(false);
});

/** Chromium fires focusout (relatedTarget null) when the focused element
 * leaves the page, as when Svelte removes a view; happy-dom fires none.
 * Returns the undo. */
function loseFocusOnRemoval(): () => void {
  const remove = Element.prototype.remove;
  Element.prototype.remove = function (this: Element) {
    const focused = document.activeElement;
    if (focused instanceof HTMLElement && this.contains(focused)) {
      focused.dispatchEvent(new FocusEvent('focusout', { bubbles: true, relatedTarget: null }));
    }
    remove.call(this);
  };
  return () => {
    Element.prototype.remove = remove;
  };
}

it('switches from icons back to the list while the icon grid has the keyboard', async () => {
  ui.setViewMode('icons');
  const { container } = render(Page);
  const undo = loseFocusOnRemoval();
  try {
    const grid = await waitFor(() => container.querySelector<HTMLElement>('.lan-icons [role=listbox]')!);
    grid.focus();

    // The icon view's DOM goes while Svelte updates the page: the focus
    // it takes along must not write the command context's stores then
    // (state_unsafe_mutation, which left the icon view on screen).
    ui.setViewMode('list');
    expect(() => flushSync()).not.toThrow();
    expect(container.querySelector('.lan-view .lan-list')).not.toBeNull();
    expect(container.querySelector('.lan-view .lan-icons')).toBeNull();
  } finally {
    undo();
    ui.setViewMode('list');
  }
});
