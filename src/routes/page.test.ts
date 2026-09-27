// Owner: unit A (spec 8.4, 8.5). Scaffold version: the window mounts,
// drags and follows the backend's activity; unit A adds the rest of 8.5.
import { fireEvent, render, waitFor } from '@testing-library/svelte';
import { beforeEach, expect, it, vi } from 'vitest';
import Page from './+page.svelte';

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
    close: vi.fn(async () => {})
  };
});

vi.mock('@tauri-apps/api/window', async (importOriginal) => ({
  ...await importOriginal<typeof import('@tauri-apps/api/window')>(),
  getCurrentWindow: () => ({
    listen: native.listen,
    startDragging: native.startDragging,
    close: native.close
  })
}));

vi.mock('@tauri-apps/api/event', () => ({ listen: native.listen }));
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(async (command: string) => {
    if (command === 'is_window_active') return native.active;
    if (command === 'get_network_interfaces') return [];
    // get_scan_results, get_system_colors, check_self_update: nothing to report.
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
