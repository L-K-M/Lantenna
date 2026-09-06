import { fireEvent, render, waitFor } from '@testing-library/svelte';
import { beforeEach, expect, it, vi } from 'vitest';
import Page from './+page.svelte';
import { windowFocused } from '$lib/util/windowState';

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
      // Linux's move grab takes keyboard focus, not active decorations.
      listeners.get('tauri://blur')?.({ payload: false });
    })
  };
});

vi.mock('@tauri-apps/api/window', async (importOriginal) => ({
  ...await importOriginal<typeof import('@tauri-apps/api/window')>(),
  getCurrentWindow: () => ({
    listen: native.listen,
    onFocusChanged: async (callback: (event: { payload: boolean }) => void) => {
      const unlistenBlur = await native.listen('tauri://blur', callback);
      const unlistenFocus = await native.listen('tauri://focus', callback);
      return () => { unlistenBlur(); unlistenFocus(); };
    },
    startDragging: native.startDragging
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
  expect(document.querySelector('.window-frame')).toBeNull();
  expect(native.listeners.size).toBe(0);

  native.startDragging.mockClear();
  native.active = true;
  windowFocused.set(true);
});

it('keeps the title bar active during a native Linux drag', async () => {
  const { container } = render(Page);
  const titleBar = container.querySelector('.title-bar')!;
  await waitFor(() => expect(native.listeners.size).toBeGreaterThan(0));

  await fireEvent.mouseDown(titleBar, { button: 0 });

  expect(native.startDragging).toHaveBeenCalledOnce();
  expect(titleBar.classList.contains('unfocused')).toBe(false);
  expect(container.querySelector('.window-unfocused')).toBeNull();
});

it('shows genuine deactivation and reactivation, including during a drag', async () => {
  const { container } = render(Page);
  const titleBar = container.querySelector('.title-bar')!;
  await waitFor(() => expect(native.listeners.size).toBeGreaterThan(0));
  await fireEvent.mouseDown(titleBar, { button: 0 });

  native.listeners.get('window-activity-changed')?.({ payload: false });
  await waitFor(() => expect(titleBar.classList.contains('unfocused')).toBe(true));

  native.listeners.get('window-activity-changed')?.({ payload: true });
  await waitFor(() => expect(titleBar.classList.contains('unfocused')).toBe(false));
});

it('reads the initial inactive state without waiting for a focus event', async () => {
  native.active = false;
  const { container } = render(Page);

  await waitFor(() => expect(container.querySelector('.window-unfocused')).not.toBeNull());
});
