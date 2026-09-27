// Owner: scaffold (spec 8.3); unit D extends it (8.4: the store emits the
// right events). The scaffold's tests cover the launch state only.
import { beforeEach, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import type { ScanEvent } from './scanEvents';

const native = vi.hoisted(() => ({
  listen: vi.fn(async () => () => {}),
  invoke: vi.fn(async (command: string) => (command === 'get_network_interfaces' ? [] : null))
}));

vi.mock('@tauri-apps/api/event', () => ({ listen: native.listen }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: native.invoke }));

/** A store as the page gets it at launch, with its own scanEvents. */
async function freshStore() {
  vi.resetModules();
  const { scanStore } = await import('./scanStore');
  const { scanEvents } = await import('./scanEvents');
  const events: ScanEvent[] = [];
  scanEvents.subscribe((e) => events.push(e));
  return { scanStore, events };
}

beforeEach(() => {
  localStorage.clear();
  native.listen.mockClear();
});

it('reads as loading from launch until init settles', async () => {
  const { scanStore } = await freshStore();
  expect(get(scanStore)).toMatchObject({ loading: true, interfaces: [], error: null });

  const init = scanStore.init();
  expect(get(scanStore).loading).toBe(true);
  await init;

  expect(get(scanStore)).toMatchObject({ loading: false, error: null });
  expect(native.listen).toHaveBeenCalledTimes(5);
  scanStore.destroy();
});

it('reports a listener that fails to attach as an init failure', async () => {
  native.listen.mockRejectedValueOnce(new Error('event plugin unavailable'));
  const { scanStore, events } = await freshStore();

  await expect(scanStore.init()).resolves.toBeUndefined();

  expect(get(scanStore)).toMatchObject({ loading: false, error: 'event plugin unavailable' });
  expect(events).toEqual([{ type: 'init-failed', message: 'event plugin unavailable' }]);
  scanStore.destroy();
});
