import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { WindowManager } from './windowManager';

const native = vi.hoisted(() => ({
  listen: vi.fn(),
  invoke: vi.fn(),
  unlisten: vi.fn()
}));

vi.mock('@tauri-apps/api/window', async (importOriginal) => ({
  ...await importOriginal<typeof import('@tauri-apps/api/window')>(),
  getCurrentWindow: () => ({ listen: native.listen })
}));
vi.mock('@tauri-apps/api/core', () => ({ invoke: native.invoke }));

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

beforeEach(() => {
  vi.resetAllMocks();
  native.listen.mockResolvedValue(native.unlisten);
  native.invoke.mockResolvedValue(true);
});

afterEach(() => vi.restoreAllMocks());

it('reports the startup state when no event arrives first', async () => {
  const onChange = vi.fn();
  const stop = new WindowManager().subscribeActivity(onChange);

  await vi.waitFor(() => expect(onChange).toHaveBeenCalledWith(true));
  expect(native.invoke).toHaveBeenCalledWith('is_window_active');

  stop();
  expect(native.unlisten).toHaveBeenCalledOnce();
});

it('does not overwrite an activity event with a stale initial snapshot', async () => {
  const snapshot = deferred<boolean>();
  native.invoke.mockReturnValue(snapshot.promise);
  const onChange = vi.fn();
  const stop = new WindowManager().subscribeActivity(onChange);
  await vi.waitFor(() => expect(native.invoke).toHaveBeenCalledWith('is_window_active'));

  native.listen.mock.calls[0][1]({ payload: false });
  snapshot.resolve(true);
  await snapshot.promise;

  expect(onChange.mock.calls).toEqual([[false]]);
  stop();
});

it('removes a listener that finishes registering after disposal', async () => {
  const registration = deferred<() => void>();
  native.listen.mockReturnValue(registration.promise);
  const onChange = vi.fn();
  const stop = new WindowManager().subscribeActivity(onChange);
  stop();

  native.listen.mock.calls[0][1]({ payload: false });
  registration.resolve(native.unlisten);
  await registration.promise;

  expect(native.unlisten).toHaveBeenCalledOnce();
  expect(native.invoke).not.toHaveBeenCalled();
  expect(onChange).not.toHaveBeenCalled();
});

it('ignores a pending snapshot and queued events after disposal', async () => {
  const snapshot = deferred<boolean>();
  native.invoke.mockReturnValue(snapshot.promise);
  const onChange = vi.fn();
  const stop = new WindowManager().subscribeActivity(onChange);
  await vi.waitFor(() => expect(native.invoke).toHaveBeenCalled());
  stop();

  snapshot.resolve(false);
  await snapshot.promise;
  native.listen.mock.calls[0][1]({ payload: true });

  expect(native.unlisten).toHaveBeenCalledOnce();
  expect(onChange).not.toHaveBeenCalled();
});

it('keeps listening if the initial query fails', async () => {
  const error = new Error('query failed');
  const report = vi.spyOn(console, 'error').mockImplementation(() => {});
  native.invoke.mockRejectedValue(error);
  const onChange = vi.fn();
  const stop = new WindowManager().subscribeActivity(onChange);
  await vi.waitFor(() => expect(report).toHaveBeenCalledWith(
    'Failed to track window activity:', error
  ));

  native.listen.mock.calls[0][1]({ payload: false });
  expect(onChange).toHaveBeenCalledWith(false);
  stop();
  expect(native.unlisten).toHaveBeenCalledOnce();
});

it('reports registration failures without an unhandled rejection', async () => {
  const error = new Error('listen failed');
  const report = vi.spyOn(console, 'error').mockImplementation(() => {});
  native.listen.mockRejectedValue(error);
  const stop = new WindowManager().subscribeActivity(vi.fn());

  await vi.waitFor(() => expect(report).toHaveBeenCalledWith(
    'Failed to track window activity:', error
  ));
  expect(native.invoke).not.toHaveBeenCalled();
  stop();
});
