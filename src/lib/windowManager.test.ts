// Owner: unit A (spec 8.4, 8.5). The six activity tests are kept from
// before the port unchanged; the window ops of spec 2.10 follow them.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LogicalPosition, LogicalSize, type Monitor } from '@tauri-apps/api/window';
import { ui } from '$lib/app/ui';
import { activeView, type HostViewApi } from '$lib/app/views';
import { WindowManager } from './windowManager';

const native = vi.hoisted(() => ({
  listen: vi.fn(),
  invoke: vi.fn(),
  unlisten: vi.fn(),
  startDragging: vi.fn(),
  close: vi.fn(),
  setSize: vi.fn(),
  setMinSize: vi.fn(),
  setPosition: vi.fn(),
  startResizeDragging: vi.fn(),
  scaleFactor: vi.fn(),
  outerPosition: vi.fn(),
  currentMonitor: vi.fn()
}));

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
    scaleFactor: native.scaleFactor,
    outerPosition: native.outerPosition
  }),
  currentMonitor: native.currentMonitor
}));
vi.mock('@tauri-apps/api/core', () => ({ invoke: native.invoke }));

/** The page fills the window, so the viewport is the window's logical
 * inner size. happy-dom fires `resize` when it changes. */
function setViewport(width: number, height: number) {
  (window as unknown as { happyDOM: { setViewport(v: { width: number; height: number }): void } })
    .happyDOM.setViewport({ width, height });
}

/** A 1440 x 900 screen with a 25 px menu bar, in physical pixels. */
function monitor(scale: number): Monitor {
  return {
    name: 'Built-in',
    scaleFactor: scale,
    size: { width: 1440 * scale, height: 900 * scale },
    position: { x: 0, y: 0 },
    workArea: {
      position: { x: 0, y: 25 * scale },
      size: { width: 1440 * scale, height: 875 * scale }
    }
  } as Monitor;
}

/** Makes setSize resize the viewport, as the real window does. */
function followSetSize() {
  native.setSize.mockImplementation(async (size: LogicalSize) => setViewport(size.width, size.height));
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

beforeEach(() => {
  vi.resetAllMocks();
  native.listen.mockResolvedValue(native.unlisten);
  native.invoke.mockResolvedValue(true);
  native.startDragging.mockResolvedValue(undefined);
  native.close.mockResolvedValue(undefined);
  native.setSize.mockResolvedValue(undefined);
  native.setMinSize.mockResolvedValue(undefined);
  native.setPosition.mockResolvedValue(undefined);
  native.startResizeDragging.mockResolvedValue(undefined);
  native.scaleFactor.mockResolvedValue(1);
  native.outerPosition.mockResolvedValue({ x: 100, y: 80 });
  native.currentMonitor.mockResolvedValue(monitor(1));
  setViewport(1200, 760);
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

it('starts a window drag within the press, before anything is awaited', () => {
  new WindowManager().apply({ op: 'dragWindow' });

  expect(native.startDragging).toHaveBeenCalledOnce();
});

it('closes the window and reports a refused close', async () => {
  const error = new Error('close refused');
  const report = vi.spyOn(console, 'error').mockImplementation(() => {});
  native.close.mockRejectedValue(error);

  new WindowManager().apply({ op: 'winClose' });

  expect(native.close).toHaveBeenCalledOnce();
  await vi.waitFor(() => expect(report).toHaveBeenCalledWith('Failed to close the window:', error));
});

describe('collapse box (winShade)', () => {
  it('does nothing for hostWindow’s startup unfold', async () => {
    new WindowManager().apply({ op: 'winShade', on: false });
    await new Promise((resolve) => setTimeout(resolve));

    expect(native.setSize).not.toHaveBeenCalled();
    expect(native.setMinSize).not.toHaveBeenCalled();
  });

  it('lifts the minimum size, then folds to the 23 px title bar', async () => {
    new WindowManager().apply({ op: 'winShade', on: true });

    await vi.waitFor(() => expect(native.setSize).toHaveBeenCalledWith(new LogicalSize(1200, 23)));
    expect(native.setMinSize).toHaveBeenCalledWith(null);
    expect(native.setMinSize.mock.invocationCallOrder[0]).toBeLessThan(
      native.setSize.mock.invocationCallOrder[0]
    );
  });

  it('folds once for a repeated fold', async () => {
    const manager = new WindowManager();
    followSetSize();
    manager.apply({ op: 'winShade', on: true });
    manager.apply({ op: 'winShade', on: true });
    await vi.waitFor(() => expect(native.setSize).toHaveBeenCalled());
    await new Promise((resolve) => setTimeout(resolve));

    expect(native.setSize).toHaveBeenCalledOnce();
  });

  it('unfolds to the saved height, then puts the minimum size back', async () => {
    const manager = new WindowManager();
    followSetSize();
    manager.apply({ op: 'winShade', on: true });
    await vi.waitFor(() => expect(window.innerHeight).toBe(23));

    manager.apply({ op: 'winShade', on: false });

    await vi.waitFor(() => expect(native.setMinSize).toHaveBeenLastCalledWith(new LogicalSize(840, 560)));
    expect(native.setSize).toHaveBeenLastCalledWith(new LogicalSize(1200, 760));
    expect(native.setSize.mock.invocationCallOrder[1]).toBeLessThan(
      native.setMinSize.mock.invocationCallOrder[1]
    );
  });

  it('restores the minimum size only once the window has grown', async () => {
    const manager = new WindowManager();
    followSetSize();
    manager.apply({ op: 'winShade', on: true });
    await vi.waitFor(() => expect(window.innerHeight).toBe(23));
    // macOS: the size change lands later than the call returns.
    native.setSize.mockResolvedValue(undefined);

    manager.apply({ op: 'winShade', on: false });
    await vi.waitFor(() => expect(native.setSize).toHaveBeenCalledTimes(2));
    await new Promise((resolve) => setTimeout(resolve));
    expect(native.setMinSize).toHaveBeenCalledOnce();

    setViewport(1200, 760);
    await vi.waitFor(() => expect(native.setMinSize).toHaveBeenCalledTimes(2));
  });

  it('restores the minimum size anyway when the window never grows', async () => {
    const manager = new WindowManager();
    followSetSize();
    manager.apply({ op: 'winShade', on: true });
    await vi.waitFor(() => expect(window.innerHeight).toBe(23));
    native.setSize.mockResolvedValue(undefined);
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });

    try {
      manager.apply({ op: 'winShade', on: false });
      await vi.waitFor(() => expect(native.setSize).toHaveBeenCalledTimes(2));
      expect(native.setMinSize).toHaveBeenCalledOnce();

      await vi.advanceTimersByTimeAsync(1000);
      expect(native.setMinSize).toHaveBeenLastCalledWith(new LogicalSize(840, 560));
    } finally {
      vi.useRealTimers();
    }
  });

  it('restores the minimum size even when the unfold fails', async () => {
    const report = vi.spyOn(console, 'error').mockImplementation(() => {});
    const manager = new WindowManager();
    manager.apply({ op: 'winShade', on: true });
    await vi.waitFor(() => expect(native.setSize).toHaveBeenCalledOnce());
    const error = new Error('size refused');
    native.setSize.mockRejectedValue(error);

    manager.apply({ op: 'winShade', on: false });

    await vi.waitFor(() => expect(report).toHaveBeenCalledWith('Failed to expand the window:', error));
    expect(native.setMinSize).toHaveBeenLastCalledWith(new LogicalSize(840, 560));
  });

  it('keeps a width the window got while folded', async () => {
    const manager = new WindowManager();
    followSetSize();
    manager.apply({ op: 'winShade', on: true });
    await vi.waitFor(() => expect(window.innerHeight).toBe(23));
    setViewport(1000, 23);

    manager.apply({ op: 'winShade', on: false });

    await vi.waitFor(() => expect(native.setSize).toHaveBeenLastCalledWith(new LogicalSize(1000, 760)));
  });

  it('unfolds a window a page reload left folded', async () => {
    followSetSize();
    setViewport(1200, 23);

    new WindowManager().apply({ op: 'winShade', on: false });

    await vi.waitFor(() => expect(native.setMinSize).toHaveBeenCalledWith(new LogicalSize(840, 560)));
    expect(native.setSize).toHaveBeenCalledWith(new LogicalSize(1200, 560));
  });

  it('unfolds when the OS makes the folded window tall again', async () => {
    const manager = new WindowManager();
    const stop = manager.watchResize();
    followSetSize();
    manager.apply({ op: 'winShade', on: true });
    await vi.waitFor(() => expect(window.innerHeight).toBe(23));

    setViewport(1200, 400); // a Linux edge resize

    await vi.waitFor(() => expect(native.setMinSize).toHaveBeenLastCalledWith(new LogicalSize(840, 560)));
    native.setSize.mockClear();
    manager.apply({ op: 'winShade', on: false });
    await new Promise((resolve) => setTimeout(resolve));
    expect(native.setSize).not.toHaveBeenCalled();
    stop();
  });

  it('ignores resizes that don’t unfold the window', async () => {
    const manager = new WindowManager();
    const stop = manager.watchResize();
    manager.apply({ op: 'winShade', on: true });
    await vi.waitFor(() => expect(native.setSize).toHaveBeenCalledOnce());

    // Tall to tall: an event from before the fold landed.
    setViewport(1100, 760);
    await new Promise((resolve) => setTimeout(resolve));

    expect(native.setMinSize).toHaveBeenCalledOnce();
    stop();
  });
});

describe('zoom box (winZoom)', () => {
  const listView = (extraHeight: number): HostViewApi => ({
    element: document.createElement('div'),
    focus() {},
    reveal() {},
    extraHeight: () => extraHeight,
    idealColumnsWidth: () => 790
  });

  afterEach(() => {
    activeView.set(null);
    ui.setInfoPane(true);
  });

  it('goes to the size that shows every column and row, and back', async () => {
    const manager = new WindowManager();
    followSetSize();
    activeView.set(listView(60)); // 80 + 820 just reaches the bottom edge

    manager.apply({ op: 'winZoom' });
    await vi.waitFor(() => expect(native.setSize).toHaveBeenCalledWith(new LogicalSize(1119, 820)));
    expect(native.setPosition).not.toHaveBeenCalled();

    manager.apply({ op: 'winZoom' });
    await vi.waitFor(() => expect(native.setSize).toHaveBeenLastCalledWith(new LogicalSize(1200, 760)));
  });

  it('moves up to fit the work area before growing, and back after shrinking', async () => {
    const manager = new WindowManager();
    followSetSize();
    native.setPosition.mockImplementation(async (p: LogicalPosition) => {
      native.outerPosition.mockResolvedValue({ x: p.x, y: p.y });
    });
    activeView.set(listView(2000));

    manager.apply({ op: 'winZoom' });
    await vi.waitFor(() => expect(native.setSize).toHaveBeenCalledWith(new LogicalSize(1119, 875)));
    expect(native.setPosition).toHaveBeenCalledWith(new LogicalPosition(100, 25));
    expect(native.setPosition.mock.invocationCallOrder[0]).toBeLessThan(
      native.setSize.mock.invocationCallOrder[0]
    );

    manager.apply({ op: 'winZoom' });
    await vi.waitFor(() => expect(native.setPosition).toHaveBeenLastCalledWith(new LogicalPosition(100, 80)));
    expect(native.setSize).toHaveBeenLastCalledWith(new LogicalSize(1200, 760));
    expect(native.setSize.mock.invocationCallOrder[1]).toBeLessThan(
      native.setPosition.mock.invocationCallOrder[1]
    );
  });

  it('works in logical pixels on a Retina screen', async () => {
    native.scaleFactor.mockResolvedValue(2);
    native.outerPosition.mockResolvedValue({ x: 200, y: 160 });
    native.currentMonitor.mockResolvedValue(monitor(2));
    activeView.set(listView(2000));

    new WindowManager().apply({ op: 'winZoom' });

    await vi.waitFor(() => expect(native.setSize).toHaveBeenCalledWith(new LogicalSize(1119, 875)));
    expect(native.setPosition).toHaveBeenCalledWith(new LogicalPosition(100, 25));
  });

  it('leaves out the pane when it is hidden, down to the minimum width', async () => {
    ui.setInfoPane(false);
    activeView.set(listView(0));

    new WindowManager().apply({ op: 'winZoom' });

    await vi.waitFor(() => expect(native.setSize).toHaveBeenCalledWith(new LogicalSize(840, 760)));
  });

  it('keeps the width in icon view and without a view', async () => {
    new WindowManager().apply({ op: 'winZoom' });

    await vi.waitFor(() => expect(native.setSize).toHaveBeenCalledWith(new LogicalSize(1200, 760)));
  });

  it('zooms in place where the window can’t be moved (Wayland)', async () => {
    const report = vi.spyOn(console, 'error').mockImplementation(() => {});
    const error = new Error('not supported');
    native.setPosition.mockRejectedValue(error);
    activeView.set(listView(2000));

    new WindowManager().apply({ op: 'winZoom' });

    await vi.waitFor(() => expect(native.setSize).toHaveBeenCalledWith(new LogicalSize(1119, 875)));
    expect(report).toHaveBeenCalledWith('Failed to move the window:', error);
  });

  it('does nothing while the window is folded', async () => {
    const manager = new WindowManager();
    manager.apply({ op: 'winShade', on: true });
    await vi.waitFor(() => expect(native.setSize).toHaveBeenCalledOnce());

    manager.apply({ op: 'winZoom' });
    await new Promise((resolve) => setTimeout(resolve));

    expect(native.setSize).toHaveBeenCalledOnce();
    expect(native.outerPosition).not.toHaveBeenCalled();
  });

  it('reports a zoom that can’t read the window’s place', async () => {
    const report = vi.spyOn(console, 'error').mockImplementation(() => {});
    const error = new Error('no monitor');
    native.currentMonitor.mockRejectedValue(error);

    new WindowManager().apply({ op: 'winZoom' });

    await vi.waitFor(() => expect(report).toHaveBeenCalledWith('Failed to zoom the window:', error));
    expect(native.setSize).not.toHaveBeenCalled();
  });
});

describe('grow box (winGrow)', () => {
  function frameWithGrip() {
    const frame = document.createElement('div');
    const grip = document.createElement('div');
    grip.className = 'osm-grow';
    frame.append(grip);
    document.body.append(frame);
    return { frame, grip };
  }

  const nextFrame = () => new Promise((resolve) => requestAnimationFrame(resolve));
  const pointer = (type: string, init: PointerEventInit) =>
    new PointerEvent(type, { bubbles: true, pointerId: 7, button: 0, buttons: 1, ...init });

  afterEach(() => {
    document.body.replaceChildren();
  });

  it('starts the OS resize drag within the press (Linux)', () => {
    new WindowManager().apply({ op: 'winGrow' });

    expect(native.startResizeDragging).toHaveBeenCalledExactlyOnceWith('SouthEast');
  });

  it('follows the pointer with setSize, never below the minimum (macOS)', async () => {
    const manager = new WindowManager();
    const { frame, grip } = frameWithGrip();
    const stop = manager.trackGrow(frame);

    grip.dispatchEvent(pointer('pointerdown', { screenX: 500, screenY: 400 }));
    manager.apply({ op: 'winGrow' });
    expect(native.startResizeDragging).not.toHaveBeenCalled();
    expect(grip.hasPointerCapture(7)).toBe(true);

    window.dispatchEvent(pointer('pointermove', { screenX: 600, screenY: 450 }));
    await nextFrame();
    await vi.waitFor(() => expect(native.setSize).toHaveBeenLastCalledWith(new LogicalSize(1300, 810)));

    window.dispatchEvent(pointer('pointermove', { screenX: 0, screenY: 0 }));
    await nextFrame();
    await vi.waitFor(() => expect(native.setSize).toHaveBeenLastCalledWith(new LogicalSize(840, 560)));

    window.dispatchEvent(pointer('pointerup', { screenX: 0, screenY: 0, buttons: 0 }));
    window.dispatchEvent(pointer('pointermove', { screenX: 900, screenY: 900 }));
    await nextFrame();
    expect(native.setSize).toHaveBeenCalledTimes(2);
    expect(grip.hasPointerCapture(7)).toBe(false);
    stop();
  });

  it('sends one size at a time and always the last one', async () => {
    const manager = new WindowManager();
    const { frame, grip } = frameWithGrip();
    const stop = manager.trackGrow(frame);
    const first = deferred<void>();
    native.setSize.mockReturnValueOnce(first.promise);

    grip.dispatchEvent(pointer('pointerdown', { screenX: 500, screenY: 400 }));
    manager.apply({ op: 'winGrow' });
    window.dispatchEvent(pointer('pointermove', { screenX: 510, screenY: 400 }));
    await nextFrame();
    window.dispatchEvent(pointer('pointermove', { screenX: 520, screenY: 400 }));
    await nextFrame();
    window.dispatchEvent(pointer('pointermove', { screenX: 530, screenY: 400 }));
    window.dispatchEvent(pointer('pointerup', { screenX: 530, screenY: 400, buttons: 0 }));
    await nextFrame();
    expect(native.setSize).toHaveBeenCalledOnce();

    first.resolve();
    await vi.waitFor(() => expect(native.setSize).toHaveBeenLastCalledWith(new LogicalSize(1230, 760)));
    expect(native.setSize).toHaveBeenCalledTimes(2);
    stop();
  });

  it('ends the grow on a move without the button', async () => {
    const manager = new WindowManager();
    const { frame, grip } = frameWithGrip();
    const stop = manager.trackGrow(frame);

    grip.dispatchEvent(pointer('pointerdown', { screenX: 500, screenY: 400 }));
    manager.apply({ op: 'winGrow' });
    window.dispatchEvent(pointer('pointermove', { screenX: 700, screenY: 500, buttons: 0 }));
    await nextFrame();

    expect(native.setSize).not.toHaveBeenCalled();
    stop();
  });

  it('stops following when the page goes away mid-grow', async () => {
    const manager = new WindowManager();
    const { frame, grip } = frameWithGrip();
    const stop = manager.trackGrow(frame);
    grip.dispatchEvent(pointer('pointerdown', { screenX: 500, screenY: 400 }));
    manager.apply({ op: 'winGrow' });

    stop();
    window.dispatchEvent(pointer('pointermove', { screenX: 700, screenY: 500 }));
    await nextFrame();

    expect(native.setSize).not.toHaveBeenCalled();
  });

  it('does nothing while the window is folded', async () => {
    const manager = new WindowManager();
    manager.apply({ op: 'winShade', on: true });

    manager.apply({ op: 'winGrow' });

    expect(native.startResizeDragging).not.toHaveBeenCalled();
  });
});
