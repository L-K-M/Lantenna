// Owner: unit D (spec 8.4). Spec: 5.1 to 5.5 (alert queue, host notes,
// lastError, scan events).
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import type { AlertOptions, AlertResult, HostedWindow, OsmiumAlert, OsmiumWindow } from 'osmium-ui';
import { formatClock } from '$lib/util/format';

interface FakeAlert extends OsmiumAlert {
  options: AlertOptions;
  press(r: AlertResult): void;
}

const osm = vi.hoisted(() => ({
  alerts: [] as FakeAlert[],
  real: null as null | ((o: AlertOptions) => OsmiumAlert),
  showAlert: vi.fn()
}));

vi.mock('osmium-ui', async (importOriginal) => {
  const actual = await importOriginal<typeof import('osmium-ui')>();
  osm.real = actual.showAlert;
  return { ...actual, showAlert: osm.showAlert };
});

function fakeShowAlert(options: AlertOptions): OsmiumAlert {
  let resolve!: (r: AlertResult) => void;
  const result = new Promise<AlertResult>((r) => {
    resolve = r;
  });
  const alert: FakeAlert = {
    element: document.createElement('div'),
    result,
    options,
    press: (r) => resolve(r),
    close: vi.fn((button?: AlertResult) => resolve(button ?? 'dismissed'))
  };
  osm.alerts.push(alert);
  return alert;
}

function fakeWindow(shaded = false) {
  const element = document.createElement('div');
  const window: OsmiumWindow = {
    element,
    content: element,
    setTitle: vi.fn(),
    setShaded: vi.fn(),
    setActive: vi.fn(),
    destroy: vi.fn()
  };
  const hosted = {
    window,
    shaded,
    setShaded: vi.fn((on: boolean) => {
      hosted.shaded = on;
    }),
    close: vi.fn(),
    destroy: vi.fn()
  };
  return hosted satisfies HostedWindow;
}

/** feedback.ts and the stores it reads, fresh for each test (the queue
 * and the notes are module state). */
async function load() {
  vi.resetModules();
  const feedback = await import('./feedback');
  const { scanEvents } = await import('$lib/util/scanEvents');
  const { scanProgress, scanStore } = await import('$lib/util/scanStore');
  return { ...feedback, scanEvents, scanProgress, scanStore };
}

/** Let promise callbacks (an alert's result) run. */
const settle = () => new Promise((r) => setTimeout(r, 0));

let dispose: (() => void) | null = null;

beforeEach(() => {
  osm.alerts = [];
  osm.showAlert.mockReset();
  osm.showAlert.mockImplementation(fakeShowAlert);
});

afterEach(() => {
  dispose?.();
  dispose = null;
  vi.restoreAllMocks();
});

it('shows a movable stop alert over the bound window', async () => {
  const f = await load();
  const hosted = fakeWindow();
  f.bindWindow(hosted);

  const result = f.stopAlert('The scan couldn’t start.', 'Another scan is still running.');

  expect(osm.showAlert).toHaveBeenCalledOnce();
  expect(osm.alerts[0].options).toEqual({
    kind: 'stop',
    modality: 'movable',
    position: 'parent',
    parent: hosted.window,
    message: 'The scan couldn’t start.',
    explanation: 'Another scan is still running.',
    buttons: { ok: 'OK' }
  });

  osm.alerts[0].press('ok');
  await expect(result).resolves.toBe('ok');
});

it('shows one alert at a time, in order', async () => {
  const f = await load();
  f.bindWindow(fakeWindow());

  const first = f.stopAlert('First.');
  const second = f.noteAlert({
    message: 'Lantenna 1.1.0 is available.',
    buttons: { ok: 'View on GitHub', cancel: 'Later' }
  });
  expect(osm.showAlert).toHaveBeenCalledOnce();

  osm.alerts[0].press('ok');
  await expect(first).resolves.toBe('ok');
  expect(osm.showAlert).toHaveBeenCalledTimes(2);
  expect(osm.alerts[1].options).toMatchObject({
    kind: 'note',
    message: 'Lantenna 1.1.0 is available.',
    buttons: { ok: 'View on GitHub', cancel: 'Later' }
  });

  osm.alerts[1].press('cancel');
  await expect(second).resolves.toBe('cancel');
});

it('drops an alert identical to one showing or waiting', async () => {
  const f = await load();
  f.bindWindow(fakeWindow());

  const a = f.stopAlert('Lantenna couldn’t stop the scan.', 'Boom.');
  const b = f.stopAlert('Other.');
  const aAgain = f.stopAlert('Lantenna couldn’t stop the scan.', 'Boom.');
  const bAgain = f.stopAlert('Other.');
  // Same message, another explanation: a different alert.
  f.stopAlert('Lantenna couldn’t stop the scan.', 'Bang.');

  expect(aAgain).toBe(a);
  expect(bAgain).toBe(b);

  for (let i = 0; i < 3; i++) {
    osm.alerts[i].press('ok');
    await settle();
  }
  expect(osm.alerts.map((x) => x.options.explanation)).toEqual(['Boom.', undefined, 'Bang.']);

  // Once answered, the same alert may come again.
  f.stopAlert('Other.');
  expect(osm.showAlert).toHaveBeenCalledTimes(4);
});

it('expands a collapsed window before an alert opens', async () => {
  const f = await load();
  const hosted = fakeWindow(true);
  f.bindWindow(hosted);
  hosted.setShaded.mockImplementation((on: boolean) => {
    expect(osm.showAlert).not.toHaveBeenCalled();
    hosted.shaded = on;
  });

  void f.stopAlert('Failed.');

  expect(hosted.setShaded).toHaveBeenCalledWith(false);
  expect(osm.showAlert).toHaveBeenCalledOnce();
});

it('closes alerts at unmount and drops the waiting ones', async () => {
  const f = await load();
  f.bindWindow(fakeWindow());
  const stop = f.installFeedback();

  const showing = f.stopAlert('One.');
  const waiting = f.stopAlert('Two.');
  stop();

  await expect(showing).resolves.toBe('dismissed');
  await expect(waiting).resolves.toBe('dismissed');
  expect(osm.alerts[0].close).toHaveBeenCalledOnce();
  expect(osm.showAlert).toHaveBeenCalledOnce();

  // The window is forgotten: a later alert centers on the page.
  void f.stopAlert('Three.');
  expect(osm.alerts[1].options).toMatchObject({ position: 'screen' });
  expect(osm.alerts[1].options.parent).toBeUndefined();
});

it('keeps the queue moving when an alert can’t be shown', async () => {
  const f = await load();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  osm.showAlert.mockImplementationOnce(() => {
    throw new Error('bad options');
  });

  await expect(f.stopAlert('Broken.')).resolves.toBe('dismissed');
  void f.stopAlert('Next.');
  expect(osm.alerts[0].options.message).toBe('Next.');
});

it('puts up a real Osmium alert and takes it down at unmount', async () => {
  osm.showAlert.mockImplementation((o: AlertOptions) => osm.real!(o));
  const f = await load();
  f.bindWindow(fakeWindow());
  dispose = f.installFeedback();

  const result = f.stopAlert('Lantenna couldn’t copy to the Clipboard.', 'Clipboard is not available.');
  const box = document.querySelector('.osm-alert[role=alertdialog]');
  expect(box?.textContent).toContain('Lantenna couldn’t copy to the Clipboard.');
  expect(box?.classList.contains('osm-movable')).toBe(true);

  dispose();
  dispose = null;
  await expect(result).resolves.toBe('dismissed');
  expect(document.querySelector('.osm-alert')).toBeNull();
});

it.each([
  [
    { type: 'init-failed', message: 'Failed to initialize scanner' },
    'Lantenna couldn’t start its scanner.',
    'Failed to initialize scanner.',
    'init'
  ],
  [
    { type: 'start-failed', message: 'A scan is already running' },
    'The scan couldn’t start.',
    'Another scan is still running. Wait for it to finish, then try again.',
    'start'
  ],
  [
    { type: 'scan-error', message: "Interface 'en0' not found" },
    'Lantenna couldn’t finish scanning the network.',
    'The interface en0 is no longer available. Choose another interface, then click Scan.',
    'scan'
  ],
  [
    { type: 'cancel-failed', message: 'Failed to cancel scan' },
    'Lantenna couldn’t stop the scan.',
    'Failed to cancel scan.',
    null
  ],
  [
    { type: 'no-interface' },
    'Lantenna can’t scan without a network interface.',
    'Choose a network interface from the Interface pop-up menu, then click Scan.',
    null
  ],
  [
    { type: 'deep-scan-failed', ip: '192.168.1.31', message: "Invalid IPv4 address '192.168.1.31'" },
    'Lantenna couldn’t deep scan 192.168.1.31.',
    '“192.168.1.31” isn’t a valid IPv4 address.',
    null
  ]
] as const)('alerts for %j', async (event, message, explanation, kind) => {
  const f = await load();
  f.bindWindow(fakeWindow());
  dispose = f.installFeedback();

  f.scanEvents.emit(event);

  expect(osm.alerts).toHaveLength(1);
  expect(osm.alerts[0].options).toMatchObject({ kind: 'stop', message, explanation, buttons: { ok: 'OK' } });
  expect(get(f.lastError)).toEqual(kind === null ? null : { kind, message: 'message' in event ? event.message : '' });
});

it('remembers the kind of the latest error', async () => {
  const f = await load();
  dispose = f.installFeedback();

  f.scanEvents.emit({ type: 'init-failed', message: 'a' });
  f.scanEvents.emit({ type: 'scan-error', message: 'b' });
  f.scanEvents.emit({ type: 'cancel-failed', message: 'c' });

  expect(get(f.lastError)).toEqual({ kind: 'scan', message: 'b' });
});

it('says nothing for a completed scan', async () => {
  const f = await load();
  dispose = f.installFeedback();

  f.scanEvents.emit({ type: 'scan-complete', hostCount: 1, cancelled: false });

  expect(osm.showAlert).not.toHaveBeenCalled();
  expect(get(f.hostNote)).toBeNull();
});

it('notes a deep scan’s result, not its progress (the pane shows that)', async () => {
  const f = await load();
  dispose = f.installFeedback();
  f.scanStore.setSelectedHost('192.168.1.31');
  const deep = { phase: 'ports' as const, current_ip: '192.168.1.31', running: true };

  f.scanProgress.set({ progress: null, hostScanProgress: { ...deep, scanned: 0, total: 0, found: 0 } });
  f.scanProgress.set({ progress: null, hostScanProgress: { ...deep, scanned: 412, total: 2048, found: 4 } });
  f.scanProgress.set({ progress: null, hostScanProgress: { ...deep, scanned: 1, total: 1, found: 5, running: false } });
  expect(get(f.hostNote)).toBeNull();

  const finished = new Date(2026, 8, 27, 15, 44);
  vi.useFakeTimers({ now: finished, toFake: ['Date'] });
  try {
    f.scanEvents.emit({ type: 'deep-scan-done', ip: '192.168.1.31', openPorts: 5 });
  } finally {
    vi.useRealTimers();
  }

  expect(get(f.hostNote)?.text).toBe(`Deep scan finished at ${formatClock(finished)}: 5 open ports.`);
});

it('words the deep scan result for one port and none', async () => {
  const f = await load();
  dispose = f.installFeedback();
  f.scanStore.setSelectedHost('10.0.0.1');

  f.scanEvents.emit({ type: 'deep-scan-done', ip: '10.0.0.1', openPorts: 1 });
  expect(get(f.hostNote)?.text).toMatch(/: 1 open port\.$/);

  f.scanEvents.emit({ type: 'deep-scan-done', ip: '10.0.0.1', openPorts: 0 });
  expect(get(f.hostNote)?.text).toMatch(/: no open ports\.$/);
});

it('notes a deep scan race and drops the note of a failed one', async () => {
  const f = await load();
  dispose = f.installFeedback();
  f.scanStore.setSelectedHost('192.168.1.31');

  f.scanEvents.emit({ type: 'deep-scan-busy', ip: '192.168.1.31' });
  expect(get(f.hostNote)).toEqual({ ip: '192.168.1.31', text: 'A deep scan is already running.' });

  f.scanEvents.emit({ type: 'deep-scan-failed', ip: '192.168.1.31', message: 'x' });
  expect(get(f.hostNote)).toBeNull();
});

it('shows the selected host’s note and drops it when another host is selected', async () => {
  const f = await load();
  dispose = f.installFeedback();
  f.scanStore.setSelectedHost('192.168.1.40');

  f.setHostNote('192.168.1.40', 'Sending a wake-up packet…');
  // A result for a host that isn't selected waits for it.
  f.setHostNote('192.168.1.31', 'Deep scan finished at 3:44 PM: 5 open ports.');
  expect(get(f.hostNote)).toEqual({ ip: '192.168.1.40', text: 'Sending a wake-up packet…' });

  f.scanStore.setSelectedHost('192.168.1.31');
  expect(get(f.hostNote)).toEqual({ ip: '192.168.1.31', text: 'Deep scan finished at 3:44 PM: 5 open ports.' });

  f.scanStore.setSelectedHost('192.168.1.40');
  expect(get(f.hostNote)).toBeNull();

  f.scanStore.setSelectedHost(null);
  f.scanStore.setSelectedHost('192.168.1.31');
  expect(get(f.hostNote)).toBeNull();
});

it('removes a note set to empty text', async () => {
  const f = await load();
  dispose = f.installFeedback();
  f.scanStore.setSelectedHost('192.168.1.40');

  f.setHostNote('192.168.1.40', 'Sending a wake-up packet…');
  f.setHostNote('192.168.1.40', '');

  expect(get(f.hostNote)).toBeNull();
});

it('publishes a note only when it changes', async () => {
  const f = await load();
  dispose = f.installFeedback();
  f.scanStore.setSelectedHost('192.168.1.40');
  const seen: unknown[] = [];
  const stop = f.hostNote.subscribe((n) => seen.push(n));

  f.setHostNote('192.168.1.40', 'Sending a wake-up packet…');
  f.setHostNote('192.168.1.40', 'Sending a wake-up packet…');
  f.setHostNote('192.168.1.99', 'Elsewhere.');
  stop();

  expect(seen).toEqual([null, { ip: '192.168.1.40', text: 'Sending a wake-up packet…' }]);
});

it('stops listening at unmount', async () => {
  const f = await load();
  const stop = f.installFeedback();
  stop();

  f.scanEvents.emit({ type: 'no-interface' });
  f.scanStore.setSelectedHost('192.168.1.31');
  f.scanProgress.set({
    progress: null,
    hostScanProgress: { phase: 'ports', scanned: 0, total: 0, found: 0, running: true, current_ip: '192.168.1.31' }
  });

  expect(osm.showAlert).not.toHaveBeenCalled();
  expect(get(f.hostNote)).toBeNull();
});
