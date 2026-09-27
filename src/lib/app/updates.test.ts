// Owner: unit D (spec 8.4). Spec: 5.4 (update timing, update alerts,
// Check for Updates…).
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { AlertResult } from 'osmium-ui';

type Callback = (event: { payload: unknown }) => void;

const native = vi.hoisted(() => ({
  listeners: new Map<string, (event: { payload: unknown }) => void>(),
  update: null as null | { version: string; url: string; notes: null },
  updateError: null as unknown,
  openError: null as unknown,
  version: '1.0.1' as string | Error,
  invoke: vi.fn(),
  noteAlert: vi.fn(),
  stopAlert: vi.fn()
}));

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async (event: string, callback: Callback) => {
    native.listeners.set(event, callback);
    return () => native.listeners.delete(event);
  })
}));
vi.mock('@tauri-apps/api/core', () => ({ invoke: native.invoke }));
vi.mock('@tauri-apps/api/app', () => ({
  getVersion: vi.fn(async () => {
    if (native.version instanceof Error) throw native.version;
    return native.version;
  })
}));
vi.mock('./feedback', () => ({ noteAlert: native.noteAlert, stopAlert: native.stopAlert }));

const RELEASE = { version: '1.1.0', url: 'https://github.com/L-K-M/Lantenna/releases/tag/v1.1.0', notes: null };

async function invokeImpl(command: string): Promise<unknown> {
  switch (command) {
    case 'get_network_interfaces':
      return [];
    case 'check_self_update':
      if (native.updateError !== null) throw native.updateError;
      return native.update;
    case 'open_release_url':
      if (native.openError !== null) throw native.openError;
      return null;
    default:
      return null;
  }
}

/** Fresh modules: `offered` is per launch, the stores are singletons. */
async function load() {
  vi.resetModules();
  const updates = await import('./updates');
  const { scanStore } = await import('$lib/util/scanStore');
  const { ui } = await import('./ui');
  const osmium = await import('osmium-ui');
  return { ...updates, scanStore, ui, osmium };
}

const settle = () => new Promise((r) => setTimeout(r, 0));

let answer: AlertResult = 'cancel';
let dispose: (() => void) | null = null;

beforeEach(() => {
  localStorage.clear();
  native.listeners.clear();
  native.update = RELEASE;
  native.updateError = null;
  native.openError = null;
  native.version = '1.0.1';
  native.invoke.mockReset();
  native.invoke.mockImplementation(invokeImpl);
  native.noteAlert.mockReset();
  native.noteAlert.mockImplementation(async () => answer);
  native.stopAlert.mockReset();
  native.stopAlert.mockResolvedValue('ok');
  answer = 'cancel';
});

afterEach(() => {
  dispose?.();
  dispose = null;
  vi.restoreAllMocks();
});

const checks = () => native.invoke.mock.calls.filter(([c]) => c === 'check_self_update').length;

const UPDATE_ALERT = {
  message: 'Lantenna 1.1.0 is available.',
  explanation: 'You have version 1.0.1. The release page on GitHub describes what’s new.',
  buttons: { ok: 'View on GitHub', cancel: 'Later', other: 'Skip This Version' }
};

it('checks once the store has read the last scan, and offers the update', async () => {
  const m = await load();
  dispose = m.scheduleUpdateCheck();
  await settle();
  expect(checks()).toBe(0);

  await m.scanStore.init();
  await settle();

  expect(checks()).toBe(1);
  expect(native.noteAlert).toHaveBeenCalledExactlyOnceWith(UPDATE_ALERT);
});

it('checks nothing when disposed before the store settles', async () => {
  const m = await load();
  m.scheduleUpdateCheck()();

  await m.scanStore.init();
  await settle();

  expect(checks()).toBe(0);
});

it('offers nothing without an update, and keeps the daily throttle', async () => {
  native.update = null;
  const m = await load();
  dispose = m.scheduleUpdateCheck();
  await m.scanStore.init();
  await settle();

  expect(checks()).toBe(1);
  expect(native.noteAlert).not.toHaveBeenCalled();

  // Checked a moment ago: the next launch doesn't ask again.
  const next = await load();
  dispose();
  dispose = next.scheduleUpdateCheck();
  await next.scanStore.init();
  await settle();
  expect(checks()).toBe(1);
});

it('waits for an active, expanded, idle window with no alert up', async () => {
  const m = await load();
  m.ui.setActive(false);
  m.ui.setShaded(true);
  dispose = m.scheduleUpdateCheck();
  await m.scanStore.init();
  // A scan resumed from progress (as after a reload mid-scan).
  native.listeners.get('scan-progress')!({
    payload: { phase: 'ports', scanned: 1, total: 4, found: 4, running: true, current_ip: null }
  });
  const alert = m.osmium.showAlert({ kind: 'note', message: 'Something else.' });
  await settle();

  m.ui.setActive(true);
  await settle();
  m.ui.setShaded(false);
  await settle();
  native.listeners.get('scan-complete')!({
    payload: {
      started_at: '',
      completed_at: new Date().toISOString(),
      cancelled: false,
      hosts: [],
      options: { interface_name: 'en0', subnet: null, port_profile: 'standard', discovery_mode: 'hybrid', timeout_ms: 450, max_hosts: null }
    }
  });
  await settle();
  expect(native.noteAlert).not.toHaveBeenCalled();

  alert.close();
  await alert.result;
  await settle();
  expect(native.noteAlert).toHaveBeenCalledExactlyOnceWith(UPDATE_ALERT);

  // Once per launch.
  m.ui.setActive(false);
  m.ui.setActive(true);
  await settle();
  expect(native.noteAlert).toHaveBeenCalledOnce();
});

it('opens the release page from View on GitHub', async () => {
  answer = 'ok';
  const m = await load();
  dispose = m.scheduleUpdateCheck();
  await m.scanStore.init();
  await settle();

  expect(native.invoke).toHaveBeenCalledWith('open_release_url', { url: RELEASE.url });
  expect(localStorage.getItem('updateChecker.skippedVersion')).toBeNull();
});

it('says so when the release page can’t be opened', async () => {
  answer = 'ok';
  native.openError = 'Only http(s) URLs may be opened';
  const m = await load();
  dispose = m.scheduleUpdateCheck();
  await m.scanStore.init();
  await settle();

  expect(native.stopAlert).toHaveBeenCalledWith(
    `Lantenna couldn’t open “${RELEASE.url}”.`,
    'Only http(s) URLs may be opened.'
  );
});

it('remembers Skip This Version and does nothing for Later', async () => {
  answer = 'other';
  let m = await load();
  dispose = m.scheduleUpdateCheck();
  await m.scanStore.init();
  await settle();
  expect(localStorage.getItem('updateChecker.skippedVersion')).toBe('1.1.0');
  expect(native.invoke).not.toHaveBeenCalledWith('open_release_url', expect.anything());

  localStorage.clear();
  answer = 'cancel';
  m = await load();
  dispose();
  dispose = m.scheduleUpdateCheck();
  await m.scanStore.init();
  await settle();
  expect(native.noteAlert).toHaveBeenCalledTimes(2);
  expect(localStorage.getItem('updateChecker.skippedVersion')).toBeNull();
  expect(native.invoke).not.toHaveBeenCalledWith('open_release_url', expect.anything());
});

it('leaves out the version it can’t read', async () => {
  native.version = new Error('no app plugin');
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  const m = await load();
  dispose = m.scheduleUpdateCheck();
  await m.scanStore.init();
  await settle();

  expect(native.noteAlert).toHaveBeenCalledWith(
    expect.objectContaining({ explanation: 'The release page on GitHub describes what’s new.' })
  );
});

it('checks now: an update, even a skipped one and within the day', async () => {
  localStorage.setItem('updateChecker.skippedVersion', '1.1.0');
  localStorage.setItem('updateChecker.lastCheck', String(Date.now()));
  const m = await load();

  await m.checkForUpdatesNow();

  expect(checks()).toBe(1);
  expect(native.noteAlert).toHaveBeenCalledExactlyOnceWith(UPDATE_ALERT);
});

it('checks now: up to date', async () => {
  native.update = null;
  const m = await load();

  await m.checkForUpdatesNow();

  expect(native.noteAlert).toHaveBeenCalledExactlyOnceWith({ message: 'Lantenna 1.0.1 is the latest version.' });
  expect(native.stopAlert).not.toHaveBeenCalled();
});

it('checks now: a failure is a stop alert, not "up to date"', async () => {
  native.updateError = 'GitHub returned HTTP 503';
  const m = await load();

  await m.checkForUpdatesNow();

  expect(native.stopAlert).toHaveBeenCalledExactlyOnceWith(
    'Lantenna couldn’t check for updates.',
    'GitHub returned HTTP 503.'
  );
  expect(native.noteAlert).not.toHaveBeenCalled();
});

it('offers an update the manual check already showed only once', async () => {
  const m = await load();
  dispose = m.scheduleUpdateCheck();
  await m.checkForUpdatesNow();
  expect(native.noteAlert).toHaveBeenCalledOnce();
  // Past the throttle, the launch check finds the same update.
  localStorage.removeItem('updateChecker.lastCheck');

  await m.scanStore.init();
  await settle();

  expect(checks()).toBe(2);
  expect(native.noteAlert).toHaveBeenCalledOnce();
});
