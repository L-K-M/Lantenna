// run(): each command's action, and the re-check that makes a stale or
// dimmed command do nothing. The stores commandContext derives from are
// replaced with writables so any state can be set.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { get, writable } from 'svelte/store';
import { balloonHelp, setBalloonHelp, showAlert, type HostedWindow } from 'osmium-ui';
import type { ScanProgressState, ScanStoreState } from '$lib/util/scanStore';
import { commandContext, osmiumMenuEntries, run, viewMenuSpec, type CommandRef } from './commands';
import { EMPTY_MODEL, IDLE_STORE, host, row } from './commands.fixture';
import type { HostModel } from './hostModel';
import { hostedWindow } from './views';

const fake = vi.hoisted(() => ({
  store: null as unknown as import('svelte/store').Writable<ScanStoreState>,
  model: null as unknown as import('svelte/store').Writable<HostModel>,
  waking: null as unknown as import('svelte/store').Writable<string | null>
}));

vi.mock('$lib/util/scanStore', async (importOriginal) => {
  const actual = await importOriginal<typeof import('$lib/util/scanStore')>();
  const { IDLE_STORE: idle } = await import('./commands.fixture');
  fake.store = writable(idle);
  return {
    ...actual,
    scanProgress: writable<ScanProgressState>({ progress: null, hostScanProgress: null }),
    scanStore: {
      subscribe: fake.store.subscribe,
      startScan: vi.fn(async () => {}),
      cancelScan: vi.fn(async () => {}),
      setInterface: vi.fn(),
      setScanApproach: vi.fn(),
      setCustomName: vi.fn(),
      toggleHidden: vi.fn(),
      toggleFavorite: vi.fn(),
      setShowHiddenEntries: vi.fn(),
      setSelectedHost: vi.fn()
    }
  };
});

vi.mock('./hostModel', async () => {
  const { EMPTY_MODEL: empty } = await import('./commands.fixture');
  fake.model = writable(empty);
  return { hostModel: fake.model };
});

vi.mock('./actions', () => {
  fake.waking = writable<string | null>(null);
  return {
    wakingIp: fake.waking,
    openHost: vi.fn(async () => {}),
    openUrl: vi.fn(async () => {}),
    wakeHost: vi.fn(async () => {}),
    deepScan: vi.fn(async () => {}),
    copyValue: vi.fn(async () => {}),
    copyHostList: vi.fn(async () => {}),
    showInfo: vi.fn(),
    beginRename: vi.fn(),
    revealHost: vi.fn()
  };
});

vi.mock('./feedback', () => ({
  noteAlert: vi.fn(async () => 'ok'),
  stopAlert: vi.fn(async () => 'ok')
}));

vi.mock('./updates', () => ({ checkForUpdatesNow: vi.fn(async () => {}) }));

vi.mock('@tauri-apps/api/app', () => ({ getVersion: vi.fn(async () => '1.0.1') }));

vi.mock('$lib/windowManager', () => ({ windowManager: { apply: vi.fn() } }));

const actions = await import('./actions');
const feedback = await import('./feedback');
const updates = await import('./updates');
const { scanStore } = await import('$lib/util/scanStore');
const { windowManager } = await import('$lib/windowManager');
const { ui } = await import('./ui');

const printer = host('192.168.1.31', { name: 'BRN30055C.local', ports: [80, 445], mac: '30:05:5C:12:34:56' });

function select(r = row(printer)) {
  fake.store.set({ ...IDLE_STORE, hosts: [r.host], selectedHostIp: r.ip });
  fake.model.set({ ...EMPTY_MODEL, rows: [r], universe: 1, selected: r });
}

function fakeWindow(shaded = false) {
  const hosted = { shaded, setShaded: vi.fn(), close: vi.fn() };
  hostedWindow.set(hosted as unknown as HostedWindow);
  return hosted;
}

beforeEach(() => {
  vi.clearAllMocks();
  fake.store.set(IDLE_STORE);
  fake.model.set(EMPTY_MODEL);
  fake.waking.set(null);
});

afterEach(() => {
  hostedWindow.set(null);
  document.body.replaceChildren();
  setBalloonHelp('hidden');
});

const go = (id: CommandRef['id'], arg?: string) => run(arg === undefined ? { id } : { id, arg });

it('does nothing for a command that is dimmed now', () => {
  go('host.open');
  go('edit.copyIp');
  go('host.toggleHidden');
  go('fav.toggle');
  expect(actions.openHost).not.toHaveBeenCalled();
  expect(actions.copyValue).not.toHaveBeenCalled();
  expect(scanStore.toggleHidden).not.toHaveBeenCalled();
  expect(scanStore.toggleFavorite).not.toHaveBeenCalled();

  // An item for another interface than the ones listed (a stale menu).
  go('scan.interface', 'en9|10.9.9.9');
  expect(scanStore.setInterface).not.toHaveBeenCalled();
});

it('does nothing while an alert is up', async () => {
  select();
  const alert = showAlert({ kind: 'stop', message: 'Lantenna couldn’t start its scanner.' });
  go('app.about');
  go('host.open');
  go('scan.toggle');
  alert.close();
  await alert.result;

  expect(feedback.noteAlert).not.toHaveBeenCalled();
  expect(actions.openHost).not.toHaveBeenCalled();
  expect(scanStore.startScan).not.toHaveBeenCalled();
});

it('runs the host commands on the selected host', () => {
  select(row(printer, { customName: 'Office Printer' }));

  go('host.open');
  expect(actions.openHost).toHaveBeenCalledWith('192.168.1.31');
  go('host.openUrl', 'smb://192.168.1.31');
  expect(actions.openUrl).toHaveBeenCalledWith('smb://192.168.1.31');
  go('host.deepScan');
  expect(actions.deepScan).toHaveBeenCalledWith('192.168.1.31');
  go('host.wake');
  expect(actions.wakeHost).toHaveBeenCalledWith('192.168.1.31');
  go('host.clearName');
  expect(scanStore.setCustomName).toHaveBeenCalledWith('192.168.1.31', '');
  go('host.toggleHidden');
  expect(scanStore.toggleHidden).toHaveBeenCalledWith('192.168.1.31');
  go('fav.toggle');
  expect(scanStore.toggleFavorite).toHaveBeenCalledWith('192.168.1.31');

  for (const [id, what] of [
    ['edit.copyIp', 'ip'],
    ['edit.copyName', 'name'],
    ['edit.copyDetectedName', 'detectedName'],
    ['edit.copyMac', 'mac']
  ] as const) {
    go(id);
    expect(actions.copyValue).toHaveBeenLastCalledWith(what, '192.168.1.31');
  }
  go('edit.copyHostList');
  expect(actions.copyHostList).toHaveBeenCalledOnce();
});

it('shows the pane, renames and reveals in an expanded window', () => {
  select();
  const hosted = fakeWindow(true);

  go('host.getInfo');
  expect(actions.showInfo).toHaveBeenCalledWith('general');
  go('host.rename');
  expect(actions.beginRename).toHaveBeenCalledOnce();
  expect(hosted.setShaded).toHaveBeenCalledWith(false);

  fake.store.update((s) => ({ ...s, favoriteIps: ['192.168.1.31'] }));
  go('fav.reveal', '192.168.1.31');
  expect(actions.revealHost).toHaveBeenCalledWith('192.168.1.31');
  go('fav.reveal', '192.168.1.99'); // not a favorite (a stale menu)
  expect(actions.revealHost).toHaveBeenCalledOnce();
});

it('starts a scan when idle and stops it while scanning', () => {
  go('scan.toggle');
  expect(scanStore.startScan).toHaveBeenCalledOnce();

  fake.store.set({ ...IDLE_STORE, scanning: true });
  go('scan.toggle');
  expect(scanStore.cancelScan).toHaveBeenCalledOnce();

  fake.store.set({ ...IDLE_STORE, scanning: true, stopping: true });
  go('scan.toggle');
  expect(scanStore.cancelScan).toHaveBeenCalledOnce();
  expect(scanStore.startScan).toHaveBeenCalledOnce();
});

it('chooses an interface and a depth only while idle', () => {
  go('scan.interface', 'en0|192.168.1.23');
  expect(scanStore.setInterface).toHaveBeenCalledWith('en0|192.168.1.23');
  go('scan.depth', 'thorough');
  expect(scanStore.setScanApproach).toHaveBeenCalledWith('thorough');

  fake.store.set({ ...IDLE_STORE, scanning: true });
  go('scan.depth', 'fast');
  expect(scanStore.setScanApproach).toHaveBeenCalledOnce();
});

it('changes the view, the pane, hidden hosts, Balloon Help', () => {
  go('view.mode', 'icons');
  expect(get(ui).viewMode).toBe('icons');
  go('view.scope', 'favorites');
  go('view.infoPane');
  let state!: import('./ui').UiState;
  ui.subscribe((s) => (state = s))();
  expect([state.viewMode, state.scope, state.infoPaneShown]).toEqual(['icons', 'favorites', false]);
  go('view.mode', 'list');
  go('view.scope', 'all');
  go('view.infoPane');

  fake.model.set({ ...EMPTY_MODEL, hiddenCount: 1 });
  go('view.showHidden');
  expect(scanStore.setShowHiddenEntries).toHaveBeenCalledWith(true);

  go('help.balloons');
  expect(balloonHelp()).toBe('shown');
  go('help.balloons');
  expect(balloonHelp()).toBe('hidden');
});

it('zooms, collapses and closes the window', () => {
  const hosted = fakeWindow();
  go('view.zoom');
  expect(windowManager.apply).toHaveBeenCalledWith({ op: 'winZoom' });
  go('view.collapse');
  expect(hosted.setShaded).toHaveBeenCalledWith(true);
  go('file.close');
  go('app.quit');
  expect(hosted.close).toHaveBeenCalledTimes(2);

  hostedWindow.set(null);
  go('file.close');
  expect(windowManager.apply).toHaveBeenLastCalledWith({ op: 'winClose' });
});

it('opens Lantenna Help, checks for updates, shows About', async () => {
  go('help.help');
  expect(actions.openUrl).toHaveBeenCalledWith('https://github.com/L-K-M/Lantenna#readme');
  go('app.checkUpdates');
  expect(updates.checkForUpdatesNow).toHaveBeenCalledOnce();

  go('app.about');
  await vi.waitFor(() => expect(feedback.noteAlert).toHaveBeenCalled());
  expect(feedback.noteAlert).toHaveBeenCalledWith({
    message: 'Lantenna 1.0.1',
    explanation: 'Finds the computers and devices on your network.\n\ngithub.com/L-K-M/Lantenna',
    buttons: { ok: 'OK' }
  });
});

it('focuses Find and selects its text', () => {
  const field = document.createElement('input');
  field.id = 'lan-find';
  field.value = 'printer';
  document.body.append(field);

  go('edit.find');
  expect(document.activeElement).toBe(field);
  expect([field.selectionStart, field.selectionEnd]).toEqual([0, 7]);
});

/** A text field with the keyboard and all its text selected. */
function focusedField(value = 'office printer') {
  const field = document.createElement('input');
  field.value = value;
  document.body.append(field);
  field.focus();
  field.select();
  return field;
}

it('copies text with the browser, and the selected host’s IP in the list', () => {
  const field = focusedField();
  const exec = vi.spyOn(document, 'execCommand').mockReturnValue(true);
  go('edit.copy');
  expect(exec).toHaveBeenCalledWith('copy');
  go('edit.cut');
  expect(exec).toHaveBeenLastCalledWith('cut');
  go('edit.undo');
  expect(exec).toHaveBeenLastCalledWith('undo');
  go('edit.selectAll');
  expect([field.selectionStart, field.selectionEnd]).toEqual([0, 14]);
  expect(feedback.stopAlert).not.toHaveBeenCalled();

  field.remove();
  const list = document.createElement('div');
  list.className = 'lan-list';
  const grid = document.createElement('div');
  grid.tabIndex = 0;
  list.append(grid);
  document.body.append(list);
  grid.focus();
  select();
  go('edit.copy');
  expect(actions.copyValue).toHaveBeenCalledWith('ip', '192.168.1.31');
  expect(exec).toHaveBeenCalledTimes(3);
});

it('reports a copy or cut the browser refused', () => {
  focusedField();
  vi.spyOn(document, 'execCommand').mockReturnValue(false);
  go('edit.copy');
  expect(feedback.stopAlert).toHaveBeenCalledWith(
    'Lantenna couldn’t copy to the Clipboard.',
    'Press Control-C to copy the selection instead.'
  );
  go('edit.cut');
  expect(feedback.stopAlert).toHaveBeenLastCalledWith(
    'Lantenna couldn’t cut to the Clipboard.',
    'Press Control-X to cut the selection instead.'
  );
});

it('does nothing for Cut or Copy with nothing selected, as the keys do', () => {
  // WebKit's execCommand returns false then: no alert for that.
  const field = focusedField();
  const exec = vi.spyOn(document, 'execCommand').mockReturnValue(false);
  for (const caret of [0, 3]) {
    field.setSelectionRange(caret, caret);
    go('edit.copy');
    go('edit.cut');
  }
  expect(exec).not.toHaveBeenCalled();
  expect(feedback.stopAlert).not.toHaveBeenCalled();
});

it('pastes what the Clipboard holds, or says to use the key', async () => {
  focusedField();
  const exec = vi.spyOn(document, 'execCommand').mockReturnValue(true);
  const readText = vi.fn(async () => 'NAS');
  vi.stubGlobal('navigator', { ...navigator, clipboard: { readText } });
  try {
    go('edit.paste');
    await vi.waitFor(() => expect(exec).toHaveBeenCalledWith('insertText', false, 'NAS'));

    const denied = new DOMException('Denied', 'NotAllowedError');
    readText.mockRejectedValueOnce(denied);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    go('edit.paste');
    await vi.waitFor(() =>
      expect(feedback.stopAlert).toHaveBeenCalledWith(
        'Lantenna couldn’t read the Clipboard.',
        'Press Control-V to paste into the field instead.'
      )
    );
    // The alert explains; the log keeps the system's reason.
    expect(warn).toHaveBeenCalledWith('Lantenna couldn’t read the Clipboard:', denied);
    warn.mockRestore();
  } finally {
    vi.unstubAllGlobals();
  }
});

it('inserts the pasted text itself where insertText is missing', async () => {
  const field = focusedField('ab');
  field.setSelectionRange(1, 1);
  vi.spyOn(document, 'execCommand').mockReturnValue(false);
  vi.stubGlobal('navigator', { ...navigator, clipboard: { readText: async () => 'X' } });
  const input = vi.fn();
  field.addEventListener('input', input);
  try {
    go('edit.paste');
    await vi.waitFor(() => expect(field.value).toBe('aXb'));
    expect(input).toHaveBeenCalledOnce();
  } finally {
    vi.unstubAllGlobals();
  }
});

it('does nothing for an Osmium menu item chosen after its meaning changed', () => {
  fake.store.set({ ...IDLE_STORE, scanning: true });
  const ctx = get(commandContext);
  const stop = osmiumMenuEntries(viewMenuSpec(ctx), ctx, 'contextual')[2] as { title: string; action: () => void };
  expect(stop.title).toBe('Stop Scan');

  // The scan ends while the menu is open.
  fake.store.set(IDLE_STORE);
  stop.action();
  expect(scanStore.startScan).not.toHaveBeenCalled();
  expect(scanStore.cancelScan).not.toHaveBeenCalled();

  fake.store.set({ ...IDLE_STORE, scanning: true });
  stop.action();
  expect(scanStore.cancelScan).toHaveBeenCalledOnce();
});
