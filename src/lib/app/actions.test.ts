// Owner: unit C (spec 8.4): host actions call Tauri with the right
// arguments, put results in the status line and report failures (5.3,
// 5.4); copy, Get Info, Rename… and the Favorites jump.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get, type Writable } from 'svelte/store';
import type { HostedWindow } from 'osmium-ui';
import { host, hostRow } from '$lib/components/hostRow.fixture';
import type { Host } from '$lib/types';
import { formatClock } from '$lib/util/format';
import type { ScanStoreState } from '$lib/util/scanStore';
import type { HostModel } from './hostModel';

const native = vi.hoisted(() => ({ invoke: vi.fn(async (_cmd: string, _args?: unknown): Promise<unknown> => null) }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: native.invoke }));

vi.mock('./feedback', async () => {
  const { readable } = await import('svelte/store');
  return {
    stopAlert: vi.fn(async () => 'ok'),
    noteAlert: vi.fn(async () => 'ok'),
    setHostNote: vi.fn(),
    hostNote: readable(null)
  };
});

vi.mock('./errorText', () => ({ explainError: (raw: string) => `explained(${raw})` }));

// The store's actions are spies over a plain writable, so each test sets
// exactly the hosts, names, query and hidden state it needs.
vi.mock('$lib/util/scanStore', async () => {
  const { writable } = await import('svelte/store');
  const state = writable({} as ScanStoreState);
  const patch = (p: Partial<ScanStoreState>) => state.update((s) => ({ ...s, ...p }));
  return {
    scanStore: {
      subscribe: state.subscribe,
      set: state.set,
      setQuery: vi.fn((query: string) => patch({ query })),
      setShowHiddenEntries: vi.fn((showHiddenEntries: boolean) => patch({ showHiddenEntries })),
      setSelectedHost: vi.fn((selectedHostIp: string | null) => patch({ selectedHostIp })),
      refreshHostPorts: vi.fn(async () => {})
    },
    scanProgress: writable({ progress: null, hostScanProgress: null })
  };
});

vi.mock('./hostModel', async () => {
  const { writable } = await import('svelte/store');
  return { hostModel: writable({ rows: [] }) };
});

const { scanStore } = await import('$lib/util/scanStore');
const { hostModel } = await import('./hostModel');
const feedback = await import('./feedback');
const { ui } = await import('./ui');
const { activeView, hostedWindow, infoPaneApi } = await import('./views');
const actions = await import('./actions');

const printer = host();
const unnamed = host({
  ip: '192.168.1.77',
  name: null,
  open_ports: [{ port: 9100, state: 'open', service: 'jetdirect', banner: null }],
  fingerprint: null
});

function setStore(p: Partial<ScanStoreState>): void {
  (scanStore as unknown as Writable<ScanStoreState>).set({
    hosts: [printer, unnamed],
    customNames: {},
    hiddenIps: [],
    showHiddenEntries: false,
    query: '',
    selectedHostIp: null,
    ...p
  } as ScanStoreState);
}

beforeEach(() => {
  vi.clearAllMocks();
  native.invoke.mockImplementation(async () => null);
  setStore({});
  ui.setInfoPane(true);
  ui.setInfoTab('general');
  ui.setScope('all');
  ui.setShaded(false);
  activeView.set(null);
  infoPaneApi.set(null);
  hostedWindow.set(null);
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('opening', () => {
  it('opens the primary target', async () => {
    await actions.openHost('192.168.1.31');
    expect(native.invoke).toHaveBeenCalledWith('open_external_url', { url: 'http://192.168.1.31' });
    expect(feedback.setHostNote).not.toHaveBeenCalled();
  });

  it('says so in the status line when there is nothing to open', async () => {
    await actions.openHost('192.168.1.77');
    expect(native.invoke).not.toHaveBeenCalled();
    expect(feedback.setHostNote).toHaveBeenCalledWith(
      '192.168.1.77',
      'This host has no web, file sharing, remote login or screen sharing service to open.'
    );
    expect(feedback.noteAlert).not.toHaveBeenCalled();
  });

  it('puts up a note alert instead while the pane is hidden', async () => {
    ui.setInfoPane(false);
    setStore({ customNames: { '192.168.1.77': 'Office Printer' } });

    await actions.openHost('192.168.1.77');

    expect(feedback.setHostNote).not.toHaveBeenCalled();
    expect(feedback.noteAlert).toHaveBeenCalledWith({
      message: '“Office Printer” has no service Lantenna can open.',
      explanation:
        'Lantenna opens web pages (HTTP and HTTPS), file servers (SMB), remote logins (SSH) and screen sharing (VNC). To see this host’s open ports, choose Show Host Information from the View menu.'
    });
  });

  it('names an unnamed host by its address in the note alert', async () => {
    ui.setInfoPane(false);
    await actions.openHost('192.168.1.77');
    expect(vi.mocked(feedback.noteAlert).mock.calls[0][0].message).toBe(
      '“192.168.1.77” has no service Lantenna can open.'
    );
  });

  it('reports an open failure in a stop alert', async () => {
    native.invoke.mockRejectedValueOnce('Unsupported URL scheme');
    await actions.openUrl('http://192.168.1.31:8080');
    expect(feedback.stopAlert).toHaveBeenCalledWith(
      'Lantenna couldn’t open “http://192.168.1.31:8080”.',
      'explained(Unsupported URL scheme)'
    );
  });
});

describe('waking', () => {
  it('sends the packet to the MAC and notes when', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(2026, 8, 27, 15, 44));
    let seen: string | null = null;
    native.invoke.mockImplementationOnce(async () => {
      seen = get(actions.wakingIp);
    });

    await actions.wakeHost('192.168.1.31');

    expect(native.invoke).toHaveBeenCalledWith('wake_host', { mac: '30:05:5C:12:34:56' });
    expect(seen).toBe('192.168.1.31');
    expect(get(actions.wakingIp)).toBeNull();
    expect(feedback.setHostNote).toHaveBeenCalledWith(
      '192.168.1.31',
      `Wake-up packet sent to 30:05:5C:12:34:56 at ${formatClock(new Date(2026, 8, 27, 15, 44))}.`
    );
  });

  it('reports a failure with advice, and is ready again', async () => {
    native.invoke.mockRejectedValueOnce("Invalid MAC address 'zz'");
    await actions.wakeHost('192.168.1.31');

    expect(feedback.stopAlert).toHaveBeenCalledWith(
      'Lantenna couldn’t send the wake-up packet.',
      "explained(Invalid MAC address 'zz') Check that this computer is connected to the network, then try again."
    );
    // The failure clears the host's older note instead of adding one.
    expect(feedback.setHostNote).toHaveBeenCalledTimes(1);
    expect(feedback.setHostNote).toHaveBeenCalledWith('192.168.1.31', '');
    expect(get(actions.wakingIp)).toBeNull();
  });

  it('does nothing without a MAC or while another packet is on its way', async () => {
    await actions.wakeHost('192.168.1.77');
    expect(native.invoke).not.toHaveBeenCalled();

    let release = () => {};
    native.invoke.mockImplementationOnce(() => new Promise<null>((r) => (release = () => r(null))));
    const first = actions.wakeHost('192.168.1.31');
    await actions.wakeHost('192.168.1.31');
    expect(native.invoke).toHaveBeenCalledTimes(1);

    release();
    await first;
  });
});

it('deep scans through the store', async () => {
  await actions.deepScan('192.168.1.31');
  expect(scanStore.refreshHostPorts).toHaveBeenCalledWith('192.168.1.31', 'deep');
});

describe('copying', () => {
  function clipboardSpy() {
    return vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue(undefined);
  }

  it('copies each value, the custom name first', async () => {
    const write = clipboardSpy();
    setStore({ customNames: { '192.168.1.31': 'Office Printer' } });

    await actions.copyValue('ip', '192.168.1.31');
    await actions.copyValue('name', '192.168.1.31');
    await actions.copyValue('detectedName', '192.168.1.31');
    await actions.copyValue('mac', '192.168.1.31');

    expect(write.mock.calls.map((c) => c[0])).toEqual([
      '192.168.1.31',
      'Office Printer',
      'BRN30055C123456.local',
      '30:05:5C:12:34:56'
    ]);
    expect(feedback.stopAlert).not.toHaveBeenCalled();
  });

  it('copies nothing for a missing value', async () => {
    const write = clipboardSpy();
    await actions.copyValue('name', '192.168.1.77');
    await actions.copyValue('mac', '192.168.1.77');
    await actions.copyValue('ip', '10.0.0.9');
    expect(write).not.toHaveBeenCalled();
  });

  it('falls back to a copy event when the Clipboard API refuses, leaving the focus alone', async () => {
    vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(new DOMException('Document is not focused.'));
    // As WebKit does without a selection: fire `copy` at the focused
    // element, write what its handlers set, and return false.
    let copied: { text: string; handled: boolean } | null = null;
    vi.spyOn(document, 'execCommand').mockImplementation((command) => {
      if (command !== 'copy') return false;
      const clipboardData = new DataTransfer();
      const event = new ClipboardEvent('copy', { clipboardData, bubbles: true, cancelable: true });
      (document.activeElement ?? document.body).dispatchEvent(event);
      copied = { text: clipboardData.getData('text/plain'), handled: event.defaultPrevented };
      return false;
    });
    // A name field with a draft in it: losing the keyboard would commit.
    const field = document.createElement('input');
    const focusOut = vi.fn();
    field.addEventListener('focusout', focusOut);
    document.body.append(field);
    field.focus();

    await actions.copyValue('ip', '192.168.1.31');

    expect(copied).toEqual({ text: '192.168.1.31', handled: true });
    expect(focusOut).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(field);
    expect(feedback.stopAlert).not.toHaveBeenCalled();
    field.remove();
  });

  it('reports a clipboard that refuses both ways, logging the system’s reason', async () => {
    const refusal = new DOMException('Document is not focused.', 'NotAllowedError');
    vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(refusal);
    vi.spyOn(document, 'execCommand').mockReturnValue(false);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await actions.copyValue('ip', '192.168.1.31');
    expect(feedback.stopAlert).toHaveBeenCalledWith(
      'Lantenna couldn’t copy to the Clipboard.',
      'explained(Clipboard write was blocked by the system)'
    );
    expect(warn).toHaveBeenCalledWith('Lantenna couldn’t copy to the Clipboard:', expect.any(Error));
    expect((warn.mock.calls[0]![1] as Error).cause).toBe(refusal);
  });

  it('copies the listed rows as tab-separated text', async () => {
    const write = clipboardSpy();
    const now = new Date().toISOString();
    const tabbed: Host = host({ ip: '192.168.1.40', name: 'studio\tmac', last_seen: now });
    (hostModel as Writable<Partial<HostModel>>).set({
      rows: [
        hostRow(tabbed, { status: 'New', kind: 'Apple host', vendor: 'Apple', portsText: '22, 88' }),
        hostRow(host({ last_seen: now }), { customName: 'Office Printer', kind: 'Printer', portsText: '80, 631' })
      ]
    });

    await actions.copyHostList();

    expect(write).toHaveBeenCalledWith(
      [
        'Name\tIP Address\tStatus\tKind\tVendor\tPorts\tLast Seen',
        'studio mac\t192.168.1.40\tNew\tApple host\tApple\t22, 88\tjust now',
        'Office Printer\t192.168.1.31\t\tPrinter\tBrother Industries\t80, 631\tjust now'
      ].join('\n')
    );
  });

  it('copies no host list without rows', async () => {
    const write = clipboardSpy();
    (hostModel as Writable<Partial<HostModel>>).set({ rows: [] });
    await actions.copyHostList();
    expect(write).not.toHaveBeenCalled();
  });
});

describe('showing the host', () => {
  function fakeWindow() {
    const setShaded = vi.fn((on: boolean) => ui.setShaded(on));
    hostedWindow.set({ setShaded } as unknown as HostedWindow);
    return setShaded;
  }

  it('Get Info shows the pane with the tab asked for', () => {
    ui.setInfoPane(false);
    actions.showInfo('fingerprint');
    expect(get(ui)).toMatchObject({ infoPaneShown: true, infoTab: 'fingerprint' });

    actions.showInfo();
    expect(get(ui).infoTab).toBe('general');
  });

  it('unfolds a collapsed window first', () => {
    const setShaded = fakeWindow();
    actions.showInfo();
    expect(setShaded).not.toHaveBeenCalled();

    ui.setShaded(true);
    actions.showInfo();
    expect(setShaded).toHaveBeenCalledWith(false);
  });

  it('Rename… shows General and focuses the name selected', () => {
    const focusName = vi.fn();
    infoPaneApi.set({ focusName });
    ui.setInfoPane(false);
    ui.setInfoTab('ports');

    actions.beginRename();

    expect(get(ui)).toMatchObject({ infoPaneShown: true, infoTab: 'general' });
    expect(focusName).toHaveBeenCalledWith(true);
  });

  it('the Favorites jump lists, selects, reveals and focuses the host', () => {
    const view = { element: document.body, focus: vi.fn(), reveal: vi.fn(), extraHeight: () => 0, idealColumnsWidth: () => null };
    activeView.set(view);
    ui.setScope('favorites');
    setStore({ query: 'nas', hiddenIps: ['192.168.1.31'] });

    actions.revealHost('192.168.1.31');

    expect(get(ui).scope).toBe('all');
    expect(scanStore.setQuery).toHaveBeenCalledWith('');
    expect(scanStore.setShowHiddenEntries).toHaveBeenCalledWith(true);
    expect(get(scanStore).selectedHostIp).toBe('192.168.1.31');
    expect(view.reveal).toHaveBeenCalledWith('192.168.1.31');
    expect(view.focus).toHaveBeenCalled();
  });

  it('the Favorites jump keeps a query and hidden rule that already show the host', () => {
    setStore({ query: 'brother printer', customNames: { '192.168.1.31': 'Office Printer' } });
    actions.revealHost('192.168.1.31');
    expect(scanStore.setQuery).not.toHaveBeenCalled();
    expect(scanStore.setShowHiddenEntries).not.toHaveBeenCalled();
    expect(scanStore.setSelectedHost).toHaveBeenCalledWith('192.168.1.31');
  });
});
