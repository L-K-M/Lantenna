// Owner: unit C (spec 8.4): the pane's tabs follow ui.infoTab, its
// buttons follow the command model and Return presses Open, the host
// status line (5.3), and Rename… reaching the name field.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte';
import { flushSync } from 'svelte';
import { get, type Writable } from 'svelte/store';
import type { HostRow } from '$lib/app/hostModel';
import type { ScanProgress } from '$lib/types';
import { host, hostRow } from './hostRow.fixture';
import HostInfoPane, { hostStatus } from './HostInfoPane.svelte';

const commands = vi.hoisted(() => ({ enabled: new Set<string>(), run: vi.fn() }));

vi.mock('$lib/app/commands', async () => {
  const { writable } = await import('svelte/store');
  return {
    commandContext: writable({}),
    // As the real model: every command is dimmed while an alert is up.
    describe: (ref: { id: string }, ctx: { modal?: boolean }) => ({
      title: ref.id,
      enabled: commands.enabled.has(ref.id) && !ctx.modal
    }),
    run: commands.run
  };
});
vi.mock('$lib/app/hostModel', async () => {
  const { writable } = await import('svelte/store');
  return { hostModel: writable({ selected: null }) };
});
vi.mock('$lib/app/feedback', async () => {
  const { writable } = await import('svelte/store');
  return { hostNote: writable(null) };
});
vi.mock('$lib/app/actions', async () => {
  const { writable } = await import('svelte/store');
  return { wakingIp: writable(null), openUrl: vi.fn() };
});
vi.mock('$lib/util/scanStore', async () => {
  const { writable } = await import('svelte/store');
  return {
    scanProgress: writable({ progress: null, hostScanProgress: null }),
    scanStore: { setCustomName: vi.fn(), toggleFavorite: vi.fn(), toggleHidden: vi.fn() }
  };
});

const { commandContext } = await import('$lib/app/commands');
const { hostModel } = await import('$lib/app/hostModel');
const model = hostModel as unknown as Writable<{ selected: HostRow | null }>;
const { hostNote } = await import('$lib/app/feedback');
const { wakingIp } = await import('$lib/app/actions');
const { scanProgress } = await import('$lib/util/scanStore');
const { ui } = await import('$lib/app/ui');
const { infoPaneApi } = await import('$lib/app/views');

const printer = hostRow();

function select(row: HostRow | null): void {
  model.set({ selected: row });
  flushSync();
}

function enable(...ids: string[]): void {
  commands.enabled = new Set(ids);
  (commandContext as Writable<object>).set({});
  flushSync();
}

function deepScanning(p: Partial<ScanProgress>): void {
  const hostScanProgress: ScanProgress = {
    phase: 'ports',
    scanned: 0,
    total: 0,
    found: 0,
    running: true,
    current_ip: '192.168.1.31',
    ...p
  };
  (scanProgress as Writable<object>).set({ progress: null, hostScanProgress });
  flushSync();
}

function pane(): HTMLElement {
  return document.querySelector('.lan-pane') as HTMLElement;
}

function status(): HTMLElement {
  return document.querySelector('.lan-host-status') as HTMLElement;
}

beforeEach(() => {
  commands.enabled = new Set();
  commands.run.mockClear();
  ui.setInfoPane(true);
  ui.setInfoTab('general');
  ui.setActive(true);
  model.set({ selected: null });
  (hostNote as Writable<unknown>).set(null);
  (wakingIp as Writable<string | null>).set(null);
  (scanProgress as Writable<object>).set({ progress: null, hostScanProgress: null });
});

afterEach(() => {
  vi.useRealTimers();
});

describe('status line text', () => {
  const note = { ip: '192.168.1.31', text: 'Wake-up packet sent to 30:05:5C:12:34:56 at 3:44 PM.' };
  const scan = (p: Partial<ScanProgress>): ScanProgress => ({
    phase: 'ports',
    scanned: 0,
    total: 0,
    found: 0,
    running: true,
    current_ip: '192.168.1.31',
    ...p
  });

  it('shows the selected host’s latest note, and nothing for others', () => {
    expect(hostStatus('192.168.1.31', note, null, null)).toEqual({ text: note.text, busy: false });
    expect(hostStatus('192.168.1.40', note, null, null).text).toBe('');
    expect(hostStatus(null, note, null, null).text).toBe('');
  });

  it('shows a wake being sent', () => {
    expect(hostStatus('192.168.1.31', note, null, '192.168.1.31').text).toBe('Sending a wake-up packet…');
    expect(hostStatus('192.168.1.31', null, null, '192.168.1.40').text).toBe('');
  });

  it('follows the host’s deep scan, busy for assistive technology', () => {
    expect(hostStatus('192.168.1.31', note, scan({}), null)).toEqual({ text: 'Deep scan starting…', busy: true });
    expect(hostStatus('192.168.1.31', null, scan({ scanned: 412, total: 2048, found: 4 }), null)).toEqual({
      text: 'Deep scan: 412 of 2,048 ports, 4 open.',
      busy: true
    });
    expect(hostStatus('192.168.1.31', null, scan({ scanned: 1, total: 1, found: 1 }), null).text).toBe(
      'Deep scan: 1 of 1 port, 1 open.'
    );
    expect(hostStatus('192.168.1.40', null, scan({ total: 2048 }), null).text).toBe('');
    expect(hostStatus('192.168.1.31', note, scan({ running: false }), null).text).toBe(note.text);
  });
});

describe('tabs', () => {
  it('pair General, Ports and Fingerprint with their panels, General in front', () => {
    render(HostInfoPane);

    const tabs = screen.getAllByRole('tab');
    expect(tabs.map((t) => t.textContent)).toEqual(['General', 'Ports', 'Fingerprint']);
    expect(tabs.map((t) => t.getAttribute('aria-selected'))).toEqual(['true', 'false', 'false']);
    expect(screen.getByRole('tablist').getAttribute('aria-label')).toBe('Host Information');

    const panels = Array.from(document.querySelectorAll('.osm-tab-pane > *')) as HTMLElement[];
    expect(panels.map((p) => p.className.split(' ')[0])).toEqual([
      'lan-info-general',
      'lan-info-ports',
      'lan-info-fingerprint'
    ]);
    expect(panels.map((p) => p.hidden)).toEqual([false, true, true]);
    expect(panels[1].getAttribute('aria-labelledby')).toBe(tabs[1].id);
  });

  it('follow ui.infoTab, and report the reader’s choice to it', async () => {
    ui.setInfoTab('fingerprint');
    render(HostInfoPane);
    expect(screen.getByRole('tab', { name: 'Fingerprint' }).getAttribute('aria-selected')).toBe('true');

    ui.setInfoTab('ports');
    flushSync();
    expect(screen.getByRole('tab', { name: 'Ports' }).getAttribute('aria-selected')).toBe('true');
    expect((document.querySelector('.lan-info-ports') as HTMLElement).hidden).toBe(false);

    await fireEvent.click(screen.getByRole('tab', { name: 'General' }), { detail: 0 });
    expect(get(ui).infoTab).toBe('general');
  });
});

it('hides itself with the pane', () => {
  render(HostInfoPane);
  expect(pane().hidden).toBe(false);

  ui.setInfoPane(false);
  flushSync();
  expect(pane().hidden).toBe(true);
});

describe('buttons', () => {
  function button(name: string): HTMLButtonElement {
    return screen.getByRole('button', { name }) as HTMLButtonElement;
  }

  it('are enabled as the commands are, and run them', async () => {
    render(HostInfoPane);
    select(printer);
    expect([button('Wake').disabled, button('Deep Scan').disabled, button('Open').disabled]).toEqual([
      true,
      true,
      true
    ]);

    enable('host.wake', 'host.deepScan', 'host.open');
    expect([button('Wake').disabled, button('Deep Scan').disabled, button('Open').disabled]).toEqual([
      false,
      false,
      false
    ]);

    await fireEvent.click(button('Wake'), { detail: 0 });
    await fireEvent.click(button('Deep Scan'), { detail: 0 });
    await fireEvent.click(button('Open'), { detail: 0 });
    expect(commands.run.mock.calls.map((c) => c[0])).toEqual([
      { id: 'host.wake' },
      { id: 'host.deepScan' },
      { id: 'host.open' }
    ]);
  });

  it('stay enabled while an alert is up, to take the keyboard back after it', () => {
    render(HostInfoPane);
    select(printer);
    enable('host.wake', 'host.deepScan', 'host.open');

    (commandContext as Writable<object>).set({ modal: true });
    flushSync();
    expect([button('Wake').disabled, button('Deep Scan').disabled, button('Open').disabled]).toEqual([
      false,
      false,
      false
    ]);
  });

  it('Open is the default button', () => {
    render(HostInfoPane);
    expect(button('Open').classList.contains('osm-default')).toBe(true);
  });

  it('Return presses Open after its flash, but not from the name field', () => {
    vi.useFakeTimers();
    render(HostInfoPane);
    select(printer);
    enable('host.open');

    fireEvent.keyDown(document.body, { key: 'Enter' });
    expect(button('Open').classList.contains('osm-pressed')).toBe(true);
    vi.advanceTimersByTime(200);
    expect(commands.run).toHaveBeenCalledWith({ id: 'host.open' });

    commands.run.mockClear();
    fireEvent.keyDown(screen.getByRole('textbox', { name: 'Name' }), { key: 'Enter' });
    vi.advanceTimersByTime(200);
    expect(commands.run).not.toHaveBeenCalled();
  });

  it('Return does nothing while Open is dimmed', () => {
    vi.useFakeTimers();
    render(HostInfoPane);
    select(printer);

    fireEvent.keyDown(document.body, { key: 'Enter' });
    vi.advanceTimersByTime(200);
    expect(commands.run).not.toHaveBeenCalled();
  });
});

describe('host status line', () => {
  it('is a polite live region with the selected host’s result', () => {
    render(HostInfoPane);
    expect(status().getAttribute('role')).toBe('status');
    expect(status().getAttribute('aria-live')).toBe('polite');

    select(printer);
    (hostNote as Writable<unknown>).set({ ip: '192.168.1.31', text: 'Deep scan finished at 3:44 PM: 5 open ports.' });
    flushSync();
    expect(status().textContent).toBe('Deep scan finished at 3:44 PM: 5 open ports.');

    select(hostRow(host({ ip: '192.168.1.40' })));
    expect(status().textContent).toBe('');
  });

  it('shows a wake being sent and a deep scan’s progress', () => {
    render(HostInfoPane);
    select(printer);

    (wakingIp as Writable<string | null>).set('192.168.1.31');
    flushSync();
    expect(status().textContent).toBe('Sending a wake-up packet…');
    (wakingIp as Writable<string | null>).set(null);

    deepScanning({ scanned: 412, total: 2048, found: 4 });
    expect(status().textContent).toBe('Deep scan: 412 of 2,048 ports, 4 open.');
    expect(status().getAttribute('aria-busy')).toBe('true');

    deepScanning({ running: false });
    expect(status().textContent).toBe('');
    expect(status().hasAttribute('aria-busy')).toBe(false);
  });
});

describe('Rename…', () => {
  it('publishes the pane’s handle while mounted', () => {
    const { unmount } = render(HostInfoPane);
    expect(get(infoPaneApi)).not.toBeNull();
    unmount();
    expect(get(infoPaneApi)).toBeNull();
  });

  it('reaches the name field in a hidden pane showing another tab', () => {
    ui.setInfoPane(false);
    ui.setInfoTab('ports');
    render(HostInfoPane);
    select(printer);

    // What actions.beginRename does.
    ui.setInfoPane(true);
    ui.setInfoTab('general');
    get(infoPaneApi)?.focusName(true);

    const field = screen.getByRole('textbox', { name: 'Name' }) as HTMLInputElement;
    expect(pane().hidden).toBe(false);
    expect(screen.getByRole('tab', { name: 'General' }).getAttribute('aria-selected')).toBe('true');
    expect(document.activeElement).toBe(field);
    expect(field.selectionEnd).toBe(field.value.length);
  });
});
