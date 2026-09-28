// Owner: unit C (spec 8.4): the Ports panel's rows, sort, caption texts
// and placeholders, and opening a port (2.7).
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte';
import { flushSync } from 'svelte';
import type { Writable } from 'svelte/store';
import type { ScanProgressState } from '$lib/util/scanStore';
import { host, hostRow } from './hostRow.fixture';
import InfoPorts, { portCaption, portRows, sortPortRows } from './InfoPorts.svelte';

vi.mock('$lib/app/actions', () => ({ openUrl: vi.fn(async () => {}) }));
vi.mock('$lib/util/scanStore', async () => {
  const { writable } = await import('svelte/store');
  return { scanProgress: writable({ progress: null, hostScanProgress: null }) };
});

const { openUrl } = await import('$lib/app/actions');
const { scanProgress } = await import('$lib/util/scanStore');

const nas = host({
  ip: '192.168.1.50',
  open_ports: [
    { port: 445, state: 'open', service: 'microsoft-ds', banner: null },
    { port: 22, state: 'open', service: 'ssh', banner: 'SSH-2.0-OpenSSH_9.6' },
    { port: 9999, state: 'open', service: null, banner: null }
  ]
});

function cells(): string[][] {
  return Array.from(document.querySelectorAll('.osm-lv-rows .osm-lv-row')).map((r) =>
    Array.from(r.querySelectorAll('.osm-lv-cell')).map((c) => c.textContent ?? '')
  );
}

function caption(): string[] {
  return Array.from(document.querySelectorAll('.lan-caption .lan-line')).map((l) => l.textContent ?? '');
}

function grid(): HTMLElement {
  return screen.getByRole('grid', { name: 'Open ports' });
}

beforeEach(() => {
  vi.clearAllMocks();
  (scanProgress as Writable<ScanProgressState>).set({ progress: null, hostScanProgress: null });
});

describe('rows', () => {
  it('are one per port, with its service (or unknown), banner and target', () => {
    const rows = portRows(nas);
    expect(rows.map((p) => [p.port, p.service, p.banner, p.target?.url ?? null])).toEqual([
      [445, 'microsoft-ds', '', 'smb://192.168.1.50'],
      [22, 'ssh', 'SSH-2.0-OpenSSH_9.6', 'ssh://192.168.1.50'],
      [9999, 'unknown', '', null]
    ]);
    expect(portRows(nas)).toBe(rows);
  });

  it('drop a repeated port number', () => {
    const twice = host({
      open_ports: [
        { port: 80, state: 'open', service: 'http', banner: null },
        { port: 80, state: 'open', service: 'http-alt', banner: null }
      ]
    });
    expect(portRows(twice).map((p) => p.service)).toEqual(['http']);
  });

  it('sort by port or service, either way', () => {
    const rows = portRows(nas);
    expect(sortPortRows(rows, { column: 'port', order: 'normal' }).map((p) => p.port)).toEqual([22, 445, 9999]);
    expect(sortPortRows(rows, { column: 'port', order: 'reversed' }).map((p) => p.port)).toEqual([9999, 445, 22]);
    expect(sortPortRows(rows, { column: 'service', order: 'normal' }).map((p) => p.service)).toEqual([
      'microsoft-ds',
      'ssh',
      'unknown'
    ]);
  });
});

describe('caption', () => {
  it('describes the selected port in three lines', () => {
    const [smb, ssh, other] = portRows(nas);
    expect(portCaption(ssh)).toEqual(['22 ssh', 'SSH-2.0-OpenSSH_9.6', 'Opens ssh://192.168.1.50.']);
    expect(portCaption(smb)).toEqual(['445 microsoft-ds', 'No banner.', 'Opens smb://192.168.1.50.']);
    expect(portCaption(other)).toEqual(['9999 unknown', 'No banner.', 'Lantenna can’t open this service.']);
  });

  it('asks for a port without one', () => {
    expect(portCaption(null)).toEqual(['Select a port to see its banner.']);
  });
});

describe('the panel', () => {
  it('shows the prompt without a selection', () => {
    render(InfoPorts, { props: { row: null } });
    expect(screen.getByText('Select a host to see its information.').hidden).toBe(false);
    expect((document.querySelector('.lan-body') as HTMLElement).hidden).toBe(true);
  });

  it('lists the ports by number with Port, Service, Opens and Banner', () => {
    render(InfoPorts, { props: { row: hostRow(nas) } });

    expect(screen.getByText('Select a host to see its information.').hidden).toBe(true);
    expect(cells()).toEqual([
      ['22', 'ssh', 'SSH', 'SSH-2.0-OpenSSH_9.6'],
      ['445', 'microsoft-ds', 'SMB', ''],
      ['9999', 'unknown', '', '']
    ]);
    expect(caption()).toEqual(['Select a port to see its banner.']);
  });

  it('captions the selected port and opens it with Return', async () => {
    render(InfoPorts, { props: { row: hostRow(nas) } });

    await fireEvent.keyDown(grid(), { key: 'ArrowDown' });
    expect(caption()).toEqual(['22 ssh', 'SSH-2.0-OpenSSH_9.6', 'Opens ssh://192.168.1.50.']);
    expect(document.querySelector('.lan-caption .lan-line')?.classList.contains('osm-label')).toBe(true);

    await fireEvent.keyDown(grid(), { key: 'Enter' });
    expect(openUrl).toHaveBeenCalledWith('ssh://192.168.1.50');
  });

  it('opens nothing for a port without a target', async () => {
    render(InfoPorts, { props: { row: hostRow(nas) } });
    await fireEvent.keyDown(grid(), { key: 'End' });
    await fireEvent.keyDown(grid(), { key: 'Enter' });
    expect(caption()[2]).toBe('Lantenna can’t open this service.');
    expect(openUrl).not.toHaveBeenCalled();
  });

  it('starts a new host with no port selected', async () => {
    const { rerender } = render(InfoPorts, { props: { row: hostRow(nas) } });
    await fireEvent.keyDown(grid(), { key: 'ArrowDown' });

    await rerender({ row: hostRow() });

    expect(caption()).toEqual(['Select a port to see its banner.']);
    expect(document.querySelector('.osm-lv-row.osm-selected')).toBeNull();
  });

  it('says when there are no open ports, without a caption', () => {
    render(InfoPorts, { props: { row: hostRow(host({ open_ports: [] })) } });
    expect(screen.getByRole('status').textContent).toBe('No open ports found.');
    expect(caption()).toEqual([]);
  });

  it('says it is scanning while a deep scan of the host has found nothing yet', () => {
    const row = hostRow(host({ open_ports: [] }));
    render(InfoPorts, { props: { row } });

    const running = { phase: 'ports', scanned: 0, total: 0, found: 0, running: true } as const;
    (scanProgress as Writable<ScanProgressState>).set({
      progress: null,
      hostScanProgress: { ...running, current_ip: row.ip }
    });
    flushSync();
    expect(screen.getByRole('status').textContent).toBe('Scanning ports…');

    (scanProgress as Writable<ScanProgressState>).set({
      progress: null,
      hostScanProgress: { ...running, current_ip: '192.168.1.99' }
    });
    flushSync();
    expect(screen.getByRole('status').textContent).toBe('No open ports found.');
  });
});
