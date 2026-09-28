// Owner: unit B (spec 8.4). The list's sort (2.6): every column's normal
// order, reversal, IP ties and unnamed hosts last by Name.
import { describe, expect, it } from 'vitest';
import type { ListViewSort } from 'osmium-ui';
import { makeFingerprint, makeHost, makePorts, makeState } from '../../test/hosts';
import { buildHostModel, type HostRow } from './hostModel';
import { COLUMN_IDS, ipOrder, sortRows } from './hostSort';

const IP_ORDER: ListViewSort = { column: 'ip', order: 'normal' };

/** Rows for hosts in `state`, in IP order (the model's own). */
function rowsOf(...args: Parameters<typeof makeState>): HostRow[] {
  return [...buildHostModel(makeState(...args), 'all', IP_ORDER).rows];
}

const ips = (rows: readonly HostRow[]) => rows.map((r) => r.ip);

describe('ipOrder', () => {
  it('orders dotted quads numerically and anything else last', () => {
    expect(ipOrder('10.0.0.2')).toBeLessThan(ipOrder('10.0.0.10'));
    expect(ipOrder('9.255.255.255')).toBeLessThan(ipOrder('10.0.0.0'));
    for (const bad of ['', 'host', '10.0.0', '10.0.0.256', '10.0.0.x', '1.2.3.4.5']) {
      expect(ipOrder(bad), bad).toBe(Number.MAX_SAFE_INTEGER);
    }
  });
});

describe('sortRows', () => {
  const rows = rowsOf({
    hosts: [
      makeHost('10.0.0.10', { name: 'beta', open_ports: makePorts(22), last_seen: '2026-09-27T10:00:00Z' }),
      makeHost('10.0.0.2', { name: 'Alpha', open_ports: makePorts(22, 80, 443), last_seen: '2026-09-27T11:00:00Z' }),
      makeHost('10.0.0.3', { last_seen: '' }),
      makeHost('10.0.0.1', { name: 'gamma', open_ports: makePorts(80), last_seen: '2026-09-27T12:00:00Z' })
    ],
    favoriteIps: ['10.0.0.3', '10.0.0.10']
  });

  it('knows every column', () => {
    for (const column of COLUMN_IDS) {
      expect(sortRows(rows, { column, order: 'normal' }), column).toHaveLength(rows.length);
    }
  });

  it('puts favorites first, then goes by IP (the default sort)', () => {
    expect(ips(sortRows(rows, { column: 'favorite', order: 'normal' }))).toEqual([
      '10.0.0.3',
      '10.0.0.10',
      '10.0.0.1',
      '10.0.0.2'
    ]);
  });

  it('reverses the column but keeps IP ties ascending', () => {
    expect(ips(sortRows(rows, { column: 'favorite', order: 'reversed' }))).toEqual([
      '10.0.0.1',
      '10.0.0.2',
      '10.0.0.3',
      '10.0.0.10'
    ]);
  });

  it('sorts IP addresses numerically', () => {
    expect(ips(sortRows(rows, { column: 'ip', order: 'normal' }))).toEqual([
      '10.0.0.1',
      '10.0.0.2',
      '10.0.0.3',
      '10.0.0.10'
    ]);
    expect(ips(sortRows(rows, { column: 'ip', order: 'reversed' }))).toEqual([
      '10.0.0.10',
      '10.0.0.3',
      '10.0.0.2',
      '10.0.0.1'
    ]);
  });

  it('sorts names A to Z ignoring case, with unnamed hosts last in both orders', () => {
    expect(ips(sortRows(rows, { column: 'name', order: 'normal' }))).toEqual([
      '10.0.0.2',
      '10.0.0.10',
      '10.0.0.1',
      '10.0.0.3'
    ]);
    expect(ips(sortRows(rows, { column: 'name', order: 'reversed' }))).toEqual([
      '10.0.0.1',
      '10.0.0.10',
      '10.0.0.2',
      '10.0.0.3'
    ]);
  });

  it('compares numbers in names by value and custom names over detected ones', () => {
    const named = rowsOf({
      hosts: [
        makeHost('10.0.0.1', { name: 'host 10' }),
        makeHost('10.0.0.2', { name: 'host 9' }),
        makeHost('10.0.0.3', { name: 'zulu' })
      ],
      customNames: { '10.0.0.3': 'Aardvark' }
    });
    expect(ips(sortRows(named, { column: 'name', order: 'normal' }))).toEqual(['10.0.0.3', '10.0.0.2', '10.0.0.1']);
  });

  it('lists the most ports first and the newest sighting first', () => {
    expect(ips(sortRows(rows, { column: 'ports', order: 'normal' }))).toEqual([
      '10.0.0.2',
      '10.0.0.1',
      '10.0.0.10',
      '10.0.0.3'
    ]);
    expect(ips(sortRows(rows, { column: 'lastSeen', order: 'normal' }))).toEqual([
      '10.0.0.1',
      '10.0.0.2',
      '10.0.0.10',
      '10.0.0.3'
    ]);
    expect(ips(sortRows(rows, { column: 'lastSeen', order: 'reversed' }))).toEqual([
      '10.0.0.3',
      '10.0.0.10',
      '10.0.0.2',
      '10.0.0.1'
    ]);
  });

  it('orders the Status column New, Checking…, Not seen, Hidden, blank', () => {
    const states = rowsOf({
      hosts: ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5'].map((ip) => makeHost(ip)),
      hiddenIps: ['10.0.0.1'],
      showHiddenEntries: true,
      staleFavoriteIps: ['10.0.0.2'],
      favoriteIps: ['10.0.0.2'],
      pendingIps: ['10.0.0.3'],
      newHostIps: ['10.0.0.5']
    });
    const sorted = sortRows(states, { column: 'status', order: 'normal' });
    expect(sorted.map((r) => r.status)).toEqual(['New', 'Checking…', 'Not seen', 'Hidden', '']);
  });

  it('sorts Kind and Vendor A to Z by their shown text', () => {
    const kinds = rowsOf({
      hosts: [
        makeHost('10.0.0.1', { fingerprint: makeFingerprint({ device_type: 'Printer', vendor: 'Brother' }) }),
        makeHost('10.0.0.2', { fingerprint: makeFingerprint({ device_type: 'camera', vendor: 'Axis' }) }),
        makeHost('10.0.0.3', { fingerprint: makeFingerprint({ device_type: 'NAS/Storage', vendor: 'Synology' }) })
      ]
    });
    expect(ips(sortRows(kinds, { column: 'kind', order: 'normal' }))).toEqual(['10.0.0.2', '10.0.0.3', '10.0.0.1']);
    expect(ips(sortRows(kinds, { column: 'vendor', order: 'normal' }))).toEqual(['10.0.0.2', '10.0.0.1', '10.0.0.3']);
  });

  it('keeps the IP order for an unknown column and leaves its input alone', () => {
    const input = sortRows(rows, { column: 'name', order: 'normal' });
    const copy = [...input];
    expect(ips(sortRows(input, { column: 'bogus', order: 'reversed' }))).toEqual([
      '10.0.0.1',
      '10.0.0.2',
      '10.0.0.3',
      '10.0.0.10'
    ]);
    expect(input).toEqual(copy);
  });
});
