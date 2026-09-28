// Owner: unit B (spec 8.4). The host model: display rules, row state,
// filters, counts, the selected host, placeholders (3.4) and the row
// cache the list view's identity check relies on.
import { afterEach, describe, expect, it } from 'vitest';
import { get } from 'svelte/store';
import type { ListViewSort } from 'osmium-ui';
import printerSvg from '$lib/assets/host-icons/printer.svg';
import { makeFingerprint, makeHost, makePorts, makeState } from '../../test/hosts';
import { buildHostModel, hostModel } from './hostModel';
import { ui } from './ui';

const BY_IP: ListViewSort = { column: 'ip', order: 'normal' };
const DEFAULT_SORT: ListViewSort = { column: 'favorite', order: 'normal' };

function model(...args: Parameters<typeof makeState>) {
  return buildHostModel(makeState(...args), 'all', BY_IP);
}

function onlyRow(...args: Parameters<typeof makeState>) {
  const rows = model(...args).rows;
  expect(rows).toHaveLength(1);
  return rows[0];
}

describe('rows', () => {
  it('names hosts by custom name, detected name, then Unknown or the IP', () => {
    const custom = onlyRow({
      hosts: [makeHost('10.0.0.5', { name: 'nas.local' })],
      customNames: { '10.0.0.5': '  Storage  ' }
    });
    expect(custom).toMatchObject({ customName: 'Storage', listName: 'Storage', iconName: 'Storage' });

    const detected = onlyRow({ hosts: [makeHost('10.0.0.5', { name: 'nas.local' })] });
    expect(detected).toMatchObject({ customName: null, listName: 'nas.local', iconName: 'nas' });

    const unnamed = onlyRow({ hosts: [makeHost('10.0.0.5')] });
    expect(unnamed).toMatchObject({ listName: 'Unknown', iconName: '10.0.0.5' });
  });

  it('shows Kind from the device type, OS guess or model guess', () => {
    const kind = (fingerprint: ReturnType<typeof makeFingerprint> | null) =>
      onlyRow({ hosts: [makeHost('10.0.0.1', { fingerprint })] }).kind;

    expect(kind(null)).toBe('--');
    expect(kind(makeFingerprint())).toBe('Unknown');
    expect(kind(makeFingerprint({ device_type: 'NAS/Storage', os_guess: 'Linux-like' }))).toBe('NAS/Storage');
    expect(kind(makeFingerprint({ os_guess: 'Linux-like', model_guess: 'DS920+' }))).toBe('Linux-like');
    expect(kind(makeFingerprint({ model_guess: '  HL-L2350DW​ ' }))).toBe('HL-L2350DW');
  });

  it('shows Vendor short, and the pane’s vendor in full', () => {
    const row = (fingerprint: ReturnType<typeof makeFingerprint> | null) =>
      onlyRow({ hosts: [makeHost('10.0.0.1', { fingerprint })] });

    expect(row(null)).toMatchObject({ vendor: '--', vendorFull: 'Unknown' });
    expect(row(makeFingerprint({ vendor: 'Espressif Inc.' }))).toMatchObject({
      vendor: 'Espressif',
      vendorFull: 'Espressif Inc.'
    });
    expect(row(makeFingerprint({ manufacturer: 'Hangzhou Hikvision Digital Technology' }))).toMatchObject({
      vendor: 'Hikvision',
      vendorFull: 'Hangzhou Hikvision Digital Technology'
    });
    expect(row(makeFingerprint({ mac_address: '02:11:22:33:44:55' }))).toMatchObject({
      vendor: 'Private address',
      vendorFull: 'Private address'
    });
    expect(row(makeFingerprint({ mac_address: '00:11:22:33:44:55' }))).toMatchObject({
      vendor: 'Unknown',
      vendorFull: 'Unknown'
    });
  });

  it('lists up to six ports, then +N, or -- without any', () => {
    const ports = (...p: number[]) => onlyRow({ hosts: [makeHost('10.0.0.1', { open_ports: makePorts(...p) })] });

    expect(ports()).toMatchObject({ portsText: '--', portCount: 0 });
    expect(ports(22, 80)).toMatchObject({ portsText: '22, 80', portCount: 2 });
    expect(ports(21, 22, 23, 80, 139, 443, 445, 631)).toMatchObject({
      portsText: '21, 22, 23, 80, 139, 443, +2',
      portCount: 8
    });
  });

  it('keeps each target once and picks the primary one', () => {
    const row = onlyRow({
      hosts: [makeHost('10.0.0.1', { open_ports: makePorts(22, [139, 'netbios-ssn'], 445, [8080, 'http-alt']) })]
    });
    expect(row.targets).toEqual([
      { label: 'SSH', url: 'ssh://10.0.0.1' },
      { label: 'SMB', url: 'smb://10.0.0.1' },
      { label: 'HTTP', url: 'http://10.0.0.1:8080' }
    ]);
    expect(row.primaryTarget).toEqual({ label: 'HTTP', url: 'http://10.0.0.1:8080' });

    expect(onlyRow({ hosts: [makeHost('10.0.0.1', { open_ports: makePorts(23) })] }).primaryTarget).toBeNull();
  });

  it('carries the icon kind, its label, the small sprite and the large SVG', () => {
    const row = onlyRow({ hosts: [makeHost('10.0.0.1', { name: 'office-printer' })] });
    expect(row.icon.kind).toBe('printer');
    expect(row.icon.label).toBe('Printer');
    expect(row.icon.small).toBe('var(--osm-sprite-lan-printer)');
    expect(row.icon.large).toBe(printerSvg);
  });

  it('reads Last Seen as a time, 0 when unknown', () => {
    const seen = (last_seen: string) => onlyRow({ hosts: [makeHost('10.0.0.1', { last_seen })] }).lastSeenMs;
    expect(seen('2026-09-27T12:00:00Z')).toBe(Date.UTC(2026, 8, 27, 12));
    expect(seen('')).toBe(0);
    expect(seen('yesterday')).toBe(0);
  });

  it('gives Status in the order New, Checking…, Not seen, Hidden', () => {
    const status = (over: Parameters<typeof makeState>[0]) =>
      onlyRow({ hosts: [makeHost('10.0.0.1')], showHiddenEntries: true, ...over }).status;
    const ip = ['10.0.0.1'];

    expect(status({})).toBe('');
    expect(status({ hiddenIps: ip })).toBe('Hidden');
    expect(status({ hiddenIps: ip, favoriteIps: ip, staleFavoriteIps: ip })).toBe('Not seen');
    expect(status({ hiddenIps: ip, pendingIps: ip })).toBe('Checking…');
    expect(status({ hiddenIps: ip, pendingIps: ip, newHostIps: ip })).toBe('New');
  });

  it('flags the row’s state', () => {
    const row = onlyRow({
      hosts: [makeHost('10.0.0.1')],
      favoriteIps: ['10.0.0.1'],
      staleFavoriteIps: ['10.0.0.1'],
      hiddenIps: ['10.0.0.1'],
      showHiddenEntries: true
    });
    expect(row).toMatchObject({ favorite: true, stale: true, hidden: true, pending: false, isNew: false });
  });
});

describe('row cache', () => {
  it('hands out the same row while its host and state stay', () => {
    const host = makeHost('10.0.0.1', { name: 'a' });
    const first = onlyRow({ hosts: [host] });
    expect(onlyRow({ hosts: [host], query: '' })).toBe(first);
  });

  it('makes a new row when the state or the host object changes', () => {
    const host = makeHost('10.0.0.1', { name: 'a' });
    const first = onlyRow({ hosts: [host] });

    const favorite = onlyRow({ hosts: [host], favoriteIps: ['10.0.0.1'] });
    expect(favorite).not.toBe(first);
    expect(favorite.favorite).toBe(true);

    const renamed = onlyRow({ hosts: [host], favoriteIps: ['10.0.0.1'], customNames: { '10.0.0.1': 'b' } });
    expect(renamed.listName).toBe('b');

    const replaced = onlyRow({ hosts: [{ ...host }], favoriteIps: ['10.0.0.1'], customNames: { '10.0.0.1': 'b' } });
    expect(replaced).not.toBe(renamed);
    expect(replaced).toEqual(renamed);
  });

  it('keeps rows immutable', () => {
    const row = onlyRow({ hosts: [makeHost('10.0.0.1')] });
    expect(Object.isFrozen(row)).toBe(true);
    expect(Object.isFrozen(row.icon)).toBe(true);
  });
});

describe('filters and counts', () => {
  const hosts = [
    makeHost('10.0.0.1', { name: 'router', fingerprint: makeFingerprint({ vendor: 'Ubiquiti' }) }),
    makeHost('10.0.0.2', { name: 'printer', open_ports: makePorts([631, 'ipp']) }),
    makeHost('10.0.0.3', { name: 'nas' }),
    makeHost('10.0.0.4', { name: 'camera' })
  ];
  const ips = (m: ReturnType<typeof model>) => m.rows.map((r) => r.ip);

  it('leaves hidden hosts out unless they are shown, and counts them', () => {
    const hidden = model({ hosts, hiddenIps: ['10.0.0.3', '10.0.0.9'], newHostIps: ['10.0.0.3', '10.0.0.4'] });
    expect(ips(hidden)).toEqual(['10.0.0.1', '10.0.0.2', '10.0.0.4']);
    expect(hidden).toMatchObject({ universe: 3, newCount: 1, hiddenCount: 1 });

    const shown = model({
      hosts,
      hiddenIps: ['10.0.0.3', '10.0.0.9'],
      newHostIps: ['10.0.0.3', '10.0.0.4'],
      showHiddenEntries: true
    });
    expect(ips(shown)).toEqual(['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']);
    expect(shown).toMatchObject({ universe: 4, newCount: 2, hiddenCount: 1 });
  });

  it('applies the Show scope', () => {
    const state = makeState({ hosts, favoriteIps: ['10.0.0.2', '10.0.0.4'], newHostIps: ['10.0.0.3'] });
    expect(buildHostModel(state, 'favorites', BY_IP).rows.map((r) => r.ip)).toEqual(['10.0.0.2', '10.0.0.4']);
    expect(buildHostModel(state, 'new', BY_IP).rows.map((r) => r.ip)).toEqual(['10.0.0.3']);
    expect(buildHostModel(state, 'favorites', BY_IP).universe).toBe(4);
  });

  it('matches every Find term against names, vendors, ports and custom names', () => {
    expect(ips(model({ hosts, query: 'ubiquiti' }))).toEqual(['10.0.0.1']);
    expect(ips(model({ hosts, query: '631' }))).toEqual(['10.0.0.2']);
    expect(ips(model({ hosts, query: 'print ipp' }))).toEqual(['10.0.0.2']);
    expect(ips(model({ hosts, query: 'print ssh' }))).toEqual([]);
    expect(ips(model({ hosts, query: 'garage', customNames: { '10.0.0.4': 'Garage cam' } }))).toEqual(['10.0.0.4']);
    expect(ips(model({ hosts, query: '   ' }))).toHaveLength(4);
  });

  it('sorts by the given sort', () => {
    const state = makeState({ hosts, favoriteIps: ['10.0.0.3'] });
    expect(buildHostModel(state, 'all', DEFAULT_SORT).rows.map((r) => r.ip)).toEqual([
      '10.0.0.3',
      '10.0.0.1',
      '10.0.0.2',
      '10.0.0.4'
    ]);
  });

  it('selects a host the query or scope hides, but not a hidden one', () => {
    expect(model({ hosts, query: 'router', selectedHostIp: '10.0.0.3' }).selected?.ip).toBe('10.0.0.3');
    const scoped = buildHostModel(makeState({ hosts, selectedHostIp: '10.0.0.3' }), 'favorites', BY_IP);
    expect(scoped.selected?.ip).toBe('10.0.0.3');

    expect(model({ hosts, hiddenIps: ['10.0.0.3'], selectedHostIp: '10.0.0.3' }).selected).toBeNull();
    expect(
      model({ hosts, hiddenIps: ['10.0.0.3'], showHiddenEntries: true, selectedHostIp: '10.0.0.3' }).selected?.status
    ).toBe('Hidden');
    expect(model({ hosts, selectedHostIp: '10.0.0.99' }).selected).toBeNull();
    expect(model({ hosts }).selected).toBeNull();
  });

  it('gives the selected host the same row object as the list', () => {
    const m = model({ hosts, selectedHostIp: '10.0.0.2' });
    expect(m.selected).toBe(m.rows[1]);
  });
});

describe('placeholders (3.4)', () => {
  const one = [makeHost('10.0.0.1')];
  const two = [makeHost('10.0.0.1'), makeHost('10.0.0.2')];

  it('reads the last scan while the store loads', () => {
    expect(model({ loading: true })).toMatchObject({ loading: true, loadingText: 'Reading the last scan…' });
    expect(model({ loading: true, scanning: true }).loadingText).toBe('Reading the last scan…');
  });

  it('says Scanning… while a scan has found nothing yet', () => {
    expect(model({ scanning: true })).toMatchObject({ loading: true, loadingText: 'Scanning…' });
    expect(model({ scanning: true, hosts: one, query: 'zzz' }).loading).toBe(false);
    expect(model({}).loading).toBe(false);
  });

  it('explains an empty list, first match first', () => {
    const empty = (state: Parameters<typeof makeState>[0], scope: 'all' | 'favorites' | 'new' = 'all') =>
      buildHostModel(makeState(state), scope, BY_IP).emptyText;

    expect(empty({ hosts: one, query: '  zz top ' }, 'favorites')).toBe('No hosts match “zz top”.');
    expect(empty({ query: 'zz' }, 'favorites')).toBe(
      'No favorite hosts. To add one, click the star next to a host.'
    );
    expect(empty({ hosts: one }, 'new')).toBe('No new hosts since the previous scan.');
    expect(empty({ hosts: one, hiddenIps: ['10.0.0.1'] })).toBe(
      'The only host is hidden. To see it, check “Show hidden hosts”.'
    );
    expect(empty({ hosts: two, hiddenIps: ['10.0.0.1', '10.0.0.2'] })).toBe(
      'All 2 hosts are hidden. To see them, check “Show hidden hosts”.'
    );
    expect(empty({ hosts: two, hiddenIps: ['10.0.0.1'] })).toBe('No hosts yet. Click Scan to search your network.');
    expect(empty({ hosts: one, hiddenIps: ['10.0.0.1'], showHiddenEntries: true })).toBe(
      'No hosts yet. Click Scan to search your network.'
    );
    expect(empty({})).toBe('No hosts yet. Click Scan to search your network.');
  });

  it('groups the count of hidden hosts', () => {
    const many = Array.from({ length: 1234 }, (_, i) => makeHost(`10.0.${i >> 8}.${i & 255}`));
    expect(model({ hosts: many, hiddenIps: many.map((h) => h.ip) }).emptyText).toBe(
      'All 1,234 hosts are hidden. To see them, check “Show hidden hosts”.'
    );
  });
});

describe('hostModel store', () => {
  afterEach(() => {
    ui.setScope('all');
    ui.setListSort(DEFAULT_SORT);
  });

  it('follows the store and the Show scope', () => {
    // The store at launch: loading until init settles, no hosts.
    expect(get(hostModel)).toMatchObject({ rows: [], loading: true, loadingText: 'Reading the last scan…' });

    ui.setScope('favorites');
    expect(get(hostModel).emptyText).toBe('No favorite hosts. To add one, click the star next to a host.');
  });

  it('does not rebuild for window activity', () => {
    const seen: unknown[] = [];
    const stop = hostModel.subscribe((m) => seen.push(m));
    ui.setActive(false);
    ui.setActive(true);
    ui.setListSort({ column: 'ip', order: 'reversed' });
    stop();
    expect(seen).toHaveLength(2);
  });
});
