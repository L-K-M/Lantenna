// Owner: unit D (spec 8.4). Spec: 5.2 (every row), 5.6 (announce).
import { describe, expect, it } from 'vitest';
import type { Host, NetworkInterface, ScanProgress } from '$lib/types';
import { formatClock } from '$lib/util/format';
import type { ScanProgressState, ScanStoreState } from '$lib/util/scanStore';
import { headerState, type HeaderInput } from './headerText';
import type { HostModel, HostRow } from './hostModel';

const EN0: NetworkInterface = {
  name: 'en0',
  ip: '192.168.1.23',
  cidr: 24,
  subnet: '192.168.1.0/24',
  host_count: 254,
  is_default_route: true
};
const EN7: NetworkInterface = {
  name: 'en7',
  ip: '10.0.4.2',
  cidr: 16,
  subnet: '10.0.0.0/16',
  host_count: 65534,
  is_default_route: false
};

const NOW = new Date(2026, 8, 27, 16, 0);
const LAST_SCAN = new Date(2026, 8, 27, 15, 42);
const AT = `at ${formatClock(LAST_SCAN)}`;

function host(ip: string): Host {
  return { ip, name: null, reachable: true, open_ports: [], last_seen: '', fingerprint: null };
}

function rows(n: number): HostRow[] {
  return Array.from({ length: n }, (_, i) => ({ ip: `192.168.1.${i + 1}` }) as HostRow);
}

const IDLE_STORE: ScanStoreState = {
  interfaces: [EN0, EN7],
  selectedInterface: 'en0|192.168.1.23',
  scanApproach: 'balanced',
  hosts: [host('192.168.1.1')],
  newHostIps: [],
  customNames: {},
  favoriteIps: [],
  hiddenIps: [],
  showHiddenEntries: false,
  staleFavoriteIps: [],
  scanning: false,
  stopping: false,
  pendingIps: [],
  loading: false,
  error: null,
  query: '',
  selectedHostIp: null,
  lastScanAt: LAST_SCAN.toISOString(),
  lastScanCancelled: false
};

const MODEL: HostModel = {
  rows: rows(24),
  universe: 24,
  newCount: 0,
  hiddenCount: 0,
  selected: null,
  loading: false,
  loadingText: '',
  emptyText: ''
};

function progress(phase: ScanProgress['phase'], scanned: number, total: number, found = 0): ScanProgress {
  return { phase, scanned, total, found, running: true, current_ip: null };
}

function input(over: {
  store?: Partial<ScanStoreState>;
  progress?: Partial<ScanProgressState>;
  model?: Partial<HostModel>;
  lastError?: HeaderInput['lastError'];
  selectedInterface?: NetworkInterface | null;
  balloons?: HeaderInput['balloons'];
} = {}): HeaderInput {
  return {
    store: { ...IDLE_STORE, ...over.store },
    progress: { progress: null, hostScanProgress: null, ...over.progress },
    model: { ...MODEL, ...over.model },
    lastError: over.lastError ?? null,
    selectedInterface: over.selectedInterface === undefined ? EN0 : over.selectedInterface,
    balloons: over.balloons ?? 'shown'
  };
}

const scanning = (p: ScanProgress | null, over: Partial<ScanStoreState> = {}) =>
  input({ store: { scanning: true, ...over }, progress: { progress: p } });

describe('row by row (first match wins)', () => {
  it('1: reading the last scan while the store loads', () => {
    const h = headerState(input({ store: { loading: true, scanning: true, error: 'x' } }), NOW);
    expect(h).toEqual({
      text: 'Reading the last scan…',
      announce: 'Reading the last scan…',
      busy: true,
      progress: null,
      icon: null
    });
  });

  it('2: stopping keeps the bar the phase showed', () => {
    const h = headerState(scanning(progress('ping', 40, 245, 11), { stopping: true }), NOW);
    expect(h.text).toBe('Stopping scan…');
    expect(h.busy).toBe(true);
    expect(h.progress).toEqual({ value: 40, max: 245, label: 'Scan progress: Stopping scan…' });

    const identifying = headerState(scanning(progress('fingerprint', 0, 11), { stopping: true }), NOW);
    expect(identifying.progress).toEqual({ indeterminate: true, label: 'Scan progress: Stopping scan…' });
  });

  it('3: starting, before discovery knows its total', () => {
    for (const p of [null, progress('discovery', 0, 0)]) {
      const h = headerState(scanning(p), NOW);
      expect(h).toMatchObject({ text: 'Starting scan…', busy: true, progress: null });
    }
  });

  it('4: discovery, with the sampled wording above 4,096 addresses', () => {
    const h = headerState(scanning(progress('discovery', 112, 254, 9)), NOW);
    expect(h.text).toBe('Looking for hosts: 112 of 254 addresses, 9 hosts found.');
    expect(h.progress).toEqual({
      value: 112,
      max: 254,
      label: 'Scan progress: Looking for hosts: 112 of 254 addresses, 9 hosts found.'
    });

    const one = headerState(scanning(progress('discovery', 1, 254, 1)), NOW);
    expect(one.text).toBe('Looking for hosts: 1 of 254 addresses, 1 host found.');

    const sampled = headerState(
      input({ store: { scanning: true }, progress: { progress: progress('discovery', 112, 4096, 9) }, selectedInterface: EN7 }),
      NOW
    );
    expect(sampled.text).toBe('Looking for hosts: 112 of 4,096 sampled addresses, 9 hosts found.');
  });

  it('5: ping', () => {
    const h = headerState(scanning(progress('ping', 40, 245, 11)), NOW);
    expect(h.text).toBe('Pinging quiet addresses: 40 of 245, 11 hosts found.');
    expect(h.progress).toMatchObject({ value: 40, max: 245 });
  });

  it('6: ports', () => {
    const h = headerState(scanning(progress('ports', 4, 11, 11)), NOW);
    expect(h.text).toBe('Probing ports: 4 of 11 hosts.');
    expect(h.progress).toMatchObject({ value: 4, max: 11 });
    expect(headerState(scanning(progress('ports', 0, 1, 1)), NOW).text).toBe('Probing ports: 0 of 1 host.');
  });

  it('7 and 8: fingerprint, without a bar', () => {
    const h = headerState(scanning(progress('fingerprint', 0, 11)), NOW);
    expect(h).toMatchObject({
      text: 'Identifying 11 hosts…',
      busy: true,
      progress: { indeterminate: true, label: 'Scan progress: Identifying 11 hosts…' }
    });
    expect(headerState(scanning(progress('fingerprint', 0, 0)), NOW).progress).toEqual({
      indeterminate: true,
      label: 'Scan progress: Finishing scan…'
    });
    expect(headerState(scanning(progress('fingerprint', 0, 1)), NOW).text).toBe('Identifying 1 host…');
    expect(headerState(scanning(progress('fingerprint', 0, 0)), NOW).text).toBe('Finishing scan…');
  });

  it('counts a scan resumed from progress alone (the store not yet scanning)', () => {
    const h = headerState(input({ progress: { progress: progress('ports', 2, 5, 5) } }), NOW);
    expect(h.text).toBe('Probing ports: 2 of 5 hosts.');
  });

  it('9: a deep scan while no network scan runs', () => {
    const deep: ScanProgress = { ...progress('ports', 412, 2048, 4), current_ip: '192.168.1.31' };
    const h = headerState(input({ progress: { hostScanProgress: deep } }), NOW);
    expect(h).toEqual({
      text: 'Deep scan of 192.168.1.31: 412 of 2,048 ports, 4 open.',
      announce: 'Deep scan of 192.168.1.31…',
      busy: true,
      progress: { value: 412, max: 2048, label: 'Deep scan progress for 192.168.1.31: 412 of 2,048 ports' },
      icon: null
    });

    const starting = headerState(input({ progress: { hostScanProgress: { ...deep, scanned: 0, total: 0 } } }), NOW);
    expect(starting).toMatchObject({ text: 'Deep scan of 192.168.1.31…', progress: null });

    // A network scan's rows come first.
    const both = headerState(
      input({ store: { scanning: true }, progress: { progress: progress('ports', 4, 11), hostScanProgress: deep } }),
      NOW
    );
    expect(both.text).toBe('Probing ports: 4 of 11 hosts.');

    // A failed last scan's line (rows 10 and 11) comes after.
    const afterFailure = headerState(
      input({ store: { error: 'Boom' }, lastError: { kind: 'scan', message: 'Boom' }, progress: { hostScanProgress: deep } }),
      NOW
    );
    expect(afterFailure).toMatchObject({ text: 'Deep scan of 192.168.1.31: 412 of 2,048 ports, 4 open.', icon: null });
    expect(afterFailure.progress).not.toBeNull();
  });

  it('10: the scanner failed to start', () => {
    const h = headerState(
      input({
        store: { error: 'Failed to list network interfaces' },
        lastError: { kind: 'init', message: 'Failed to list network interfaces' }
      }),
      NOW
    );
    expect(h).toEqual({
      text: 'Lantenna couldn’t start its scanner. Lantenna couldn’t read this computer’s network interfaces. Try again in a moment.',
      announce:
        'Lantenna couldn’t start its scanner. Lantenna couldn’t read this computer’s network interfaces. Try again in a moment.',
      busy: false,
      progress: null,
      icon: 'stop'
    });
  });

  it('11: the last scan failed to start or finish', () => {
    for (const kind of ['start', 'scan'] as const) {
      const h = headerState(
        input({ store: { error: "Interface 'en0' not found" }, lastError: { kind, message: 'x' } }),
        NOW
      );
      expect(h.text).toBe(
        'The last scan didn’t finish. The interface en0 is no longer available. Choose another interface, then click Scan.'
      );
      expect(h.icon).toBe('stop');
    }
    // Without a recorded kind, the store's error still shows.
    expect(headerState(input({ store: { error: 'Boom' } }), NOW).text).toBe('The last scan didn’t finish. Boom.');
  });

  it('12: no interfaces', () => {
    const h = headerState(input({ store: { interfaces: [] }, selectedInterface: null }), NOW);
    expect(h).toMatchObject({
      text: 'No network interface with an IPv4 subnet was found.',
      busy: false,
      icon: 'caution'
    });
  });

  it('13: an interface with nothing to scan', () => {
    const p2p = { ...EN0, name: 'utun3', subnet: '10.8.0.2/32', host_count: 0 };
    const h = headerState(input({ selectedInterface: p2p }), NOW);
    expect(h.text).toBe('utun3 (10.8.0.2/32) has no other addresses to scan. Choose another interface.');
    expect(h.icon).toBe('caution');
  });

  it('14: first launch, with the balloon hint while balloons are hidden', () => {
    const never = { lastScanAt: null, hosts: [] };
    // The count row 4 will report: the scan skips this computer's own
    // address, so a /24's 254 host addresses are 253 to search.
    const hinted = headerState(input({ store: never, balloons: 'hidden' }), NOW);
    expect(hinted.text).toBe(
      'Click Scan to search 253 addresses on en0 (192.168.1.0/24). This computer is 192.168.1.23. For help, choose Show Balloons from the Help menu.'
    );
    expect(headerState(input({ store: never, balloons: 'shown' }), NOW).text).toBe(
      'Click Scan to search 253 addresses on en0 (192.168.1.0/24). This computer is 192.168.1.23.'
    );
    // Above 4,096 addresses the scan samples, and the hint says so.
    expect(headerState(input({ store: never, selectedInterface: EN7, balloons: 'shown' }), NOW).text).toBe(
      'Click Scan to search 4,096 sampled addresses on en7 (10.0.0.0/16). This computer is 10.0.4.2.'
    );
    const exactly = { ...EN7, host_count: 4097 };
    expect(headerState(input({ store: never, selectedInterface: exactly, balloons: 'shown' }), NOW).text).toBe(
      'Click Scan to search 4,096 addresses on en7 (10.0.0.0/16). This computer is 10.0.4.2.'
    );
    const slash30 = { ...EN0, ip: '192.168.1.22', subnet: '192.168.1.20/30', host_count: 2 };
    expect(headerState(input({ store: never, selectedInterface: slash30, balloons: 'shown' }), NOW).text).toBe(
      'Click Scan to search 1 address on en0 (192.168.1.20/30). This computer is 192.168.1.22.'
    );
  });

  it('15: idle counts with plurals and the last scan', () => {
    expect(headerState(input({ model: { newCount: 2, hiddenCount: 3 } }), NOW).text).toBe(
      `24 hosts, 2 new, 3 hidden. Last scan today ${AT}.`
    );
    expect(headerState(input({ model: { rows: rows(1), universe: 1, hiddenCount: 1 } }), NOW).text).toBe(
      `1 host, 1 hidden. Last scan today ${AT}.`
    );
    expect(headerState(input({ model: { rows: [], universe: 0 } }), NOW).text).toBe(`0 hosts. Last scan today ${AT}.`);
    expect(
      headerState(input({ model: { rows: rows(2048), universe: 2048, newCount: 1024 } }), NOW).text
    ).toBe(`2,048 hosts, 1,024 new. Last scan today ${AT}.`);
  });

  it('15: a stopped last scan, another day, and no scan at all', () => {
    const stopped = headerState(input({ store: { lastScanCancelled: true } }), NOW);
    expect(stopped.text).toBe(`24 hosts. The last scan was stopped today ${AT}.`);

    const tomorrow = new Date(2026, 8, 28, 9, 0);
    expect(headerState(input(), tomorrow).text).toBe(`24 hosts. Last scan yesterday ${AT}.`);

    // Favorites listed before any scan: counts only.
    expect(headerState(input({ store: { lastScanAt: null } }), NOW).text).toBe('24 hosts.');
    expect(headerState(input({ store: { lastScanAt: 'garbage' } }), NOW).text).toBe('24 hosts.');
  });

  it('16: Show or Find narrows the list', () => {
    const h = headerState(input({ model: { rows: rows(5), newCount: 2 } }), NOW);
    expect(h.text).toBe(`Showing 5 of 24 hosts. Last scan today ${AT}.`);
    expect(headerState(input({ model: { rows: [], universe: 1 } }), NOW).text).toBe(
      `Showing 0 of 1 host. Last scan today ${AT}.`
    );
    expect(
      headerState(input({ store: { lastScanCancelled: true }, model: { rows: rows(5) } }), NOW).text
    ).toBe(`Showing 5 of 24 hosts. The last scan was stopped today ${AT}.`);
  });
});

describe('announce (5.6)', () => {
  it('names the phase without its counts', () => {
    const a = headerState(scanning(progress('discovery', 3, 254, 1)), NOW).announce;
    const b = headerState(scanning(progress('discovery', 200, 254, 30)), NOW).announce;
    expect(a).toBe('Looking for hosts…');
    expect(b).toBe(a);
    expect(headerState(scanning(progress('ping', 1, 2, 3)), NOW).announce).toBe('Pinging quiet addresses…');
    expect(headerState(scanning(progress('ports', 1, 2, 3)), NOW).announce).toBe('Probing ports…');
    expect(headerState(scanning(progress('fingerprint', 0, 11)), NOW).announce).toBe('Identifying 11 hosts…');
  });

  it('says the idle sentence, unchanged by Show and Find', () => {
    const all = headerState(input({ model: { newCount: 2 } }), NOW);
    const narrowed = headerState(input({ model: { rows: rows(3), newCount: 2 } }), NOW);
    expect(all.announce).toBe(`24 hosts, 2 new. Last scan today ${AT}.`);
    expect(narrowed.announce).toBe(all.announce);
    expect(narrowed.text).not.toBe(all.text);
  });
});

it('keeps a bar value within its range', () => {
  const h = headerState(scanning(progress('ports', 13, 11, 11)), NOW);
  expect(h.progress).toMatchObject({ value: 11, max: 11 });
  expect(headerState(scanning(progress('ping', 0, 0, 5)), NOW).progress).toBeNull();
});
