// Owner: unit C (spec 8.4). Test support for the info pane's tests: Host
// and HostRow values as unit B's model would build them. Not app code.

import type { HostRow } from '$lib/app/hostModel';
import { ipOrder } from '$lib/app/hostSort';
import type { DeviceFingerprint, Host } from '$lib/types';
import { getPortTarget, primaryPortTarget, type PortTarget } from '$lib/util/portTargets';

export function fingerprint(overrides: Partial<DeviceFingerprint> = {}): DeviceFingerprint {
  return {
    mac_address: '30:05:5C:12:34:56',
    oui: '30055C',
    vendor: 'Brother Industries, Ltd.',
    manufacturer: null,
    model_guess: 'HL-L2350DW',
    device_type: 'Printer',
    os_guess: 'Linux-like',
    confidence: 87,
    sources: ['arp-table', 'mdns'],
    notes: ['mDNS service: _ipp._tcp', 'Printer service detected via mDNS'],
    discovered_services: [],
    last_updated: '2026-09-27T13:42:00Z',
    ...overrides
  };
}

export function host(overrides: Partial<Host> = {}): Host {
  return {
    ip: '192.168.1.31',
    name: 'BRN30055C123456.local',
    reachable: true,
    open_ports: [
      { port: 80, state: 'open', service: 'http', banner: 'lighttpd/1.4.59' },
      { port: 631, state: 'open', service: 'ipp', banner: null }
    ],
    last_seen: '2026-09-27T13:42:00Z',
    fingerprint: fingerprint(),
    ...overrides
  };
}

export function hostRow(h: Host = host(), overrides: Partial<HostRow> = {}): HostRow {
  const targets = h.open_ports
    .map((p) => getPortTarget(h.ip, p.port, p.service))
    .filter((t): t is PortTarget => t !== null);
  const customName = overrides.customName ?? null;

  return {
    ip: h.ip,
    ipNum: ipOrder(h.ip),
    host: h,
    customName,
    listName: customName || h.name || 'Unknown',
    iconName: customName || h.name?.replace(/\.local$/, '') || h.ip,
    icon: { kind: 'printer', label: 'Printer', small: 'var(--osm-sprite-lan-printer)', large: '/printer.svg' },
    kind: 'Printer',
    vendor: 'Brother Industries',
    vendorFull: 'Brother Industries, Ltd.',
    portsText: h.open_ports.map((p) => p.port).join(', ') || '--',
    portCount: h.open_ports.length,
    lastSeenMs: Date.parse(h.last_seen),
    status: '',
    favorite: false,
    hidden: false,
    stale: false,
    pending: false,
    isNew: false,
    targets,
    primaryTarget: primaryPortTarget(h),
    ...overrides
  };
}
