// Owner: unit G (spec 8.4). Spec: 8.6 (visual verification), inventory 4
// and 7 (backend surface and facts).
//
// Pure data for the mock backend (mockBackend.ts, `vite dev --mode mock`
// only): the networks it pretends to see, the last scan it pretends to
// have stored, the user data it seeds, and pure copies of the backend
// rules the scripted scans follow (scan targets and sampling, port
// profiles, service names). Times are relative to a `now` the caller
// passes, so relative dates read the same whenever the mock runs.
//
// Coverage the spec asks for (8.6): printer, Mac, router, NAS, TV,
// camera, Linux, unknown, a stale favorite with a MAC, hidden hosts, new
// hosts, long and non-Latin names, a long banner, a /16 that is sampled,
// and every HostIconKind. fixtures.test.ts checks each claim.

import type {
  DeviceFingerprint,
  Host,
  NetworkInterface,
  PortInfo,
  PortProfile,
  ScanApproach,
  ScanOptions,
  ScanResult
} from '$lib/types';
import type { Platform } from '$lib/app/platform';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

// ---------------------------------------------------------------------
// Backend rules (src-tauri/src/scanner.rs), copied so the scripted scans
// report the same totals and ports a real scan would.

/** Ports the discovery sweep probes on every address. */
export const DISCOVERY_PORTS: readonly number[] = [22, 80, 443, 445, 62078];

const SIGNATURE_PORTS = [
  22, 80, 443, 445, 548, 554, 631, 1883, 3389, 5000, 5001, 7000, 8009, 8080, 8123, 8443, 9100, 32400, 62078
];
const QUICK_EXTRA_PORTS = [21, 23, 53, 110, 135, 139, 143, 515, 5900, 8000];
const STANDARD_EXTRA_PORTS = [
  25, 88, 111, 119, 389, 465, 587, 636, 873, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049, 2375, 3000, 3306,
  3689, 5060, 5432, 5672, 6053, 6379, 6443, 7001, 8008, 8081, 8291, 8554, 8728, 8729, 8883, 8888, 9000, 9090,
  9200, 27017, 37777, 37778
];
const DEEP_RANGE_END = 2048;

/** The ports a profile probes, ascending (scanner.rs ports_for_profile). */
export function portsForProfile(profile: PortProfile): number[] {
  const ports = new Set([...SIGNATURE_PORTS, ...QUICK_EXTRA_PORTS]);
  if (profile !== 'quick') for (const p of STANDARD_EXTRA_PORTS) ports.add(p);
  if (profile === 'deep') for (let p = 1; p <= DEEP_RANGE_END; p++) ports.add(p);
  return [...ports].sort((a, b) => a - b);
}

/** scanner.rs service_name, for the ports the fixtures use. */
const SERVICE_NAMES: Readonly<Record<number, string>> = {
  21: 'ftp',
  22: 'ssh',
  53: 'dns',
  80: 'http',
  88: 'kerberos',
  111: 'rpcbind',
  135: 'msrpc',
  139: 'netbios-ssn',
  443: 'https',
  445: 'smb',
  515: 'printer',
  548: 'afp',
  554: 'rtsp',
  631: 'ipp',
  873: 'rsync',
  1883: 'mqtt',
  1900: 'upnp',
  2049: 'nfs',
  2375: 'docker',
  3000: 'dev-http',
  3389: 'rdp',
  5000: 'upnp/http',
  5001: 'management-https',
  5060: 'sip',
  5432: 'postgres',
  5900: 'vnc',
  6053: 'esphome',
  6379: 'redis',
  7000: 'airplay',
  8000: 'http-alt',
  8008: 'http-alt',
  8009: 'cast',
  8080: 'http-proxy',
  8123: 'home-assistant',
  8291: 'mikrotik-winbox',
  8443: 'https-alt',
  8728: 'mikrotik-api',
  9000: 'app',
  9090: 'metrics',
  9100: 'jetdirect',
  9200: 'elasticsearch',
  37777: 'dvr-command',
  37778: 'dvr-media',
  62078: 'iphone-sync'
};

export function serviceName(port: number): string | null {
  return SERVICE_NAMES[port] ?? null;
}

/** The mapping scanStore uses (scanStore.ts approachToSettings), for
 * the stored scan's options. */
const APPROACH_OPTIONS: Readonly<Record<ScanApproach, Pick<ScanOptions, 'port_profile' | 'discovery_mode' | 'timeout_ms'>>> = {
  fast: { port_profile: 'quick', discovery_mode: 'tcp', timeout_ms: 350 },
  balanced: { port_profile: 'standard', discovery_mode: 'hybrid', timeout_ms: 450 },
  thorough: { port_profile: 'deep', discovery_mode: 'hybrid', timeout_ms: 600 }
};

export function ipToNumber(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3];
}

export function numberToIp(n: number): string {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/**
 * The addresses a scan probes, in order (scanner.rs build_scan_targets):
 * every host address but the network, broadcast and this computer's;
 * above `maxHosts`, that many spread evenly over the subnet ("sampled").
 * /31 and /32 give none.
 */
export function buildScanTargets(subnet: string, localIp: string | null, maxHosts: number): string[] {
  const [base, prefixText] = subnet.split('/');
  const prefix = Number(prefixText);
  if (maxHosts <= 0 || prefix >= 31) return [];

  const size = 2 ** (32 - prefix);
  const network = ipToNumber(base) - (ipToNumber(base) % size);
  const first = network + 1;
  const last = network + size - 2;
  const local = localIp === null ? null : ipToNumber(localIp);
  const localInRange = local !== null && local >= first && local <= last;
  const totalHosts = last - first + 1;
  const available = totalHosts - (localInRange ? 1 : 0);
  const count = Math.min(maxHosts, available);
  if (count <= 0) return [];

  const targets: number[] = [];
  if (count >= available) {
    for (let raw = first; raw <= last; raw++) if (raw !== local) targets.push(raw);
    return targets.map(numberToIp);
  }

  const chosen = new Set<number>();
  for (let index = 0; index < count; index++) {
    const raw = first + Math.min(Math.floor((index * totalHosts) / count), last - first);
    if (chosen.has(raw)) continue;
    chosen.add(raw);
    if (raw !== local) targets.push(raw);
  }

  for (let raw = first; raw <= last && targets.length < count; raw++) {
    if (chosen.has(raw) || raw === local) continue;
    targets.push(raw);
  }

  return targets.map(numberToIp);
}

/** Whether `ip` lies in `subnet` (a.b.c.d/n). */
export function inSubnet(ip: string, subnet: string): boolean {
  const [base, prefixText] = subnet.split('/');
  const size = 2 ** (32 - Number(prefixText));
  const network = ipToNumber(base) - (ipToNumber(base) % size);
  const n = ipToNumber(ip);
  return n >= network && n < network + size;
}

// ---------------------------------------------------------------------
// Interfaces

/** This computer's address on the home network (never scanned). */
export const THIS_COMPUTER_IP = '192.168.1.23';
export const HOME_SUBNET = '192.168.1.0/24';
export const OFFICE_SUBNET = '10.20.0.0/16';
const VM_SUBNET_MAC = '192.168.64.0/24';
const VM_SUBNET_LINUX = '192.168.122.0/24';

/**
 * What get_network_interfaces returns: the home Wi-Fi (default route), a
 * wired /16 that is sampled, a virtual bridge and a VPN tunnel whose /32
 * has nothing to scan. Names follow the platform; the backend sorts by
 * name, then IP.
 */
export function interfacesFor(platform: Platform): NetworkInterface[] {
  const mac = platform === 'mac';
  const list: NetworkInterface[] = [
    { name: mac ? 'en0' : 'wlp2s0', ip: THIS_COMPUTER_IP, cidr: 24, subnet: HOME_SUBNET, host_count: 254, is_default_route: true },
    { name: mac ? 'en7' : 'enp0s31f6', ip: '10.20.4.17', cidr: 16, subnet: OFFICE_SUBNET, host_count: 65534, is_default_route: false },
    {
      name: mac ? 'bridge100' : 'virbr0',
      ip: mac ? '192.168.64.1' : '192.168.122.1',
      cidr: 24,
      subnet: mac ? VM_SUBNET_MAC : VM_SUBNET_LINUX,
      host_count: 254,
      is_default_route: false
    },
    { name: mac ? 'utun4' : 'tun0', ip: '10.8.0.2', cidr: 32, subnet: '10.8.0.2/32', host_count: 0, is_default_route: false }
  ];

  return list.sort((a, b) => a.name.localeCompare(b.name) || ipToNumber(a.ip) - ipToNumber(b.ip));
}

export function interfaceKeyOf(item: NetworkInterface): string {
  return `${item.name}|${item.ip}`;
}

// ---------------------------------------------------------------------
// Hosts

/** How a scan finds a host: it answers a discovery port (sweep), shows
 * up only in the ARP table after the sweep (arp), or only answers a
 * ping (ping, hybrid discovery only). */
export type Discovery = 'sweep' | 'arp' | 'ping';

export interface PortSpec {
  readonly port: number;
  /** What the backend reads from the port (SSH greeting, HTTP Server
   * header); at most 200 characters. */
  readonly banner?: string;
}

export interface FingerprintSpec {
  readonly mac: string | null;
  readonly vendor: string | null;
  readonly model: string | null;
  readonly type: string | null;
  readonly os: string | null;
  readonly confidence: number;
  readonly sources: readonly string[];
  readonly notes: readonly string[];
  readonly services?: readonly string[];
}

/** A device on a fixture network. */
export interface NetworkHost {
  readonly ip: string;
  /** Reverse DNS or mDNS name. */
  readonly name: string | null;
  /** Every open port the device has; a scan finds those its profile
   * probes. */
  readonly ports: readonly PortSpec[];
  readonly fingerprint: FingerprintSpec;
  readonly via: Discovery;
  /** False: asleep or gone, so no scan finds it. */
  readonly awake: boolean;
  /** In the scan the backend has stored (get_scan_results). */
  readonly inLastScan: boolean;
  /** Last seen this long before `now` (favorite snapshots only; hosts in
   * a scan were seen during that scan). */
  readonly lastSeenAgo?: number;
}

function fp(
  mac: string | null,
  vendor: string | null,
  type: string | null,
  os: string | null,
  model: string | null,
  confidence: number,
  sources: readonly string[],
  notes: readonly string[] = [],
  services: readonly string[] = []
): FingerprintSpec {
  return { mac, vendor, type, os, model, confidence, sources, notes, services };
}

const p = (port: number, banner?: string): PortSpec => (banner === undefined ? { port } : { port, banner });

/** An Apache Server header of 162 characters (the backend keeps 200). */
export const LONG_BANNER =
  'Apache/2.4.57 (Debian) OpenSSL/3.0.11 mod_wsgi/4.9.4 Python/3.11 mod_perl/2.0.12 Perl/v5.36.0 PHP/8.2.7 ' +
  'mod_fcgid/2.3.9 mod_auth_openidc/2.4.14.2 SVN/1.14.2 DAV/2';

const ARP = 'arp-table';
const OUI = 'oui-cache';
const MDNS = 'mdns';
const BANNER = 'banner-grab';
const RDNS = 'reverse-dns';

/**
 * The home network (192.168.1.0/24) as the mock sees it. The stored scan
 * holds every host with `inLastScan`; a new scan finds every `awake`
 * host. So a rescan marks .80 and .81 New, drops .160, and leaves .61 a
 * stale favorite ("Not seen") whose snapshot has a MAC to wake.
 */
export const HOME_HOSTS: readonly NetworkHost[] = [
  {
    ip: '192.168.1.1',
    name: 'router.lan',
    ports: [p(22, 'SSH-2.0-dropbear_2020.81'), p(53), p(80, 'nginx'), p(443), p(1900)],
    fingerprint: fp('74:83:C2:1A:2B:01', 'Ubiquiti Inc.', 'Network device', 'Linux-like', 'UniFi Dream Machine', 82, [ARP, OUI, BANNER, RDNS], [
      'gateway/router service profile detected',
      'detected software: dropbear_2020.81'
    ]),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.2',
    name: 'switch-office.lan',
    ports: [p(80, 'GS308E')],
    fingerprint: fp('A0:40:A0:62:17:9C', 'NETGEAR', 'Network device', null, null, 45, [ARP, OUI, BANNER, RDNS], [
      'gateway/router service profile detected'
    ]),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.10',
    name: 'DS920plus.local',
    ports: [
      p(22, 'SSH-2.0-OpenSSH_8.2'),
      p(80, 'nginx'),
      p(111),
      p(139),
      p(443),
      p(445),
      p(548),
      p(873),
      p(2049),
      p(5000, 'nginx'),
      p(5001)
    ],
    fingerprint: fp(
      '00:11:32:9A:4E:21',
      'Synology Incorporated',
      'NAS/Storage',
      'Linux-like',
      'Synology NAS (DSM)',
      96,
      [ARP, OUI, MDNS, BANNER],
      ['mDNS service: _smb._tcp', 'mDNS service: _afpovertcp._tcp', 'NAS management + file sharing signature detected'],
      ['_smb._tcp', '_afpovertcp._tcp', '_http._tcp']
    ),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.12',
    name: 'homeassistant.local',
    ports: [p(22, 'SSH-2.0-OpenSSH_9.3'), p(1883), p(8123, 'Python/3.12 aiohttp/3.9.5')],
    fingerprint: fp(
      'DC:A6:32:5E:0B:7A',
      'Raspberry Pi Trading Ltd',
      'Single-board computer',
      'Linux-like',
      'Raspberry Pi',
      88,
      [ARP, OUI, MDNS, BANNER],
      ['hostname/vendor hints indicate Raspberry Pi', 'mDNS service: _home-assistant._tcp'],
      ['_home-assistant._tcp']
    ),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.31',
    name: 'BRN30055C123456.local',
    ports: [p(80, 'debut/1.30'), p(443), p(515), p(631, 'debut/1.30'), p(9100)],
    fingerprint: fp(
      '30:05:5C:12:34:56',
      'Brother Industries, LTD.',
      'Printer',
      null,
      'HL-L2350DW',
      87,
      [ARP, OUI, MDNS, BANNER],
      [
        'mDNS service: _ipp._tcp',
        'Printer service detected via mDNS',
        'printer signature detected (IPP/LPD/JetDirect)',
        'detected software: debut/1.30'
      ],
      ['_ipp._tcp', '_printer._tcp', '_http._tcp']
    ),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.40',
    name: 'Mac-Studio.local',
    ports: [p(22, 'SSH-2.0-OpenSSH_9.8'), p(88), p(445), p(7000)],
    fingerprint: fp(
      'F0:2F:4B:0C:88:13',
      'Apple, Inc.',
      'Apple device',
      'Apple OS family',
      'Mac13,1',
      90,
      [ARP, OUI, MDNS, BANNER, RDNS],
      ['Apple vendor or device name detected', 'mDNS service: _smb._tcp', 'mDNS service: _airplay._tcp'],
      ['_smb._tcp', '_airplay._tcp', '_device-info._tcp']
    ),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.41',
    name: 'Anas-MacBook-Air.local',
    ports: [p(7000)],
    fingerprint: fp('3C:22:FB:4D:90:A7', 'Apple, Inc.', 'Apple device', 'Apple OS family', null, 74, [ARP, OUI, MDNS], [
      'Apple vendor or device name detected',
      'mDNS service: _airplay._tcp'
    ], ['_airplay._tcp']),
    via: 'arp',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.45',
    name: 'DESKTOP-7Q2M4KD.lan',
    ports: [p(135), p(139), p(445), p(3389)],
    fingerprint: fp('00:D8:61:3A:7F:02', 'Micro-Star INTL CO., LTD.', 'Workstation/Server', 'Windows-like', null, 70, [ARP, OUI, RDNS], [
      'MS-RPC/RDP ports suggest a Windows host'
    ]),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.46',
    name: 'LAPTOP-JONAS.lan',
    ports: [],
    fingerprint: fp('3C:9C:0F:21:C4:5D', 'Intel Corporate', null, 'Windows-like', null, 35, [ARP, OUI, RDNS], [
      'reverse DNS/mDNS name: LAPTOP-JONAS.lan'
    ]),
    via: 'arp',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.52',
    name: 'thinkpad-x1.lan',
    ports: [p(22, 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5')],
    fingerprint: fp(
      '8C:16:45:B2:0E:39',
      'LCFC(HeFei) Electronics Technology co., ltd',
      'Workstation/Server',
      'Ubuntu Linux',
      null,
      64,
      [ARP, OUI, BANNER, RDNS],
      ['SSH-first profile suggests Linux/Unix', 'detected software: OpenSSH_9.6p1 Ubuntu-3ubuntu13.5']
    ),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    // The stale favorite: asleep, missing from the stored scan, listed
    // from its snapshot, which has a MAC (Wake works).
    ip: '192.168.1.61',
    name: 'LGwebOSTV.lan',
    ports: [p(3000), p(3001)],
    fingerprint: fp('58:FD:B1:3C:77:0E', 'LG Electronics', 'Media device', 'Linux-like', 'webOS TV', 72, [ARP, OUI, MDNS], [
      'mDNS service: _airplay._tcp'
    ], ['_airplay._tcp']),
    via: 'arp',
    awake: false,
    inLastScan: false,
    lastSeenAgo: 3 * DAY + 2 * HOUR
  },
  {
    ip: '192.168.1.64',
    name: 'Apple-TV.local',
    ports: [p(7000)],
    fingerprint: fp('F4:34:F0:18:62:C5', 'Apple, Inc.', 'Media device', 'Apple OS family', null, 80, [ARP, OUI, MDNS], [
      'AirPlay service detected via mDNS',
      'Apple vendor or device name detected'
    ], ['_airplay._tcp', '_raop._tcp']),
    via: 'arp',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.70',
    name: 'IPC-HDW2431T.lan',
    ports: [p(80, 'WEB SERVER'), p(554), p(37777), p(37778)],
    fingerprint: fp(
      '3C:EF:8C:A1:05:6B',
      'Zhejiang Dahua Technology Co., Ltd.',
      'Camera/NVR',
      null,
      'Dahua/Amcrest-style DVR/NVR',
      90,
      [ARP, OUI, BANNER],
      ['DVR/NVR signature detected (ports 37777/37778)']
    ),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.71',
    name: 'Reolink-E1-Zoom.lan',
    ports: [p(80), p(443), p(554), p(8000), p(9000)],
    fingerprint: fp('EC:71:DB:2C:4A:90', 'Reolink Innovation Limited', 'Camera', null, null, 76, [ARP, OUI, RDNS], [
      'RTSP/ONVIF profile suggests camera device'
    ]),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    // Nothing to go on: no name, a locally administered MAC ("Private
    // address"), no ports, no hints ("Unknown" kind).
    ip: '192.168.1.77',
    name: null,
    ports: [],
    fingerprint: fp('7A:2F:4C:91:0B:E3', null, null, null, null, 10, [ARP]),
    via: 'arp',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.80',
    name: 'iPhone.local',
    ports: [p(62078)],
    fingerprint: fp(
      'D2:6B:19:84:3E:0F',
      null,
      'Mobile device',
      'Apple iOS/iPadOS family',
      'Apple mobile device',
      84,
      [ARP, MDNS],
      ['Apple mobile sync port (62078) or device name detected']
    ),
    via: 'sweep',
    awake: true,
    inLastScan: false
  },
  {
    ip: '192.168.1.81',
    name: '山田のiPad.local',
    ports: [p(62078)],
    fingerprint: fp(
      'A6:03:5E:C7:21:98',
      null,
      'Mobile device',
      'Apple iOS/iPadOS family',
      'Apple mobile device',
      84,
      [ARP, MDNS],
      ['Apple mobile sync port (62078) or device name detected']
    ),
    via: 'sweep',
    awake: true,
    inLastScan: false
  },
  {
    // Found by ping only; the ARP read missed it, so no MAC (Wake dims).
    ip: '192.168.1.82',
    name: 'Pixel-8.lan',
    ports: [],
    fingerprint: fp(null, null, null, null, null, 5, [RDNS], ['reverse DNS/mDNS name: Pixel-8.lan']),
    via: 'ping',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.90',
    name: 'pve.lan',
    ports: [p(22, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3'), p(111)],
    fingerprint: fp('BC:5F:F4:7D:12:0A', 'ASRock Incorporation', 'Workstation/Server', 'Debian Linux', null, 66, [ARP, OUI, BANNER, RDNS], [
      'SSH-first profile suggests Linux/Unix',
      'detected software: OpenSSH_9.2p1 Debian-2+deb12u3'
    ]),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.91',
    name: 'docker-01.lan',
    ports: [
      p(22, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3'),
      p(80, 'nginx/1.25.3'),
      p(443),
      p(2375),
      p(3000, 'Grafana'),
      p(5432),
      p(6379),
      p(8080, LONG_BANNER),
      p(9000, 'MinIO'),
      p(9090),
      p(9200)
    ],
    fingerprint: fp(
      'BC:24:11:6E:3F:D1',
      'Proxmox Server Solutions GmbH',
      'Server/Container host',
      'Linux/Unix-like',
      null,
      78,
      [ARP, OUI, BANNER, RDNS],
      [
        'container/orchestration management ports detected',
        'database/search service ports detected',
        'detected software: nginx/1.25.3',
        'open services: 22:ssh, 80:http, 443:https, 2375:docker, 3000:dev-http, 5432:postgres'
      ]
    ),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.95',
    name: 'pikvm.local',
    ports: [p(22, 'SSH-2.0-OpenSSH_9.7'), p(80, 'nginx'), p(443), p(5900)],
    fingerprint: fp(
      'DC:A6:32:0F:9E:44',
      'Raspberry Pi Trading Ltd',
      'Single-board computer',
      'Linux-like',
      'Raspberry Pi',
      80,
      [ARP, OUI, MDNS, BANNER],
      ['hostname/vendor hints indicate Raspberry Pi']
    ),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.100',
    name: 'esphome-plug-kitchen.lan',
    ports: [p(80), p(6053)],
    fingerprint: fp('24:0A:C4:8B:61:3D', 'Espressif Inc.', 'IoT device', null, null, 70, [ARP, OUI, MDNS], [
      'IoT/messaging profile detected (MQTT or IoT naming)',
      'mDNS service: _esphomelib._tcp'
    ], ['_esphomelib._tcp']),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.101',
    name: 'shellyplus1pm-a8032ab12345.lan',
    ports: [p(80)],
    fingerprint: fp('A8:03:2A:B1:23:45', 'Espressif Inc.', 'IoT device', null, null, 68, [ARP, OUI, RDNS], [
      'IoT/messaging profile detected (MQTT or IoT naming)'
    ]),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    // Answers nothing a Balanced scan probes; a deep scan finds 1400 and
    // 1443.
    ip: '192.168.1.110',
    name: 'Sonos-5CAAFD8E0F21.lan',
    ports: [p(1400), p(1443)],
    fingerprint: fp('5C:AA:FD:8E:0F:21', 'Sonos, Inc.', 'Media device', null, null, 60, [ARP, OUI, MDNS], [
      'mDNS service: _sonos._tcp'
    ], ['_sonos._tcp']),
    via: 'arp',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.120',
    name: 'Chromecast-Ultra.lan',
    ports: [p(8008, 'Chromecast'), p(8009), p(8443)],
    fingerprint: fp('F4:F5:D8:2B:9C:11', 'Google, Inc.', 'Media device', null, null, 74, [ARP, OUI, MDNS, BANNER], [
      'mDNS service: _googlecast._tcp'
    ], ['_googlecast._tcp']),
    via: 'arp',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.130',
    name: 'TS-453D.lan',
    ports: [p(22, 'SSH-2.0-OpenSSH_8.0'), p(80, 'http server 1.0'), p(139), p(443), p(445), p(8080, 'http server 1.0')],
    fingerprint: fp('24:5E:BE:4C:0D:77', 'QNAP Systems, Inc.', 'NAS/Storage', 'Linux-like', null, 85, [ARP, OUI, BANNER, RDNS], [
      'NAS management + file sharing signature detected'
    ]),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.140',
    name: 'Brother-MFC-L3770CDW-Color-Laser-Multifunction-Second-Floor.local',
    ports: [p(80, 'debut/1.20'), p(631, 'debut/1.20'), p(9100)],
    fingerprint: fp('30:05:5C:9E:10:42', 'Brother Industries, LTD.', 'Printer', null, 'MFC-L3770CDW', 86, [ARP, OUI, MDNS, BANNER], [
      'Printer service detected via mDNS',
      'printer signature detected (IPP/LPD/JetDirect)'
    ], ['_ipp._tcp']),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    ip: '192.168.1.150',
    name: 'Küche-Thermostat.local',
    ports: [p(80)],
    fingerprint: fp('EC:FA:BC:40:5B:2E', 'tado GmbH', 'IoT device', null, null, 58, [ARP, OUI, MDNS], [
      'mDNS service: _hap._tcp'
    ], ['_hap._tcp']),
    via: 'sweep',
    awake: true,
    inLastScan: true
  },
  {
    // In the stored scan, gone now: a rescan drops it.
    ip: '192.168.1.160',
    name: 'Guest-Laptop.lan',
    ports: [p(135), p(445)],
    fingerprint: fp('3C:9C:0F:77:18:AB', 'Intel Corporate', 'Workstation/Server', 'Windows-like', null, 62, [ARP, OUI, RDNS], [
      'MS-RPC/RDP ports suggest a Windows host'
    ]),
    via: 'sweep',
    awake: false,
    inLastScan: true
  },
  {
    ip: '192.168.1.200',
    name: 'hAP-ax3.lan',
    ports: [p(22, 'SSH-2.0-ROSSSH'), p(80), p(8291), p(8728)],
    fingerprint: fp(
      '48:A9:8A:C1:0D:5F',
      'Routerboard.com',
      'Network appliance',
      null,
      'MikroTik RouterOS device',
      83,
      [ARP, OUI, BANNER, RDNS],
      ['MikroTik signature detected (Winbox/API ports)']
    ),
    via: 'sweep',
    awake: true,
    inLastScan: true
  }
];

/** Two VMs on the virtual bridge. */
function vmHosts(platform: Platform): NetworkHost[] {
  const prefix = platform === 'mac' ? '192.168.64' : '192.168.122';
  return [
    {
      ip: `${prefix}.2`,
      name: 'ubuntu-server.shared',
      ports: [p(22, 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5'), p(80, 'nginx/1.24.0 (Ubuntu)')],
      fingerprint: fp('52:54:00:3A:9D:1E', null, 'Workstation/Server', 'Ubuntu Linux', null, 60, [ARP, BANNER], [
        'SSH-first profile suggests Linux/Unix'
      ]),
      via: 'sweep',
      awake: true,
      inLastScan: false
    },
    {
      ip: `${prefix}.3`,
      name: 'win11-dev.shared',
      ports: [p(135), p(445), p(3389)],
      fingerprint: fp('52:54:00:C4:02:7B', null, 'Workstation/Server', 'Windows-like', null, 66, [ARP], [
        'MS-RPC/RDP ports suggest a Windows host'
      ]),
      via: 'sweep',
      awake: true,
      inLastScan: false
    }
  ];
}

// ---------------------------------------------------------------------
// The "many" network: 1,500 hosts on the sampled /16

/** Hosts in the "many" scenario (above Osmium's 1,000-row windowing). */
export const MANY_HOST_COUNT = 1500;
const OFFICE_LOCAL_IP = '10.20.4.17';

interface ManyTemplate {
  /** The reverse DNS name of the n-th host; null: none. */
  name: ((n: number) => string) | null;
  vendor: string | null;
  type: string | null;
  os: string | null;
  ports: readonly number[];
  banner?: string;
}

const MANY_TEMPLATES: readonly ManyTemplate[] = [
  { name: (n) => `WS-${String(n).padStart(4, '0')}.corp.lan`, vendor: 'Dell Inc.', type: 'Workstation/Server', os: 'Windows-like', ports: [135, 139, 445, 3389] },
  { name: (n) => `MacBook-Pro-${n}.local`, vendor: 'Apple, Inc.', type: 'Apple device', os: 'Apple OS family', ports: [22, 445] },
  { name: (n) => `HP-LaserJet-${n}.corp.lan`, vendor: 'HP Inc.', type: 'Printer', os: null, ports: [80, 443, 631, 9100], banner: 'HP HTTP Server; HP LaserJet' },
  { name: (n) => `iPhone-${n}.local`, vendor: null, type: 'Mobile device', os: 'Apple iOS/iPadOS family', ports: [62078] },
  { name: (n) => `cam-${n}.corp.lan`, vendor: 'Hangzhou Hikvision Digital Technology Co.,Ltd.', type: 'Camera', os: null, ports: [80, 554, 8000], banner: 'App-webs/' },
  { name: (n) => `srv-${n}.corp.lan`, vendor: 'Super Micro Computer, Inc.', type: 'Server/Database host', os: 'Ubuntu Linux', ports: [22, 5432, 9090], banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10' },
  { name: (n) => `ap-${n}.corp.lan`, vendor: 'Cisco Meraki', type: 'Network device', os: null, ports: [80, 443] },
  { name: null, vendor: 'Cisco Systems, Inc', type: null, os: null, ports: [80, 5060] }
];

/** A small deterministic PRNG (mulberry32), so every run shows the same
 * hosts. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function hex2(n: number): string {
  return n.toString(16).toUpperCase().padStart(2, '0');
}

let manyCache: readonly NetworkHost[] | null = null;

/** MANY_HOST_COUNT hosts on addresses a sampled scan of the /16 probes. */
export function manyHosts(): readonly NetworkHost[] {
  if (manyCache) return manyCache;

  const targets = buildScanTargets(OFFICE_SUBNET, OFFICE_LOCAL_IP, 4096);
  const random = mulberry32(0x1a7e22a);
  const hosts: NetworkHost[] = [];

  // (i * 7919) mod n is a permutation of 0..n-1 (7919 is prime and does
  // not divide n), so exactly MANY_HOST_COUNT targets are picked.
  for (let i = 0; i < targets.length; i++) {
    if ((i * 7919) % targets.length >= MANY_HOST_COUNT) continue;

    const template = MANY_TEMPLATES[Math.floor(random() * MANY_TEMPLATES.length)];
    const serial = hosts.length + 1;
    const mac = template.vendor
      ? `00:1B:${hex2(serial >> 8)}:${hex2(serial & 255)}:${hex2(Math.floor(random() * 256))}:${hex2(i & 255)}`
      : `DA:${hex2(Math.floor(random() * 256))}:${hex2(serial >> 8)}:${hex2(serial & 255)}:${hex2(i & 255)}:0E`;
    hosts.push({
      ip: targets[i],
      name: template.name ? template.name(serial) : null,
      ports: template.ports.map((port) => (template.banner && (port === 80 || port === 22) ? p(port, template.banner) : p(port))),
      fingerprint: fp(mac, template.vendor, template.type, template.os, null, 40 + Math.floor(random() * 50), [ARP, OUI]),
      via: template.ports.some((port) => DISCOVERY_PORTS.includes(port)) ? 'sweep' : 'arp',
      awake: true,
      inLastScan: true
    });
  }

  manyCache = hosts;
  return hosts;
}

/** The devices on the network `subnet`, as the mock scans it. */
export function networkFor(subnet: string, platform: Platform): readonly NetworkHost[] {
  if (subnet === HOME_SUBNET) return HOME_HOSTS;
  if (subnet === OFFICE_SUBNET) return manyHosts();
  if (subnet === VM_SUBNET_MAC || subnet === VM_SUBNET_LINUX) return vmHosts(platform);
  return [];
}

// ---------------------------------------------------------------------
// Hosts as the backend reports them

/** How far a scan has come with a host: the discovery sweep (discovery
 * ports only, no fingerprint), the port phase (the profile's ports, no
 * fingerprint yet) or the end (enriched). */
export type HostStage = 'discovery' | 'ports' | 'complete';

function portInfo(spec: PortSpec): PortInfo {
  return { port: spec.port, state: 'open', service: serviceName(spec.port), banner: spec.banner ?? null };
}

function fingerprintOf(spec: FingerprintSpec, updatedAt: string): DeviceFingerprint {
  return {
    mac_address: spec.mac,
    oui: spec.mac ? spec.mac.slice(0, 8) : null,
    vendor: spec.vendor,
    manufacturer: null,
    model_guess: spec.model,
    device_type: spec.type,
    os_guess: spec.os,
    confidence: spec.confidence,
    sources: [...spec.sources],
    notes: [...spec.notes],
    discovered_services: [...(spec.services ?? [])],
    last_updated: updatedAt
  };
}

/** The open ports of `host` a probe of `ports` finds. */
export function openPorts(host: NetworkHost, ports: readonly number[] | null): PortInfo[] {
  const probed = ports === null ? null : new Set(ports);
  return host.ports.filter((spec) => probed === null || probed.has(spec.port)).map(portInfo);
}

/** `host` as the backend reports it at `stage` of a scan with `profile`,
 * seen at `seenAt` (ISO). */
export function reportedHost(host: NetworkHost, profile: PortProfile, stage: HostStage, seenAt: string): Host {
  const ports = stage === 'discovery' ? DISCOVERY_PORTS : portsForProfile(profile);
  return {
    ip: host.ip,
    name: host.name,
    reachable: true,
    open_ports: openPorts(host, ports),
    last_seen: seenAt,
    fingerprint: stage === 'complete' ? fingerprintOf(host.fingerprint, seenAt) : null
  };
}

/** A favorite's snapshot as scanStore keeps it (lantenna.favoriteHosts). */
export function snapshotOf(host: NetworkHost, now: number): Host {
  const seenAt = new Date(now - (host.lastSeenAgo ?? 0)).toISOString();
  return {
    ip: host.ip,
    name: host.name,
    reachable: true,
    open_ports: openPorts(host, portsForProfile('standard')),
    last_seen: seenAt,
    fingerprint: fingerprintOf(host.fingerprint, seenAt)
  };
}

export function scanOptions(iface: NetworkInterface, approach: ScanApproach): ScanOptions {
  return {
    interface_name: iface.name,
    subnet: iface.subnet,
    ...APPROACH_OPTIONS[approach],
    max_hosts: iface.host_count > 0 ? Math.min(iface.host_count, 4096) : null
  };
}

// ---------------------------------------------------------------------
// Persisted state per scenario

/** What the backend has stored (get_scan_results): a Balanced scan of
 * `iface` that finished 12 minutes before `now` and found the hosts of
 * `hosts` marked `inLastScan`. */
export function storedScan(iface: NetworkInterface, hosts: readonly NetworkHost[], now: number): ScanResult {
  const completed = now - 12 * MINUTE;
  const completedAt = new Date(completed).toISOString();
  const options = scanOptions(iface, 'balanced');

  return {
    started_at: new Date(completed - 41_000).toISOString(),
    completed_at: completedAt,
    cancelled: false,
    hosts: hosts
      .filter((host) => host.inLastScan)
      .map((host) => reportedHost(host, options.port_profile, 'complete', completedAt)),
    options
  };
}

/** The user data scanStore reads from localStorage at launch. */
export interface SeededUserData {
  readonly favoriteIps: readonly string[];
  readonly favoriteHosts: Readonly<Record<string, Host>>;
  readonly hiddenIps: readonly string[];
  readonly customNames: Readonly<Record<string, string>>;
}

export const FAVORITE_IPS: readonly string[] = ['192.168.1.10', '192.168.1.31', '192.168.1.61'];
export const HIDDEN_IPS: readonly string[] = ['192.168.1.101', '192.168.1.120'];
export const CUSTOM_NAMES: Readonly<Record<string, string>> = {
  '192.168.1.10': 'NAS-01',
  '192.168.1.31': 'Office Printer',
  '192.168.1.61': 'Living Room TV',
  '192.168.1.70': 'Driveway Camera',
  '192.168.1.91': 'Docker host (Proxmox VM in the basement rack)',
  '192.168.1.110': 'Kitchen Speaker'
};

/** Favorites with snapshots of when they were last seen, hidden hosts
 * and custom names; empty for a fresh install. */
export function userData(kind: 'fresh' | 'regular', now: number): SeededUserData {
  if (kind === 'fresh') return { favoriteIps: [], favoriteHosts: {}, hiddenIps: [], customNames: {} };

  const favoriteHosts: Record<string, Host> = {};
  for (const ip of FAVORITE_IPS) {
    const host = HOME_HOSTS.find((item) => item.ip === ip);
    if (host) favoriteHosts[ip] = snapshotOf(host, now);
  }

  return { favoriteIps: FAVORITE_IPS, favoriteHosts, hiddenIps: HIDDEN_IPS, customNames: CUSTOM_NAMES };
}

// ---------------------------------------------------------------------
// Updates and colors

/** check_self_update's answer when an update is offered. */
export const UPDATE_INFO = {
  version: '1.1.0',
  url: 'https://github.com/L-K-M/Lantenna/releases/tag/v1.1.0',
  notes: 'Mac OS 8 look, contextual menus and Balloon Help.'
} as const;

/** macOS: NSColor.controlAccentColor's documented fallback (Blue). The
 * app reads only the accent (spec 6). */
export const MAC_ACCENT = '#007AFF';
