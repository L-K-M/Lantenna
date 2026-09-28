// Owner: unit G. The fixtures behind the mock backend (spec 8.6): the
// backend rules they copy, and the coverage the verification plan needs.

import { describe, expect, it } from 'vitest';
import type { HostIconKind } from '$lib/osm/sprites';
import { getHostIcon } from '$lib/util/hostIcons';
import {
  CUSTOM_NAMES,
  DISCOVERY_PORTS,
  FAVORITE_IPS,
  HIDDEN_IPS,
  HOME_HOSTS,
  HOME_SUBNET,
  LONG_BANNER,
  MANY_HOST_COUNT,
  OFFICE_SUBNET,
  THIS_COMPUTER_IP,
  buildScanTargets,
  inSubnet,
  interfacesFor,
  ipToNumber,
  manyHosts,
  networkFor,
  portsForProfile,
  reportedHost,
  storedScan,
  userData
} from './fixtures';

const NOW = Date.parse('2026-09-27T15:42:00Z');
const home = () => interfacesFor('mac').find((item) => item.subnet === HOME_SUBNET)!;
const byIp = (ip: string) => HOME_HOSTS.find((host) => host.ip === ip)!;

describe('backend rules', () => {
  it('builds the profiles as ports_for_profile does', () => {
    const quick = portsForProfile('quick');
    const standard = portsForProfile('standard');
    const deep = portsForProfile('deep');

    expect(quick).toHaveLength(29);
    expect(standard).toHaveLength(71);
    // 1..2048 plus the 39 Standard ports above 2048.
    expect(deep).toHaveLength(2087);
    expect(deep.slice(0, 2048)).toEqual(Array.from({ length: 2048 }, (_, i) => i + 1));
    for (const list of [quick, standard, deep]) expect([...list].sort((a, b) => a - b)).toEqual(list);
    expect(standard).toEqual(expect.arrayContaining(quick));
    expect(DISCOVERY_PORTS.every((port) => quick.includes(port))).toBe(true);
  });

  it('skips the network, broadcast and local addresses (scanner.rs test case)', () => {
    const targets = buildScanTargets('192.168.10.0/29', '192.168.10.3', 16);

    expect(targets).toEqual(['192.168.10.1', '192.168.10.2', '192.168.10.4', '192.168.10.5', '192.168.10.6']);
  });

  it('probes 253 addresses of the home /24', () => {
    const targets = buildScanTargets(HOME_SUBNET, THIS_COMPUTER_IP, 254);

    expect(targets).toHaveLength(253);
    expect(targets).not.toContain(THIS_COMPUTER_IP);
    expect(targets[0]).toBe('192.168.1.1');
    expect(targets.at(-1)).toBe('192.168.1.254');
  });

  it('samples 4,096 addresses spread over a /16', () => {
    const targets = buildScanTargets(OFFICE_SUBNET, '10.20.4.17', 4096);
    const numbers = targets.map(ipToNumber);

    expect(targets).toHaveLength(4096);
    expect(new Set(targets).size).toBe(4096);
    expect(targets.every((ip) => inSubnet(ip, OFFICE_SUBNET))).toBe(true);
    expect(numbers).toEqual([...numbers].sort((a, b) => a - b));
    expect(targets[0]).toBe('10.20.0.1');
    expect(ipToNumber(targets.at(-1)!) - ipToNumber('10.20.0.0')).toBeGreaterThan(65_000);
  });

  it('gives /31 and /32 subnets nothing to scan', () => {
    expect(buildScanTargets('10.8.0.2/32', '10.8.0.2', 1)).toEqual([]);
    expect(buildScanTargets('10.8.0.2/31', '10.8.0.2', 1)).toEqual([]);
  });
});

describe('interfaces', () => {
  it('lists a default route, a sampled /16, a bridge and a /32, sorted by name', () => {
    for (const platform of ['mac', 'linux'] as const) {
      const list = interfacesFor(platform);
      const names = list.map((item) => item.name);

      expect(names).toEqual([...names].sort((a, b) => a.localeCompare(b)));
      expect(list.filter((item) => item.is_default_route).map((item) => item.subnet)).toEqual([HOME_SUBNET]);
      expect(list.some((item) => item.cidr === 16 && item.host_count > 4096)).toBe(true);
      expect(list.some((item) => item.host_count === 0)).toBe(true);
    }

    expect(interfacesFor('mac').map((item) => item.name)).toContain('en0');
    expect(interfacesFor('linux').map((item) => item.name)).toContain('wlp2s0');
  });
});

describe('home network', () => {
  it('has about 30 distinct hosts inside the /24, never this computer', () => {
    const ips = HOME_HOSTS.map((host) => host.ip);

    expect(HOME_HOSTS.length).toBeGreaterThanOrEqual(28);
    expect(new Set(ips).size).toBe(ips.length);
    expect(ips.every((ip) => inSubnet(ip, HOME_SUBNET))).toBe(true);
    expect(ips).not.toContain(THIS_COMPUTER_IP);
  });

  it('finds a host in the sweep exactly when it has a discovery port open', () => {
    for (const host of HOME_HOSTS) {
      const answersSweep = host.ports.some((spec) => DISCOVERY_PORTS.includes(spec.port));
      expect({ ip: host.ip, sweep: host.via === 'sweep' }).toEqual({ ip: host.ip, sweep: answersSweep });
    }
  });

  it('keeps banners within the backend’s 200 characters and has a long one', () => {
    const banners = HOME_HOSTS.flatMap((host) => host.ports.map((spec) => spec.banner ?? ''));

    expect(banners.every((banner) => banner.length <= 200)).toBe(true);
    expect(LONG_BANNER.length).toBeGreaterThan(150);
    expect(banners).toContain(LONG_BANNER);
  });

  it('covers every host icon kind', () => {
    const iso = new Date(NOW).toISOString();
    const kinds = new Set<HostIconKind>(
      HOME_HOSTS.map((host) => getHostIcon(reportedHost(host, 'standard', 'complete', iso), CUSTOM_NAMES[host.ip] ?? '').kind)
    );

    expect([...kinds].sort()).toEqual(
      ['camera', 'iot', 'kvm', 'media', 'mobile', 'pc-generic', 'pc-linux', 'pc-mac', 'pc-windows', 'printer', 'router', 'server'].sort()
    );
  });

  it('covers the host states spec 8.6 asks for', () => {
    const stale = HOME_HOSTS.filter((host) => FAVORITE_IPS.includes(host.ip) && !host.inLastScan && !host.awake);
    expect(stale.map((host) => host.ip)).toEqual(['192.168.1.61']);
    expect(stale[0].fingerprint.mac).toMatch(/^[0-9A-F]{2}(:[0-9A-F]{2}){5}$/);

    const fresh = HOME_HOSTS.filter((host) => host.awake && !host.inLastScan);
    expect(fresh.map((host) => host.ip)).toEqual(['192.168.1.80', '192.168.1.81']);

    const gone = HOME_HOSTS.filter((host) => host.inLastScan && !host.awake);
    expect(gone.map((host) => host.ip)).toEqual(['192.168.1.160']);

    for (const ip of HIDDEN_IPS) expect(byIp(ip).awake).toBe(true);
    for (const ip of Object.keys(CUSTOM_NAMES)) expect(byIp(ip)).toBeDefined();
  });

  it('has long, non-Latin, missing and private-address names and vendors', () => {
    const names = HOME_HOSTS.map((host) => host.name ?? '');

    expect(names.some((name) => /\p{Script=Han}/u.test(name))).toBe(true);
    expect(names.some((name) => /[äöü]/i.test(name))).toBe(true);
    expect(names.some((name) => name.length > 60)).toBe(true);
    expect(Object.values(CUSTOM_NAMES).some((name) => name.length > 40)).toBe(true);
    expect(HOME_HOSTS.some((host) => host.name === null)).toBe(true);
    expect(HOME_HOSTS.some((host) => host.fingerprint.mac === null)).toBe(true);
    // Locally administered: the second hex digit is 2, 6, A or E.
    expect(HOME_HOSTS.some((host) => /^.[26AE]/.test(host.fingerprint.mac ?? '') && host.fingerprint.vendor === null)).toBe(true);
  });

  it('reports a host as the scan stages see it', () => {
    const nas = byIp('192.168.1.10');
    const iso = new Date(NOW).toISOString();

    const found = reportedHost(nas, 'standard', 'discovery', iso);
    expect(found.fingerprint).toBeNull();
    expect(found.open_ports.map((port) => port.port)).toEqual([22, 80, 443, 445]);

    const probed = reportedHost(nas, 'quick', 'ports', iso);
    expect(probed.fingerprint).toBeNull();
    expect(probed.open_ports.map((port) => port.port)).toEqual([22, 80, 139, 443, 445, 548, 5000, 5001]);

    const done = reportedHost(nas, 'standard', 'complete', iso);
    expect(done.fingerprint?.vendor).toBe('Synology Incorporated');
    expect(done.fingerprint?.oui).toBe('00:11:32');
    expect(done.open_ports[0]).toEqual({ port: 22, state: 'open', service: 'ssh', banner: 'SSH-2.0-OpenSSH_8.2' });
    expect(done.last_seen).toBe(iso);
  });

  it('hides Sonos ports from a Balanced scan and shows them to a deep one', () => {
    const sonos = byIp('192.168.1.110');

    expect(reportedHost(sonos, 'standard', 'complete', '').open_ports).toEqual([]);
    expect(reportedHost(sonos, 'deep', 'complete', '').open_ports.map((port) => port.port)).toEqual([1400, 1443]);
  });
});

describe('stored scan and user data', () => {
  it('stores a Balanced scan of the home network from 12 minutes ago', () => {
    const scan = storedScan(home(), HOME_HOSTS, NOW);

    expect(scan.cancelled).toBe(false);
    expect(Date.parse(scan.completed_at!)).toBe(NOW - 12 * 60_000);
    expect(scan.options).toEqual({
      interface_name: 'en0',
      subnet: HOME_SUBNET,
      port_profile: 'standard',
      discovery_mode: 'hybrid',
      timeout_ms: 450,
      max_hosts: 254
    });
    expect(scan.hosts.map((host) => host.ip)).toEqual(HOME_HOSTS.filter((host) => host.inLastScan).map((host) => host.ip));
    expect(scan.hosts.every((host) => host.fingerprint !== null)).toBe(true);
  });

  it('stores an empty scan for the empty scenario', () => {
    expect(storedScan(home(), [], NOW).hosts).toEqual([]);
  });

  it('seeds favorites with snapshots, hidden hosts and names, or nothing', () => {
    const regular = userData('regular', NOW);
    const tv = regular.favoriteHosts['192.168.1.61'];

    expect(regular.favoriteIps).toEqual(FAVORITE_IPS);
    expect(Object.keys(regular.favoriteHosts).sort()).toEqual([...FAVORITE_IPS].sort());
    expect(tv.fingerprint?.mac_address).toBe('58:FD:B1:3C:77:0E');
    expect(NOW - Date.parse(tv.last_seen)).toBe(3 * 24 * 3_600_000 + 2 * 3_600_000);
    expect(regular.hiddenIps).toEqual(HIDDEN_IPS);
    expect(regular.customNames['192.168.1.31']).toBe('Office Printer');

    expect(userData('fresh', NOW)).toEqual({ favoriteIps: [], favoriteHosts: {}, hiddenIps: [], customNames: {} });
  });

  it('keeps favorites and hidden hosts IP-sorted, as scanStore stores them', () => {
    const sorted = (ips: readonly string[]) => [...ips].sort((a, b) => ipToNumber(a) - ipToNumber(b));

    expect(FAVORITE_IPS).toEqual(sorted(FAVORITE_IPS));
    expect(HIDDEN_IPS).toEqual(sorted(HIDDEN_IPS));
  });
});

describe('many hosts', () => {
  it('puts 1,500 hosts on sampled addresses, the same every time', () => {
    const hosts = manyHosts();
    const targets = new Set(buildScanTargets(OFFICE_SUBNET, '10.20.4.17', 4096));

    expect(hosts).toHaveLength(MANY_HOST_COUNT);
    expect(new Set(hosts.map((host) => host.ip)).size).toBe(MANY_HOST_COUNT);
    expect(hosts.every((host) => targets.has(host.ip))).toBe(true);
    expect(networkFor(OFFICE_SUBNET, 'mac')).toBe(hosts);
    expect(hosts[0]).toEqual(manyHosts()[0]);
    expect(hosts.every((host) => (host.via === 'sweep') === host.ports.some((spec) => DISCOVERY_PORTS.includes(spec.port)))).toBe(
      true
    );
  });
});
