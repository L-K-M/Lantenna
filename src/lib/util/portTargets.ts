import type { Host } from '$lib/types';

export interface PortTarget {
  label: 'HTTP' | 'HTTPS' | 'SMB' | 'SSH' | 'FTP' | 'VNC' | 'Telnet' | 'RTSP';
  url: string;
}

const httpPorts = new Set([
  80, 81, 82, 3000, 3001, 5000, 5601, 7001, 7080, 8000, 8008, 8080, 8081, 8088, 8090, 8123, 8181, 8880, 8888,
  9000, 9080, 9090
]);
const httpsPorts = new Set([443, 444, 5443, 6443, 7443, 8443, 8843, 9443, 10443]);
const smbPorts = new Set([139, 445]);
const sshPorts = new Set([22, 2222]);
const ftpPorts = new Set([21, 2121]);
const vncPorts = new Set([5900, 5901, 5902]);
const telnetPorts = new Set([23, 2323]);
const rtspPorts = new Set([554, 8554]);

const IPV4_LITERAL = /^\d{1,3}(\.\d{1,3}){3}$/;

/** The URL a user would open for an open port, or null when there is none. */
export function getPortTarget(hostIp: string, port: number, service: string | null): PortTarget | null {
  // These URLs go to the OS opener; only interpolate a plain IPv4 address
  // (host records can also come from favorites saved in localStorage).
  if (!IPV4_LITERAL.test(hostIp)) {
    return null;
  }

  const normalized = (service || '').toLowerCase();
  const buildUrl = (
    scheme: 'http' | 'https' | 'ftp' | 'ssh' | 'telnet' | 'rtsp' | 'vnc',
    defaultPort: number
  ): string => `${scheme}://${hostIp}${port === defaultPort ? '' : `:${port}`}`;

  // FTP's data port never accepts a control connection.
  if (normalized === 'ftp-data') {
    return null;
  }

  if (normalized.includes('https') || normalized.includes('ssl/http') || normalized.includes('tls/http')) {
    return { label: 'HTTPS', url: buildUrl('https', 443) };
  }

  if (normalized.includes('http')) {
    return { label: 'HTTP', url: buildUrl('http', 80) };
  }

  if (normalized.includes('smb') || normalized.includes('microsoft-ds') || normalized.includes('netbios')) {
    return { label: 'SMB', url: `smb://${hostIp}` };
  }

  if (normalized.includes('ssh')) {
    return { label: 'SSH', url: buildUrl('ssh', 22) };
  }

  if (normalized.includes('ftp')) {
    return { label: 'FTP', url: buildUrl('ftp', 21) };
  }

  if (normalized.includes('vnc')) {
    return { label: 'VNC', url: buildUrl('vnc', 5900) };
  }

  if (normalized.includes('telnet')) {
    return { label: 'Telnet', url: buildUrl('telnet', 23) };
  }

  if (normalized.includes('rtsp')) {
    return { label: 'RTSP', url: buildUrl('rtsp', 554) };
  }

  if (httpsPorts.has(port)) {
    return { label: 'HTTPS', url: buildUrl('https', 443) };
  }

  if (httpPorts.has(port)) {
    return { label: 'HTTP', url: buildUrl('http', 80) };
  }

  if (smbPorts.has(port)) {
    return { label: 'SMB', url: `smb://${hostIp}` };
  }

  if (sshPorts.has(port)) {
    return { label: 'SSH', url: buildUrl('ssh', 22) };
  }

  if (ftpPorts.has(port)) {
    return { label: 'FTP', url: buildUrl('ftp', 21) };
  }

  if (vncPorts.has(port)) {
    return { label: 'VNC', url: buildUrl('vnc', 5900) };
  }

  if (telnetPorts.has(port)) {
    return { label: 'Telnet', url: buildUrl('telnet', 23) };
  }

  if (rtspPorts.has(port)) {
    return { label: 'RTSP', url: buildUrl('rtsp', 554) };
  }

  return null;
}

/**
 * Targets a double-click or Return may open, in order of preference: the web
 * UI (HTTP before HTTPS, since devices usually redirect), then file sharing,
 * remote login and screen sharing. Telnet, FTP and RTSP stay link-only in the
 * inspector; launching those handlers from a double-click would surprise.
 */
const PRIMARY_TARGET_ORDER: PortTarget['label'][] = ['HTTP', 'HTTPS', 'SMB', 'SSH', 'VNC'];

/** What opening a host should do, or null when nothing suitable is open. */
export function primaryPortTarget(host: Host): PortTarget | null {
  const targets = host.open_ports
    .map((port) => getPortTarget(host.ip, port.port, port.service))
    .filter((target): target is PortTarget => target !== null);

  for (const label of PRIMARY_TARGET_ORDER) {
    const target = targets.find((item) => item.label === label);
    if (target) {
      return target;
    }
  }

  return null;
}
