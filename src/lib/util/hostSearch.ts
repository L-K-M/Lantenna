import type { Host } from '$lib/types';

function searchableText(host: Host, customName: string): string {
  const fp = host.fingerprint;
  const mac = fp?.mac_address || '';

  return [
    host.ip,
    host.name,
    customName,
    fp?.vendor,
    fp?.manufacturer,
    fp?.model_guess,
    fp?.device_type,
    fp?.os_guess,
    mac,
    mac.replace(/[:-]/g, ''),
    ...(fp?.discovered_services || []),
    ...host.open_ports.map((port) => port.service)
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
}

/**
 * Whether a host matches the filter box. Every whitespace-separated term must
 * match something: the address, a name, vendor, type, OS, model, MAC (with or
 * without separators), a service name, or exactly an open port number.
 * So "apple ssh" finds Apple devices with SSH, and "22" finds port 22 as well
 * as addresses containing 22.
 */
export function hostMatchesQuery(host: Host, customName: string, query: string): boolean {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) {
    return true;
  }

  const text = searchableText(host, customName);
  const ports = new Set(host.open_ports.map((port) => String(port.port)));

  return terms.every((term) => ports.has(term) || text.includes(term));
}
