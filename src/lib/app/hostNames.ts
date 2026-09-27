// Owner: scaffold (spec 8.3), complete. Spec: 2.6 (Name cell), 2.8
// (tile label), 3.1 (1.10 Favorites menu, 1.12 display rules kept), 4.1.
//
// The display-name rules in one place, pure over a Host and its custom
// name, so the list (unit B), the pane and copy actions (C) and the
// Favorites menu (E), which also names favorites that are not listed,
// agree. Take the custom name from customNameFor(store.customNames, ip).

import type { Host } from '$lib/types';

/** `ip`'s custom name, trimmed; null when it has none. */
export function customNameFor(customNames: Readonly<Record<string, string>>, ip: string): string | null {
  return customNames[ip]?.trim() || null;
}

/** The list's Name cell: the custom name, else the detected name, else
 * "Unknown" (2.6, unchanged). */
export function listName(host: Host, customName: string | null): string {
  return customName || host.name || 'Unknown';
}

/** An icon tile's label: the custom name, else the detected name without
 * a trailing ".local", else the IP (2.8, unchanged). */
export function iconName(host: Host, customName: string | null): string {
  return customName || host.name?.replace(/\.local$/, '') || host.ip;
}

/** The custom name, else the detected name; null when the host has
 * neither. The Favorites menu shows "<name> (<ip>)" or just the IP, and
 * Copy Host Name is dimmed without one (4.1). */
export function knownName(host: Host, customName: string | null): string | null {
  return customName || host.name || null;
}
