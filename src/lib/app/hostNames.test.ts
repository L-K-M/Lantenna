import { expect, it } from 'vitest';
import type { Host } from '$lib/types';
import { customNameFor, iconName, knownName, listName } from './hostNames';

function host(name: string | null): Host {
  return { ip: '192.168.1.31', name, reachable: true, open_ports: [], last_seen: '', fingerprint: null };
}

it('reads a custom name only when it has text', () => {
  const names = { '192.168.1.31': '  Office Printer ', '192.168.1.32': '   ' };

  expect(customNameFor(names, '192.168.1.31')).toBe('Office Printer');
  expect(customNameFor(names, '192.168.1.32')).toBeNull();
  expect(customNameFor(names, '192.168.1.33')).toBeNull();
});

it('names hosts as the list, the icons and the menus do', () => {
  const detected = host('BRN30055C123456.local');
  const unnamed = host(null);

  expect(listName(detected, 'Printer')).toBe('Printer');
  expect(listName(detected, null)).toBe('BRN30055C123456.local');
  expect(listName(unnamed, null)).toBe('Unknown');

  expect(iconName(detected, null)).toBe('BRN30055C123456');
  expect(iconName(unnamed, null)).toBe('192.168.1.31');

  expect(knownName(detected, 'Printer')).toBe('Printer');
  expect(knownName(detected, null)).toBe('BRN30055C123456.local');
  expect(knownName(unnamed, null)).toBeNull();
});
