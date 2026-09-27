// Owner: unit C (spec 8.4): the name field's commit rule (2.7).
import { describe, expect, it } from 'vitest';
import type { Host } from '$lib/types';
import { commitName, detectedDisplayName, nameFieldValue } from './nameCommit';

function host(name: string | null): Host {
  return { ip: '192.168.1.31', name, reachable: true, open_ports: [], last_seen: '', fingerprint: null };
}

const detected = host('BRN30055C123456.local');
const unnamed = host(null);

describe('the field value', () => {
  it('is the custom name, else the detected name without .local, else empty', () => {
    expect(nameFieldValue(detected, 'Office Printer')).toBe('Office Printer');
    expect(nameFieldValue(detected, null)).toBe('BRN30055C123456');
    expect(nameFieldValue(host('router'), null)).toBe('router');
    expect(nameFieldValue(unnamed, null)).toBe('');
  });

  it('strips only a trailing .local', () => {
    expect(detectedDisplayName(host('printer.local.lan'))).toBe('printer.local.lan');
    expect(detectedDisplayName(host('studio.local'))).toBe('studio');
    expect(detectedDisplayName(unnamed)).toBe('');
  });
});

describe('committing', () => {
  it('sets a new name, trimmed', () => {
    expect(commitName('  Office Printer ', detected, null)).toEqual({ action: 'set', name: 'Office Printer' });
    expect(commitName('Printer 2', detected, 'Office Printer')).toEqual({ action: 'set', name: 'Printer 2' });
    expect(commitName('NAS', unnamed, null)).toEqual({ action: 'set', name: 'NAS' });
  });

  it('clears the custom name when the text is empty', () => {
    expect(commitName('', detected, 'Office Printer')).toEqual({ action: 'clear' });
    expect(commitName('   ', detected, 'Office Printer')).toEqual({ action: 'clear' });
  });

  it('does nothing for empty text without a custom name', () => {
    expect(commitName('', detected, null)).toEqual({ action: 'none' });
    expect(commitName('  ', unnamed, null)).toEqual({ action: 'none' });
  });

  it('does nothing for the detected display name while no custom name exists', () => {
    expect(commitName('BRN30055C123456', detected, null)).toEqual({ action: 'none' });
    expect(commitName(' BRN30055C123456 ', detected, null)).toEqual({ action: 'none' });
  });

  it('keeps the detected display name as a custom name once one exists', () => {
    expect(commitName('BRN30055C123456', detected, 'Office Printer')).toEqual({
      action: 'set',
      name: 'BRN30055C123456'
    });
  });

  it('does nothing for the current custom name', () => {
    expect(commitName('Office Printer', detected, 'Office Printer')).toEqual({ action: 'none' });
    expect(commitName(' Office Printer  ', detected, 'Office Printer')).toEqual({ action: 'none' });
  });
});
