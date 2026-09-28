// Owner: unit D (spec 8.4). The scaffold's cases for the shared wording
// helpers; the locale-dependent parts are checked for shape only.
import { expect, it } from 'vitest';
import {
  formatClock,
  formatCount,
  formatLongDate,
  formatRelativeTime,
  formatWhen,
  normalizeSpaces,
  plural
} from './format';

const ODD_SPACES = /[  ]/;

it('counts with en-US grouping and the right noun', () => {
  expect(formatCount(2048)).toBe('2,048');
  expect(plural(1, 'host')).toBe('1 host');
  expect(plural(0, 'host')).toBe('0 hosts');
  expect(plural(4096, 'address', 'addresses')).toBe('4,096 addresses');
  expect(plural(2, 'hidden', 'hidden')).toBe('2 hidden');
});

it('replaces the spaces no Osmium strike has', () => {
  expect(normalizeSpaces('3:42 PM, today')).toBe('3:42 PM, today');
  expect(formatClock(new Date(2026, 8, 27, 15, 42))).not.toMatch(ODD_SPACES);
});

it('says when the last scan ran in local calendar days', () => {
  const now = new Date(2026, 8, 27, 0, 30);
  const at = (d: Date) => `at ${formatClock(d)}`;
  const today = new Date(2026, 8, 27, 0, 5);
  const yesterday = new Date(2026, 8, 26, 23, 59);
  const earlier = new Date(2026, 8, 25, 15, 42);
  const lastYear = new Date(2025, 8, 25, 15, 42);

  expect(formatWhen(today.toISOString(), now)).toBe(`today ${at(today)}`);
  expect(formatWhen(yesterday.toISOString(), now)).toBe(`yesterday ${at(yesterday)}`);

  const onEarlier = formatWhen(earlier.toISOString(), now);
  expect(onEarlier).toMatch(/^on .+ at /);
  expect(onEarlier.endsWith(at(earlier))).toBe(true);
  expect(onEarlier).not.toContain('2026');
  expect(formatWhen(lastYear.toISOString(), now)).toContain('2025');

  for (const text of [onEarlier, formatWhen(lastYear.toISOString(), now)]) {
    expect(text).not.toMatch(ODD_SPACES);
  }
  expect(formatWhen('not a date', now)).toBe('--');
});

it('marks unknown dates with --', () => {
  expect(formatLongDate('')).toBe('--');
  expect(formatLongDate('garbage')).toBe('--');
  expect(formatRelativeTime('', Date.now())).toBe('--');
  expect(formatRelativeTime('garbage', Date.now())).toBe('--');

  const long = formatLongDate(new Date(2026, 8, 27, 15, 42).toISOString());
  expect(long).toContain('2026');
  expect(long).not.toMatch(ODD_SPACES);
});
