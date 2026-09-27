/**
 * Corporate suffixes stripped from vendor names for compact display, e.g.
 * "Espressif Inc." -> "Espressif". Applied repeatedly from the end.
 */
const LEGAL_SUFFIX =
  /[\s,]+(co\.?,?\s*ltd\.?|ltd\.?|limited|inc\.?|incorporated|corp\.?|corporation|gmbh|ag|s\.?a\.?|llc|b\.?v\.?|pty|co\.?)$/i;

/** Long registry names with a well-known short form, matched by prefix. */
const VENDOR_ALIASES: [prefix: string, short: string][] = [
  ['hangzhou hikvision', 'Hikvision'],
  ['zhejiang dahua', 'Dahua'],
  ['raspberry pi', 'Raspberry Pi'],
  ['micro-star', 'MSI'],
  ['avm audiovisuelles', 'AVM'],
  ['hon hai precision', 'Foxconn'],
  ['asustek', 'ASUS'],
  ['tp-link', 'TP-Link'],
  ['samsung electronics', 'Samsung'],
  ['lg electronics', 'LG'],
  ['sony interactive', 'Sony'],
  ['amazon technologies', 'Amazon'],
  ['intel corporate', 'Intel'],
  ['hewlett packard enterprise', 'HPE'],
  ['hewlett packard', 'HP'],
  ['cisco systems', 'Cisco'],
  ['murata manufacturing', 'Murata']
];

/** Short display form of an OUI vendor name; the full name stays in the inspector. */
export function shortVendorName(vendor: string): string {
  const trimmed = vendor.trim();
  const lowered = trimmed.toLowerCase();
  const alias = VENDOR_ALIASES.find(([prefix]) => lowered.startsWith(prefix));
  if (alias) {
    return alias[1];
  }

  let short = trimmed;
  let previous = '';
  while (short !== previous) {
    previous = short;
    short = short.replace(LEGAL_SUFFIX, '').trim();
  }

  return short || trimmed;
}

/**
 * Cleans text from device registries and banners for display: drops control
 * and zero-width characters, collapses whitespace, and adds a missing space
 * after a comma ("Co.,Ltd" -> "Co., Ltd"). It leaves periods alone so
 * versions like "1.24.0" survive.
 */
export function normalizeDisplayText(value: string): string {
  return value
    .normalize('NFKC')
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/\s+,/g, ',')
    .replace(/,(?=\p{L})/gu, ', ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Finder's mark for an empty value (spec 3.4). */
export const EMPTY_VALUE = '--';

/** "just now", "5 min ago", "3 h ago", "2 d ago", then the date; `--`
 * when unknown. */
export function formatRelativeTime(iso: string, now: number): string {
  if (!iso) {
    return EMPTY_VALUE;
  }

  const timestamp = Date.parse(iso);
  if (Number.isNaN(timestamp)) {
    return EMPTY_VALUE;
  }

  const minutes = Math.floor((now - timestamp) / 60_000);
  if (minutes < 1) {
    return 'just now';
  }
  if (minutes < 60) {
    return `${minutes} min ago`;
  }

  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours} h ago`;
  }

  const days = Math.floor(hours / 24);
  if (days < 7) {
    return `${days} d ago`;
  }

  return new Date(timestamp).toLocaleDateString();
}

// Spec 3.4 and 8.2: the wording helpers every unit shares (added by the
// scaffold so units B, C and D use one set; unit D owns the file).
// Numbers use en-US grouping; dates and times use the user's locale,
// with the narrow and no-break spaces some locales put in them replaced
// by plain spaces, since no Osmium strike has those characters.

/** U+202F and U+00A0 become plain spaces. */
export function normalizeSpaces(text: string): string {
  return text.replace(/[\u202F\u00A0]/g, ' ');
}

/** 2048 -> "2,048". */
export function formatCount(n: number): string {
  return n.toLocaleString('en-US');
}

/**
 * The count and the noun that fits it: plural(1, 'host') is "1 host",
 * plural(2048, 'port') "2,048 ports". Pass `many` for words without an
 * "s" plural: plural(2, 'hidden', 'hidden') is "2 hidden".
 */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${formatCount(n)} ${n === 1 ? one : many}`;
}

/** The time of day in the user's locale, "3:44 PM" (5.3's status line). */
export function formatClock(date: Date): string {
  return normalizeSpaces(date.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' }));
}

/** Days since the epoch of `date`'s local calendar day. */
function localDay(date: Date): number {
  return Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()) / 86_400_000;
}

/**
 * When the last scan ran, for the header (5.2 `<when>`): "today at 3:42
 * PM", "yesterday at 3:42 PM", "on Sep 25 at 3:42 PM", and "on Sep 25,
 * 2025 at 3:42 PM" in another year (en-US shown; the date and time
 * follow the user's locale). Days are local calendar days. `--` for an
 * invalid date.
 */
export function formatWhen(iso: string, now: Date): string {
  const timestamp = Date.parse(iso);
  if (Number.isNaN(timestamp)) {
    return EMPTY_VALUE;
  }

  const date = new Date(timestamp);
  const at = `at ${formatClock(date)}`;
  const daysAgo = localDay(now) - localDay(date);
  if (daysAgo === 0) {
    return `today ${at}`;
  }
  if (daysAgo === 1) {
    return `yesterday ${at}`;
  }

  const sameYear = date.getFullYear() === now.getFullYear();
  const day = date.toLocaleDateString(
    undefined,
    sameYear ? { month: 'short', day: 'numeric' } : { month: 'short', day: 'numeric', year: 'numeric' }
  );
  return `on ${normalizeSpaces(day)} ${at}`;
}

/** The full date and time, for General's Last Seen (2.7): "Sep 27,
 * 2026, 3:42 PM" in en-US; `--` for an empty or invalid date. */
export function formatLongDate(iso: string): string {
  const timestamp = iso ? Date.parse(iso) : Number.NaN;
  if (Number.isNaN(timestamp)) {
    return EMPTY_VALUE;
  }

  return normalizeSpaces(new Date(timestamp).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }));
}
