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

/** "just now", "5 min ago", "3 h ago", "2 d ago", then the date. */
export function formatRelativeTime(iso: string, now: number): string {
  if (!iso) {
    return '-';
  }

  const timestamp = Date.parse(iso);
  if (Number.isNaN(timestamp)) {
    return '-';
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
