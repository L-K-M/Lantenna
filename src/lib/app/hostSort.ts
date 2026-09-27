// Owner: unit B (spec 8.4). Spec: 2.6 (column orders), 2.8 (the icon
// view follows the list's sort).
//
// The list's sort as the Finder does it (Osmium's ListViewSort): one sort
// column and one order for the whole list. Each column has a normal
// order (table 2.6); "reversed" turns that order over. Two rules hold in
// both orders: ties go by IP address ascending, and unnamed hosts sort
// after named ones by Name (kept from the pre-port list).
//
// Import direction: hostModel.ts imports this module, so this one takes
// only types from it.

import type { ListViewSort } from 'osmium-ui';
import type { HostRow, RowStatus } from './hostModel';
import { COLUMN_IDS, type ColumnId } from './columns';

// Defined in the scaffold's leaf module columns.ts (see its header).
export { COLUMN_IDS, type ColumnId } from './columns';

/** 192.168.1.10 -> a number that orders addresses numerically; anything
 * that isn't a dotted quad sorts last. */
export function ipOrder(ip: string): number {
  const parts = ip.split('.');
  if (parts.length !== 4) return Number.MAX_SAFE_INTEGER;

  let value = 0;
  for (const part of parts) {
    const octet = /^\d{1,3}$/.test(part) ? Number(part) : Number.NaN;
    if (!(octet <= 255)) return Number.MAX_SAFE_INTEGER;
    value = value * 256 + octet;
  }

  return value;
}

/** The Status column's normal order (2.6). */
const STATUS_ORDER: Readonly<Record<RowStatus, number>> = {
  New: 0,
  'Checking…': 1,
  'Not seen': 2,
  Hidden: 3,
  '': 4
};

// Names and texts as the Finder compares them: case and accents aside,
// digits by value ("host 9" before "host 10").
const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

/** Hosts with neither a custom nor a detected name ("Unknown"). */
function isUnnamed(row: HostRow): boolean {
  return !row.customName && !row.host.name;
}

type Compare = (a: HostRow, b: HostRow) => number;

/** Each column's normal order: negative when `a` comes first. */
const NORMAL_ORDER: Readonly<Record<ColumnId, Compare>> = {
  // Favorites first.
  favorite: (a, b) => Number(b.favorite) - Number(a.favorite),
  // A to Z.
  name: (a, b) => collator.compare(a.listName, b.listName),
  // Numeric, ascending.
  ip: (a, b) => a.ipNum - b.ipNum,
  status: (a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status],
  kind: (a, b) => collator.compare(a.kind, b.kind),
  vendor: (a, b) => collator.compare(a.vendor, b.vendor),
  // Most first, as the Finder's Size column puts the largest first.
  ports: (a, b) => b.portCount - a.portCount,
  // Newest first, as the Finder's date columns; unknown dates (0) last.
  lastSeen: (a, b) => b.lastSeenMs - a.lastSeenMs
};

const COLUMNS: readonly string[] = COLUMN_IDS;

function isColumnId(column: string): column is ColumnId {
  return COLUMNS.includes(column);
}

/**
 * `rows` in `sort`'s order, as a new array. An unknown column keeps the
 * IP order (ui.ts only stores known columns; this is a fallback, not a
 * mode).
 */
export function sortRows(rows: readonly HostRow[], sort: ListViewSort): HostRow[] {
  const compare = isColumnId(sort.column) ? NORMAL_ORDER[sort.column] : null;
  const direction = sort.order === 'reversed' ? -1 : 1;
  const byName = sort.column === 'name';

  return [...rows].sort((a, b) => {
    if (byName) {
      const unnamed = Number(isUnnamed(a)) - Number(isUnnamed(b));
      if (unnamed !== 0) return unnamed;
    }

    const result = compare ? compare(a, b) : 0;
    if (result !== 0) return direction * result;

    return a.ipNum - b.ipNum;
  });
}
