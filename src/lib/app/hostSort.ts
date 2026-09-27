// Owner: unit B (spec 8.4). Spec: 2.6.
//
// SCAFFOLD STUB: sortRows returns the rows in the order given.
// Final contract: sort by the column's normal order (table 2.6), turn
// the whole order over when sort.order is "reversed", ties by IP
// ascending, unnamed hosts last in both orders for "name".

import type { ListViewSort } from 'osmium-ui';
import type { HostRow } from './hostModel';

/** The list's column ids, in display order. ui.ts validates a stored
 * sort against them. */
export const COLUMN_IDS = [
  'favorite',
  'name',
  'ip',
  'status',
  'kind',
  'vendor',
  'ports',
  'lastSeen'
] as const;

export type ColumnId = (typeof COLUMN_IDS)[number];

export function sortRows(rows: readonly HostRow[], sort: ListViewSort): HostRow[] {
  return [...rows];
}
