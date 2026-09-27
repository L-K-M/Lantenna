// Owner: unit B (spec 8.4). Spec: 2.6.
//
// SCAFFOLD STUB: sortRows returns the rows in the order given.
// Final contract: sort by the column's normal order (table 2.6), turn
// the whole order over when sort.order is "reversed", ties by IP
// ascending, unnamed hosts last in both orders for "name".

import type { ListViewSort } from 'osmium-ui';
import type { HostRow } from './hostModel';

// Defined in the scaffold's leaf module columns.ts (see its header).
export { COLUMN_IDS, type ColumnId } from './columns';

export function sortRows(rows: readonly HostRow[], sort: ListViewSort): HostRow[] {
  return [...rows];
}
