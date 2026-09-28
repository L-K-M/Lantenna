// Owner: scaffold (spec 8.3), complete. Spec: 2.6.
//
// The list's column ids, in a leaf module so ui.ts imports nothing of
// unit B's. hostModel.ts builds a derived store over ui when it loads;
// any import path from ui.ts to it (ui -> hostSort -> hostModel, say)
// would, when ui.ts loads first, run that code before `ui` exists and
// throw a ReferenceError. hostSort.ts re-exports these.

/** The list's column ids, in display order. */
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
