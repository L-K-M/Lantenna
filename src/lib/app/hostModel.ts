// Owner: unit B (spec 8.4). Spec: 2.6, 2.8, 3.1, 3.4.
//
// SCAFFOLD STUB: hostModel is an empty model (no rows, nothing selected,
// not loading, no placeholder text).
// Final contract: rows under the hidden rule, the Show scope and the
// Find query, sorted by ui.listSort; row objects cached per Host
// (WeakMap + signature) and immutable, so the list view's identity
// check skips unchanged rows; emptyText/loadingText per table 3.4.

import { readable, type Readable } from 'svelte/store';
import type { HostIconKind } from '$lib/osm/sprites';
import type { Host } from '$lib/types';
import type { PortTarget } from '$lib/util/portTargets';

export type RowStatus = '' | 'New' | 'Checking…' | 'Not seen' | 'Hidden';

export interface HostRow {
  readonly ip: string;
  readonly host: Host;
  readonly customName: string | null;
  /** Display rules of 3.1: the list's name and the icon label's. */
  readonly listName: string;
  readonly iconName: string;
  /** `small` is a CSS image (sprite var), `large` the 32 x 32 SVG url. */
  readonly icon: {
    readonly kind: HostIconKind;
    readonly label: string;
    readonly small: string;
    readonly large: string;
  };
  readonly kind: string;
  readonly vendor: string;
  readonly vendorFull: string;
  readonly portsText: string;
  readonly portCount: number;
  readonly lastSeenMs: number;
  readonly status: RowStatus;
  readonly favorite: boolean;
  readonly hidden: boolean;
  readonly stale: boolean;
  readonly pending: boolean;
  readonly isNew: boolean;
  readonly targets: readonly PortTarget[];
  readonly primaryTarget: PortTarget | null;
}

export interface HostModel {
  /** Hidden rule + scope + query, sorted by ui.listSort. */
  readonly rows: readonly HostRow[];
  /** Hosts under the current hidden rule (N of 5.2). */
  readonly universe: number;
  readonly newCount: number;
  readonly hiddenCount: number;
  readonly selected: HostRow | null;
  readonly loading: boolean;
  readonly loadingText: string;
  readonly emptyText: string;
}

const EMPTY_MODEL: HostModel = {
  rows: [],
  universe: 0,
  newCount: 0,
  hiddenCount: 0,
  selected: null,
  loading: false,
  loadingText: '',
  emptyText: ''
};

export const hostModel: Readable<HostModel> = readable(EMPTY_MODEL);
