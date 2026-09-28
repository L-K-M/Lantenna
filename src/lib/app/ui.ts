// Owner: scaffold (spec 8.3), complete. Spec: 2.7, 2.9, 3.5, 4.1, 4.5.
//
// Page state that is not scan data: the view, the Show scope, the pane
// and its front tab, the list's sort and column widths, Balloon Help,
// and the window's active and shaded state. Settings are read once at
// module load and written on every change through storage.ts (keys of
// 3.5); scope, active and shaded are not persisted.
//
// ui records what happened; it drives nothing. The page mirrors Osmium's
// Balloon Help state into it (onBalloonHelpChange -> setBalloons) and the
// window's activity and fold (setActive, setShaded).

import { writable, type Readable } from 'svelte/store';
import type { BalloonHelpState, ListViewSort } from 'osmium-ui';
import type { HostViewMode } from '$lib/types';
import { readJson, readString, writeJson, writeString } from '$lib/util/storage';
import { COLUMN_IDS } from './columns';

export type ShowScope = 'all' | 'favorites' | 'new';
export type InfoTab = 'general' | 'ports' | 'fingerprint';

export interface UiState {
  viewMode: HostViewMode;
  scope: ShowScope;
  infoPaneShown: boolean;
  infoTab: InfoTab;
  listSort: ListViewSort;
  /** Column widths after a divider drag, by column id; null before. */
  columnWidths: Readonly<Record<string, number>> | null;
  balloons: BalloonHelpState;
  active: boolean;
  shaded: boolean;
}

const VIEW_MODE_KEY = 'lantenna.viewMode';
const INFO_PANE_KEY = 'lantenna.infoPane';
const INFO_TAB_KEY = 'lantenna.infoTab';
const LIST_SORT_KEY = 'lantenna.listSort';
const LIST_COLUMNS_KEY = 'lantenna.listColumns';
const BALLOON_HELP_KEY = 'lantenna.balloonHelp';

const INFO_TABS: readonly InfoTab[] = ['general', 'ports', 'fingerprint'];
const COLUMNS: readonly string[] = COLUMN_IDS;

/** Today's order: favorites first, then IP. */
const DEFAULT_SORT: ListViewSort = { column: 'favorite', order: 'normal' };

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isListSort(v: unknown): v is ListViewSort {
  return (
    isRecord(v) &&
    typeof v.column === 'string' &&
    COLUMNS.includes(v.column) &&
    (v.order === 'normal' || v.order === 'reversed')
  );
}

function isColumnWidths(v: unknown): v is Record<string, number> {
  return (
    isRecord(v) &&
    Object.entries(v).every(
      ([id, px]) => COLUMNS.includes(id) && typeof px === 'number' && Number.isFinite(px) && px > 0
    )
  );
}

function loadState(): UiState {
  const tab = readString(INFO_TAB_KEY);

  return {
    viewMode: readString(VIEW_MODE_KEY) === 'icons' ? 'icons' : 'list',
    scope: 'all',
    infoPaneShown: readString(INFO_PANE_KEY) !== 'hidden',
    infoTab: INFO_TABS.find((t) => t === tab) ?? 'general',
    listSort: readJson(LIST_SORT_KEY, isListSort) ?? DEFAULT_SORT,
    columnWidths: readJson(LIST_COLUMNS_KEY, isColumnWidths),
    balloons: readString(BALLOON_HELP_KEY) === 'shown' ? 'shown' : 'hidden',
    active: true,
    shaded: false
  };
}

function createUi() {
  let state = loadState();
  const store = writable<UiState>(state);

  /** Apply `next` only if it changes something, so subscribers (the
   * native menu sync, the list) don't run for no-op calls. */
  function patch(next: Partial<UiState>): boolean {
    const changed = (Object.keys(next) as (keyof UiState)[]).some((k) => state[k] !== next[k]);
    if (!changed) return false;

    state = { ...state, ...next };
    store.set(state);
    return true;
  }

  return {
    subscribe: store.subscribe,
    setViewMode(m: HostViewMode) {
      if (patch({ viewMode: m })) writeString(VIEW_MODE_KEY, m);
    },
    setScope(s: ShowScope) {
      patch({ scope: s });
    },
    setInfoPane(shown: boolean) {
      if (patch({ infoPaneShown: shown })) writeString(INFO_PANE_KEY, shown ? 'shown' : 'hidden');
    },
    setInfoTab(t: InfoTab) {
      if (patch({ infoTab: t })) writeString(INFO_TAB_KEY, t);
    },
    setListSort(s: ListViewSort) {
      if (state.listSort.column === s.column && state.listSort.order === s.order) return;

      const listSort: ListViewSort = { column: s.column, order: s.order };
      patch({ listSort });
      writeJson(LIST_SORT_KEY, listSort);
    },
    /** Every column's width after a divider drag (Osmium fixes all of
     * them on the first drag, so all are stored): one update, one write. */
    setColumnWidths(widths: Readonly<Record<string, number>>) {
      // A programming error: stored, it would fail isColumnWidths at the
      // next launch and lose every width.
      if (!isColumnWidths(widths)) throw new RangeError(`invalid column widths ${JSON.stringify(widths)}`);

      const current = state.columnWidths;
      const ids = Object.keys(widths);
      const same =
        current !== null &&
        Object.keys(current).length === ids.length &&
        ids.every((id) => current[id] === widths[id]);
      if (same) return;

      const columnWidths = { ...widths };
      patch({ columnWidths });
      writeJson(LIST_COLUMNS_KEY, columnWidths);
    },
    setBalloons(s: BalloonHelpState) {
      if (patch({ balloons: s })) writeString(BALLOON_HELP_KEY, s);
    },
    setActive(a: boolean) {
      patch({ active: a });
    },
    setShaded(s: boolean) {
      patch({ shaded: s });
    }
  };
}

export const ui: Readable<UiState> & {
  setViewMode(m: HostViewMode): void;
  setScope(s: ShowScope): void;
  setInfoPane(shown: boolean): void;
  setInfoTab(t: InfoTab): void;
  setListSort(s: ListViewSort): void;
  setColumnWidths(widths: Readonly<Record<string, number>>): void;
  setBalloons(s: BalloonHelpState): void;
  setActive(a: boolean): void;
  setShaded(s: boolean): void;
} = createUi();
