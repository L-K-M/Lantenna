// Owner: scaffold (spec 8.3), complete. Spec: 2.10, 4.1, 3.1 (1.10).
//
// Handles that components publish so commands and actions can reach
// them without importing components: the mounted host view (list or
// icons), the info pane, and the hosted Osmium window. Each publisher
// sets its handle on mount and null on destroy.

import { writable, type Writable } from 'svelte/store';
import type { HostedWindow } from 'osmium-ui';

/**
 * Callers change stores and call the view in the same task: revealHost
 * sets the scope, the query and Show hidden hosts, selects, then calls
 * reveal() and focus(); Find's Return selects the first row and calls
 * focus(); zoom reads extraHeight(). The view hands rows to Osmium once
 * per animation frame, so focus(), reveal() and extraHeight() first
 * apply any pending rows synchronously from the latest hostModel
 * (Osmium's reveal and select can't scroll to a key it has no row for,
 * and contentHeight counts the rows it has).
 */
export interface HostViewApi {
  /** The view's focusable element (the list's grid, the icon grid). */
  readonly element: HTMLElement;
  /** Give the view the keyboard (after applying pending rows). */
  focus(): void;
  /** Apply pending rows, then scroll `ip`'s row or tile into view. */
  reveal(ip: string): void;
  /** contentHeight - viewportHeight (>= 0) with the latest rows: what
   * zoom adds. */
  extraHeight(): number;
  /** Sum of the list's column widths; null in icon view. */
  idealColumnsWidth(): number | null;
}

/** Published by HostList / HostIconView (unit B). */
export const activeView: Writable<HostViewApi | null> = writable(null);

export interface InfoPaneApi {
  /** Host > Rename…: give the name field the keyboard, its text selected. */
  focusName(): void;
}

/** Published by HostInfoPane (unit C). */
export const infoPaneApi: Writable<InfoPaneApi | null> = writable(null);

/** Published by +page.svelte. */
export const hostedWindow: Writable<HostedWindow | null> = writable(null);

/** id of the Find field (ControlStrip, unit D). Edit > Find focuses it by
 * id; its "Find:" label points at it with for=. */
export const FIND_FIELD_ID = 'lan-find';
