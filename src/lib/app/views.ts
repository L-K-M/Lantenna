// Owner: scaffold (spec 8.3), complete. Spec: 2.10, 4.1, 3.1 (1.10).
//
// Handles that components publish so commands and actions can reach
// them without importing components: the mounted host view (list or
// icons), the info pane, and the hosted Osmium window. Each publisher
// sets its handle on mount and null on destroy.

import { writable, type Writable } from 'svelte/store';
import type { HostedWindow } from 'osmium-ui';

export interface HostViewApi {
  /** The view's focusable element (the list's grid, the icon grid). */
  readonly element: HTMLElement;
  /** Give the view the keyboard. */
  focus(): void;
  /** Scroll `ip`'s row or tile into view. */
  reveal(ip: string): void;
  /** contentHeight - viewportHeight (>= 0): what zoom adds. */
  extraHeight(): number;
  /** Sum of the list's column widths; null in icon view. */
  idealColumnsWidth(): number | null;
}

/** Published by HostList / HostIconView (unit B). */
export const activeView: Writable<HostViewApi | null> = writable(null);

export interface InfoPaneApi {
  focusName(select: boolean): void;
}

/** Published by HostInfoPane (unit C). */
export const infoPaneApi: Writable<InfoPaneApi | null> = writable(null);

/** Published by +page.svelte. */
export const hostedWindow: Writable<HostedWindow | null> = writable(null);

/** id of the Find field (ControlStrip, unit D). Edit > Find focuses it by
 * id; its "Find:" label points at it with for=. */
export const FIND_FIELD_ID = 'lan-find';
