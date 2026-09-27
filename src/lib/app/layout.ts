// Owner: scaffold (spec 8.3), complete. Spec: 2.1, 2.3.
//
// Fixed window geometry in CSS pixels (one CSS pixel is one Mac pixel).
// The Tauri inner size W x H includes Osmium's 1px drop shadow; the
// content inner area is (W - FRAME_W) x (H - FRAME_H) from page (6, 22).

import { isMac } from './platform';

/** The Osmium menu bar at the top of the content (Linux only). */
export const MENUBAR_H: number = isMac ? 0 : 20;
/** The control strip on the gray: Interface, Depth, Scan / Show, Find. */
export const STRIP_H = 64;
/** The Finder window header (.osm-placard) under the strip. */
export const HEADER_H = 21;
/** The Host Information pane at the right. */
export const PANE_W = 300;
/** Smallest Tauri inner size. */
export const MIN_W = 840;
export const MIN_H = 560;
/** Tauri inner height of a collapsed window: 22px title bar + shadow. */
export const SHADED_H = 23;

/** Tauri inner size minus the content inner area: 5 + 1 + 1 + 5 + 1
 * across (frame, content border, shadow), 21 + 1 + 1 + 5 + 1 down. */
export const FRAME_W = 13;
export const FRAME_H = 29;
/** List column headers, row pitch (18px row + white rule), scroll bar. */
export const LIST_HEADER_H = 21;
export const LIST_ROW_H = 19;
export const SCROLLBAR_W = 15;
