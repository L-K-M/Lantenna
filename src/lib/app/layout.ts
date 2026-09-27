// Owner: scaffold (spec 8.3), complete. Spec: 2.1, 2.3.
//
// Fixed window geometry in CSS pixels (one CSS pixel is one Mac pixel),
// as the code uses it; the page's CSS places the regions (spec 2.3).
// The Tauri inner size W x H includes Osmium's 1px drop shadow; the
// content inner area is (W - FRAME_W) x (H - 29) from page (6, 22).

/** The Host Information pane at the right. */
export const PANE_W = 300;
/** Smallest Tauri inner size. */
export const MIN_W = 840;
export const MIN_H = 560;
/** Tauri inner height of a collapsed window: 22px title bar + shadow. */
export const SHADED_H = 23;

/** Tauri inner width minus the content inner area's: 5 + 1 + 1 + 5 + 1
 * (frame, content border, shadow). */
export const FRAME_W = 13;
/** List row pitch (18px row + white rule), scroll bar width. */
export const LIST_ROW_H = 19;
export const SCROLLBAR_W = 15;
