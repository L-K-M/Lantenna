// Owner: unit A (spec 8.4). Spec: 2.10 (Standard size).
//
// The zoom box's arithmetic, pure. The zoom box toggles the window
// between the user state (where the user put it) and the standard state
// (the size that shows everything), the Mac OS 8 way:
//
// - Which state: the window is in the standard state when its size is
//   within 1 px of the standard size zoom last went to (the size only,
//   as 8.5's IsWindowInStandardState compares). Then zoom restores the
//   saved user frame, size and position, and forgets it.
// - Otherwise the current frame becomes the user frame and the window
//   goes to the standard size: the ideal size clamped to the minimum and
//   to the work area. It keeps its top-left corner when that frame fits
//   in the work area, and else moves as little as possible to stay on
//   the screen (HIG: "Move the window as little as possible to make it
//   the standard size, and keep the window on the screen"; Osmium's own
//   Swift host does the same).
//
// All values are logical pixels (one CSS pixel each).

import { FRAME_W, PANE_W, SCROLLBAR_W } from './layout';

export interface Size {
  w: number;
  h: number;
}

export interface Point {
  x: number;
  y: number;
}

/** A window frame: its top-left corner and inner size. */
export interface Frame extends Point, Size {}

export interface ZoomInput {
  /** The window's inner size now. */
  inner: Size;
  /** The window's top-left corner now. */
  position: Point;
  /** The monitor's work area (without the menu bar and Dock); null when
   * no monitor is known: no clamp, no move. */
  workArea: Frame | null;
  /** What shows everything (idealSize). */
  ideal: Size;
  min: Size;
  /** The standard size of the previous zoom; null before the first. */
  lastStandard: Size | null;
  /** The user frame saved by the zoom to the standard size. */
  userFrame: Frame | null;
}

export interface ZoomTarget {
  size: Size;
  /** Where to move the window; absent when it stays put. */
  position?: Point;
  /** Move before resizing: the order whose in-between frame stays in
   * the work area (move up, then grow; shrink, then move down). */
  moveFirst: boolean;
  /** The user frame to keep for the next zoom. */
  userFrame: Frame | null;
  /** The standard size this zoom computed (the next lastStandard). */
  standard: Size;
}

export interface IdealInput {
  inner: Size;
  /** The list's columns in total; null in icon view, which keeps the
   * window's width. */
  columnsWidth: number | null;
  paneShown: boolean;
  /** How much taller the view's content is than the view (>= 0). */
  extraHeight: number;
}

/** The list view's black right edge, drawn only beside the pane. */
const VIEW_EDGE_W = 1;

/** How close to the standard size counts as being in the standard
 * state (spec 2.10). */
const STATE_TOLERANCE = 1;

/**
 * The size that shows every column and every row: the frame, the
 * columns, the list's vertical scroll bar and, when shown, the view's
 * edge and the pane across; the window's height plus what the view
 * would scroll. With the default columns (790 px) and the pane that is
 * 1119 px wide.
 */
export function idealSize(i: IdealInput): Size {
  const pane = i.paneShown ? VIEW_EDGE_W + PANE_W : 0;
  const w = i.columnsWidth === null ? i.inner.w : FRAME_W + i.columnsWidth + SCROLLBAR_W + pane;

  return { w, h: i.inner.h + i.extraHeight };
}

export function zoomTarget(i: ZoomInput): ZoomTarget {
  const standard = standardSize(i.ideal, i.min, i.workArea);

  if (i.userFrame && i.lastStandard && near(i.inner, i.lastStandard)) {
    const { x, y, w, h } = i.userFrame;
    return { size: { w, h }, ...moveTo(i, { x, y }), userFrame: null, standard };
  }

  return {
    size: standard,
    ...moveTo(i, onScreen(i.position, standard, i.workArea)),
    userFrame: { ...i.position, ...i.inner },
    standard
  };
}

function standardSize(ideal: Size, min: Size, area: Frame | null): Size {
  const maxW = area ? Math.floor(area.w) : Infinity;
  const maxH = area ? Math.floor(area.h) : Infinity;

  // The minimum wins over a work area smaller than the window can be.
  return {
    w: Math.max(min.w, Math.min(ideal.w, maxW)),
    h: Math.max(min.h, Math.min(ideal.h, maxH))
  };
}

/** Where a window of `size` at `at` goes to lie inside `area`: shifted
 * left and up past the right and bottom edges, but never past the left
 * and top edges (the title bar stays reachable). */
function onScreen(at: Point, size: Size, area: Frame | null): Point {
  if (!area) return at;

  return {
    x: Math.round(Math.max(area.x, Math.min(at.x, area.x + area.w - size.w))),
    y: Math.round(Math.max(area.y, Math.min(at.y, area.y + area.h - size.h)))
  };
}

/** `{ position }` when `to` is a real move away from the window's
 * position (which comes from physical pixels divided by the scale
 * factor, so it may be off by half a pixel), and in which order. */
function moveTo(i: ZoomInput, to: Point): { position?: Point; moveFirst: boolean } {
  const from = i.position;
  const moved = Math.abs(to.x - from.x) > 0.5 || Math.abs(to.y - from.y) > 0.5;
  if (!moved) return { moveFirst: false };

  const movedFirst = { ...to, ...i.inner };
  return { position: to, moveFirst: !i.workArea || inside(movedFirst, i.workArea) };
}

function inside(f: Frame, area: Frame): boolean {
  return f.x >= area.x && f.y >= area.y && f.x + f.w <= area.x + area.w && f.y + f.h <= area.y + area.h;
}

function near(a: Size, b: Size): boolean {
  return Math.abs(a.w - b.w) <= STATE_TOLERANCE && Math.abs(a.h - b.h) <= STATE_TOLERANCE;
}
