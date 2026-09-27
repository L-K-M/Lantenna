// Owner: unit A (spec 8.4). Spec: 2.10 (Standard size).
//
// SCAFFOLD STUB: zoomTarget keeps the current size.
// Final contract: pure; toggles between the user frame and the standard
// size (Mac OS 8 rule), clamped to `min` and to the work area below and
// right of the window, shifting the window left/up when the standard
// frame would cross the work area's right or bottom edge.

export interface Size {
  w: number;
  h: number;
}

export interface ZoomInput {
  inner: Size;
  position: { x: number; y: number };
  workArea: { x: number; y: number; w: number; h: number };
  ideal: Size;
  min: Size;
  lastStandard: Size | null;
  userFrame: Size | null;
}

export function zoomTarget(i: ZoomInput): {
  size: Size;
  position?: { x: number; y: number };
  userFrame: Size | null;
  standard: Size;
} {
  return { size: i.inner, userFrame: i.userFrame, standard: i.ideal };
}
