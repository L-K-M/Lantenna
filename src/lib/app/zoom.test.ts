// Owner: unit A (spec 8.4). Spec: 2.10 (Standard size).
import { describe, expect, it } from 'vitest';
import { idealSize, zoomTarget, type ZoomInput } from './zoom';

/** A 1440 x 900 screen with a 25 px menu bar, the window at (100, 80). */
function input(change: Partial<ZoomInput> = {}): ZoomInput {
  return {
    inner: { w: 1200, h: 760 },
    position: { x: 100, y: 80 },
    workArea: { x: 0, y: 25, w: 1440, h: 875 },
    ideal: { w: 1119, h: 760 },
    min: { w: 840, h: 560 },
    lastStandard: null,
    userFrame: null,
    ...change
  };
}

describe('idealSize', () => {
  const inner = { w: 1200, h: 760 };

  it('fits the default columns, the scroll bar, the view’s edge and the pane', () => {
    expect(idealSize({ inner, columnsWidth: 790, paneShown: true, extraHeight: 0 })).toEqual({ w: 1119, h: 760 });
  });

  it('drops the pane and the edge beside it when the pane is hidden', () => {
    expect(idealSize({ inner, columnsWidth: 790, paneShown: false, extraHeight: 0 }).w).toBe(13 + 790 + 15);
  });

  it('follows dragged columns', () => {
    expect(idealSize({ inner, columnsWidth: 1000, paneShown: true, extraHeight: 0 }).w).toBe(1329);
  });

  it('keeps the width in icon view', () => {
    expect(idealSize({ inner, columnsWidth: null, paneShown: true, extraHeight: 0 }).w).toBe(1200);
  });

  it('adds what the view would scroll to the height', () => {
    expect(idealSize({ inner, columnsWidth: 790, paneShown: true, extraHeight: 190 }).h).toBe(950);
  });
});

describe('zoomTarget', () => {
  it('saves the user frame and goes to the standard size, top-left kept', () => {
    const target = zoomTarget(input());

    expect(target).toEqual({
      size: { w: 1119, h: 760 },
      moveFirst: false,
      userFrame: { x: 100, y: 80, w: 1200, h: 760 },
      standard: { w: 1119, h: 760 }
    });
    expect(target).not.toHaveProperty('position');
  });

  it('restores the user frame, size and position, from the standard size', () => {
    const target = zoomTarget(
      input({
        inner: { w: 1119, h: 875 },
        position: { x: 100, y: 25 },
        lastStandard: { w: 1119, h: 875 },
        userFrame: { x: 100, y: 80, w: 1200, h: 760 }
      })
    );

    expect(target.size).toEqual({ w: 1200, h: 760 });
    expect(target.position).toEqual({ x: 100, y: 80 });
    expect(target.userFrame).toBeNull();
    // Moved down first, the tall window would hang below the screen.
    expect(target.moveFirst).toBe(false);
  });

  it('counts a size within 1 px of the last standard size as the standard state', () => {
    const target = zoomTarget(
      input({
        inner: { w: 1120, h: 759 },
        lastStandard: { w: 1119, h: 760 },
        userFrame: { x: 100, y: 80, w: 900, h: 600 }
      })
    );

    expect(target.size).toEqual({ w: 900, h: 600 });
    expect(target).not.toHaveProperty('position');
  });

  it('zooms out again once the window left the standard size', () => {
    const target = zoomTarget(
      input({
        inner: { w: 1000, h: 700 },
        lastStandard: { w: 1119, h: 760 },
        userFrame: { x: 10, y: 30, w: 900, h: 600 }
      })
    );

    expect(target.size).toEqual({ w: 1119, h: 760 });
    expect(target.userFrame).toEqual({ x: 100, y: 80, w: 1000, h: 700 });
  });

  it('goes to the standard size when no user frame is saved, even at that size', () => {
    const target = zoomTarget(input({ inner: { w: 1119, h: 760 }, lastStandard: { w: 1119, h: 760 } }));

    expect(target.size).toEqual({ w: 1119, h: 760 });
    expect(target.userFrame).toEqual({ x: 100, y: 80, w: 1119, h: 760 });
  });

  it('never goes below the minimum size', () => {
    expect(zoomTarget(input({ ideal: { w: 818, h: 400 } })).size).toEqual({ w: 840, h: 560 });
  });

  it('clamps to the work area and moves up as little as the height needs', () => {
    const target = zoomTarget(input({ ideal: { w: 1119, h: 2000 } }));

    expect(target.size).toEqual({ w: 1119, h: 875 });
    expect(target.position).toEqual({ x: 100, y: 25 });
    expect(target.moveFirst).toBe(true);
  });

  it('shifts left when the standard frame would cross the right edge', () => {
    const target = zoomTarget(input({ position: { x: 600, y: 80 } }));

    expect(target.position).toEqual({ x: 1440 - 1119, y: 80 });
  });

  it('shifts up when the standard frame would cross the bottom edge', () => {
    const target = zoomTarget(input({ position: { x: 100, y: 300 }, ideal: { w: 1119, h: 800 } }));

    expect(target.size).toEqual({ w: 1119, h: 800 });
    expect(target.position).toEqual({ x: 100, y: 25 + 875 - 800 });
  });

  it('keeps the title bar on a screen smaller than the minimum size', () => {
    const target = zoomTarget(input({ workArea: { x: 0, y: 25, w: 800, h: 500 }, ideal: { w: 1119, h: 900 } }));

    expect(target.size).toEqual({ w: 840, h: 560 });
    expect(target.position).toEqual({ x: 0, y: 25 });
  });

  it('brings a window that hangs off the left edge back on the screen', () => {
    expect(zoomTarget(input({ position: { x: -300, y: 80 } })).position).toEqual({ x: 0, y: 80 });
  });

  it('measures the work area on a second monitor from its own origin', () => {
    const target = zoomTarget(
      input({
        position: { x: 1500, y: 100 },
        workArea: { x: 1440, y: 0, w: 1920, h: 1080 },
        ideal: { w: 1119, h: 1200 }
      })
    );

    expect(target.size).toEqual({ w: 1119, h: 1080 });
    expect(target.position).toEqual({ x: 1500, y: 0 });
  });

  it('neither clamps nor moves without a known work area', () => {
    const target = zoomTarget(input({ workArea: null, ideal: { w: 1119, h: 3000 }, position: { x: 5000, y: 80 } }));

    expect(target.size).toEqual({ w: 1119, h: 3000 });
    expect(target).not.toHaveProperty('position');
  });

  it('ignores the half pixels of a scaled position', () => {
    const target = zoomTarget(input({ position: { x: 100.5, y: 79.5 } }));

    expect(target).not.toHaveProperty('position');
  });
});
