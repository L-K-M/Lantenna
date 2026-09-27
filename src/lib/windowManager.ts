// Owner: unit A (spec 8.4). Spec: 2.10 (window ops), 8.2.
//
// Carries out Osmium's window ops (hostWindow's `post`) on the one Tauri
// window, and reports whether the window draws as active. The page draws
// the whole window; the native window only moves and changes size:
//
//   dragWindow    startDragging, from within the press
//   winClose      close (it's the only window, so Lantenna quits)
//   winShade      fold to the 23 px title bar with the minimum size
//                 lifted, and back
//   winZoom       toggle the user and standard frames (app/zoom.ts)
//   winGrow       Linux: the OS resize drag; macOS, where tao can't
//                 start one: a setSize loop fed by trackGrow
//
// After an OS move or resize, WebKitGTK misses the release; the press
// that follows is passed on as a pointerdown (recoverNextPress).
//
// State: this class owns the native side's bookkeeping, the height a
// folded window unfolds to and zoom's user frame. It follows the ops it
// is given, so the page's startup winShade { on: false } puts a folded
// window back. Size changes run one at a time in op order, because
// Tauri answers each call when it has queued the change, not when the
// window has it; a queued task reads the window's size when it runs.

import {
  currentMonitor,
  getCurrentWindow,
  LogicalPosition,
  LogicalSize,
  type Monitor,
  type Window
} from '@tauri-apps/api/window';
import { invoke } from '@tauri-apps/api/core';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type { WindowOp } from 'osmium-ui';
import { get } from 'svelte/store';
import { MIN_H, MIN_W, SHADED_H } from '$lib/app/layout';
import { isMac } from '$lib/app/platform';
import { ui } from '$lib/app/ui';
import { activeView } from '$lib/app/views';
import { idealSize, zoomTarget, type Frame, type Size } from '$lib/app/zoom';

// Must match ACTIVITY_CHANGED in src-tauri/src/window_activity.rs; nothing
// checks this at build time.
const ACTIVITY_CHANGED = 'window-activity-changed';

/** hostWindow's SHADED_MAX_H: a viewport this tall or less is a folded
 * window; one growing past it has been unfolded. */
const SHADED_MAX_H = 60;

/** How long an unfold waits for the window to grow before it restores
 * the minimum size anyway. */
const UNFOLD_WAIT_MS = 1000;

/** PointerEvent.button for the main (left) button. */
const MAIN_BUTTON = 0;

/** What WebKit tells the page about the window's screen; availTop is
 * non-standard. */
type WebKitScreen = Screen & { availTop?: number };

/** A press on the grow box, as trackGrow saw it before Osmium posted
 * winGrow. */
interface GrowPress {
  grip: HTMLElement;
  pointerId: number;
  screenX: number;
  screenY: number;
  size: Size;
}

function reportFailure(what: string) {
  return (error: unknown) => console.error(`Failed to ${what}:`, error);
}

/** The window's logical inner size: the page fills it. */
function viewportSize(): Size {
  return { w: window.innerWidth, h: window.innerHeight };
}

/** Resolves once the viewport is taller than a folded window, that is
 * once a requested unfold has reached the window, or after `ms`. */
function unfolded(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const done = () => {
      clearTimeout(timer);
      window.removeEventListener('resize', check);
      resolve();
    };
    const check = () => {
      if (window.innerHeight > SHADED_MAX_H) done();
    };
    const timer = setTimeout(done, ms);
    window.addEventListener('resize', check);
  });
}

/** The pointerdown for a press WebKit reported as `move` (see
 * WindowManager.recoverNextPress). */
function pressLike(move: PointerEvent): PointerEventInit {
  return {
    bubbles: true,
    cancelable: true,
    composed: true,
    view: window,
    pointerId: move.pointerId,
    pointerType: move.pointerType,
    isPrimary: move.isPrimary,
    width: move.width,
    height: move.height,
    pressure: move.pressure,
    button: move.button,
    buttons: move.buttons,
    screenX: move.screenX,
    screenY: move.screenY,
    clientX: move.clientX,
    clientY: move.clientY,
    ctrlKey: move.ctrlKey,
    shiftKey: move.shiftKey,
    altKey: move.altKey,
    metaKey: move.metaKey
  };
}

/** Holds back the mousedown that WebKit dispatches right after, and in
 * the same task as, the pointer event of the same press. */
function holdBackMouseDown(): void {
  const hold = (e: MouseEvent) => {
    e.preventDefault();
    e.stopImmediatePropagation();
  };
  window.addEventListener('mousedown', hold, { capture: true, once: true });
  setTimeout(() => window.removeEventListener('mousedown', hold, { capture: true }));
}

/**
 * The monitor's work area in logical pixels.
 *
 * macOS: Tauri 2.10 reports the visible frame's size (the screen without
 * the menu bar and Dock) at the screen's top edge; tauri-runtime-wry's
 * src/monitor/macos.rs corrects only x. That rect starts under the menu
 * bar, so it moves down by WebKit's screen.availTop: the visible frame's
 * top measured from the top of the window's screen (WebKit's
 * PlatformScreenMac.mm). That is used only while WebKit describes the
 * same visible frame (the same height). Otherwise the top moves down by
 * all the height the menu bar and Dock take and the bottom stays, which
 * is inside the real work area wherever the Dock is.
 */
function logicalWorkArea(monitor: Monitor, webKitScreen: WebKitScreen): Frame {
  const { position, size } = monitor.workArea;
  const scale = monitor.scaleFactor;
  const area = { x: position.x / scale, y: position.y / scale, w: size.width / scale, h: size.height / scale };
  if (!isMac) return area;

  const lost = monitor.size.height / scale - area.h;
  const menuBarH = webKitScreen.availTop;
  const sameFrame = Math.abs(webKitScreen.availHeight - area.h) <= 1;
  if (menuBarH !== undefined && sameFrame && menuBarH >= 0 && menuBarH <= lost) {
    return { ...area, y: area.y + menuBarH };
  }

  return { ...area, y: area.y + lost, h: area.h - lost };
}

export class WindowManager {
  private currentWindow: Window | null = null;
  /** Whether the window is folded, or will be once the queue gets there. */
  private folded = false;
  /** The height a folded window unfolds to, read when the fold ran. */
  private unfoldedH = MIN_H;
  /** Zoom's user frame and the standard size it last went to. */
  private userFrame: Frame | null = null;
  private lastStandard: Size | null = null;
  /** Size changes in op order (see the header). */
  private queue: Promise<void> = Promise.resolve();
  /** The grow-box press trackGrow saw last (macOS). */
  private growPress: GrowPress | null = null;
  /** Ends the macOS grow loop in progress, if one is. */
  private endGrow: (() => void) | null = null;
  /** Stops waiting for a press lost to a native move or resize. */
  private stopPressRecovery: (() => void) | null = null;

  /**
   * The Tauri window, looked up on first use rather than at construction,
   * so importing the shared instance never touches Tauri's internals (a
   * mock backend may install them after the page's modules load).
   */
  private get appWindow(): Window {
    this.currentWindow ??= getCurrentWindow();
    return this.currentWindow;
  }

  /**
   * Reports whether the window draws as active. On Linux that is GTK's
   * decoration state rather than keyboard focus, so dragging the custom title
   * bar no longer greys it out mid-drag.
   */
  subscribeActivity(onChange: (active: boolean) => void): UnlistenFn {
    let disposed = false;
    let receivedEvent = false;
    let unlisten: UnlistenFn | undefined;

    // Listen before reading the startup state; a newer event beats that snapshot.
    void this.appWindow
      .listen<boolean>(ACTIVITY_CHANGED, ({ payload }) => {
        if (disposed) return;

        receivedEvent = true;
        onChange(payload);
      })
      .then(async (stop) => {
        if (disposed) {
          stop();
          return;
        }

        unlisten = stop;

        // An event already told us the current state; skip the round trip.
        if (receivedEvent) return;

        const active = await invoke<boolean>('is_window_active');
        if (!disposed && !receivedEvent) onChange(active);
      })
      .catch((error) => {
        console.error('Failed to track window activity:', error);
      });

    return () => {
      disposed = true;
      unlisten?.();
    };
  }

  /**
   * Carry out a window op from Osmium's hostWindow (its `post`) or a
   * menu command. Called synchronously from the pointer event that
   * caused it: startDragging and startResizeDragging must be invoked
   * before anything is awaited, or the OS misses the press.
   */
  apply(op: WindowOp): void {
    switch (op.op) {
      case 'dragWindow':
        this.appWindow.startDragging().catch(reportFailure('drag the window'));
        this.recoverNextPress();
        return;
      case 'winClose':
        this.appWindow.close().catch(reportFailure('close the window'));
        return;
      case 'winShade':
        if (op.on) this.fold();
        else this.unfold();
        return;
      case 'winZoom':
        // The zoom box does nothing while folded (Osmium doesn't post
        // then); View > Zoom Window reaches here directly.
        if (!this.folded) this.enqueue('zoom the window', () => this.zoom());
        return;
      case 'winGrow':
        this.grow();
        return;
    }
  }

  /**
   * macOS grow box: remember presses on `frame`'s .osm-grow (in the
   * capture phase, before Osmium's own listener posts winGrow), so
   * winGrow resizes the window from that press with a setSize loop; tao
   * can't start a resize drag on macOS. Returns the disposer, which also
   * ends a grow in progress.
   */
  trackGrow(frame: HTMLElement): () => void {
    const onPress = (e: PointerEvent) => {
      const grip = e.target instanceof Element ? e.target.closest<HTMLElement>('.osm-grow') : null;
      if (!grip || e.button !== 0) return;

      this.growPress = {
        grip,
        pointerId: e.pointerId,
        screenX: e.screenX,
        screenY: e.screenY,
        size: viewportSize()
      };
    };
    frame.addEventListener('pointerdown', onPress, true);

    return () => {
      frame.removeEventListener('pointerdown', onPress, true);
      this.growPress = null;
      this.endGrow?.();
    };
  }

  /**
   * Keep the fold's bookkeeping right when the OS resizes the window: a
   * folded window growing past SHADED_MAX_H (a Linux edge resize) is
   * unfolded. hostWindow unfolds the page by the same rule on the same
   * event, without posting; here the saved size goes and the minimum
   * size comes back. Returns the disposer.
   */
  watchResize(): () => void {
    let lastH = window.innerHeight;
    const onResize = () => {
      const h = window.innerHeight;
      if (this.folded && lastH <= SHADED_MAX_H && h > SHADED_MAX_H) {
        this.folded = false;
        this.enqueue('restore the minimum window size', () =>
          this.appWindow.setMinSize(new LogicalSize(MIN_W, MIN_H))
        );
      }
      lastH = h;
    };
    window.addEventListener('resize', onResize);

    return () => window.removeEventListener('resize', onResize);
  }

  private enqueue(what: string, task: () => Promise<void>): void {
    this.queue = this.queue.then(task).catch(reportFailure(what));
  }

  /**
   * Fold to the title bar, top edge pinned. The minimum size goes first,
   * or the window couldn't get this short. The height to unfold to is
   * read when the fold runs: an unfold queued before it may not have
   * reached the window when the op arrives.
   */
  private fold(): void {
    if (this.folded) return;

    this.folded = true;
    this.enqueue('collapse the window', async () => {
      const { w, h } = viewportSize();
      this.unfoldedH = h;
      await this.appWindow.setMinSize(null);
      await this.appWindow.setSize(new LogicalSize(w, SHADED_H));
    });
  }

  /**
   * Unfold to the saved height, at the window's current width. The
   * minimum size comes back only once the window has grown. macOS
   * applies a size change later than the call (tao dispatches it to the
   * main queue) but a minimum-size change at once, and a minimum that
   * came first would grow the window in two visible steps, to the
   * minimum height and then to the saved one.
   */
  private unfold(): void {
    const wasFolded = this.folded;
    this.folded = false;

    this.enqueue('expand the window', async () => {
      let h = this.unfoldedH;

      // Not folded: nothing to do (hostWindow's startup post, usually).
      // Unless the window is folded anyway, as after a page reload, which
      // loses this bookkeeping but not the native fold: then unfold to the
      // minimum height. (A zero viewport isn't laid out yet, not folded.)
      if (!wasFolded) {
        const viewportH = window.innerHeight;
        if (viewportH === 0 || viewportH > SHADED_MAX_H) return;
        h = MIN_H;
      }

      const grown = unfolded(UNFOLD_WAIT_MS);
      try {
        await this.appWindow.setSize(new LogicalSize(window.innerWidth, h));
        await grown;
      } finally {
        await this.appWindow.setMinSize(new LogicalSize(MIN_W, MIN_H));
      }
    });
  }

  private async zoom(): Promise<void> {
    if (this.folded) return;

    const win = this.appWindow;
    const view = get(activeView);
    const inner = viewportSize();
    const ideal = idealSize({
      inner,
      columnsWidth: view ? view.idealColumnsWidth() : null,
      paneShown: get(ui).infoPaneShown,
      extraHeight: view ? view.extraHeight() : 0
    });
    const [scale, outer, monitor] = await Promise.all([
      win.scaleFactor(),
      win.outerPosition(),
      currentMonitor()
    ]);

    const target = zoomTarget({
      inner,
      position: { x: outer.x / scale, y: outer.y / scale },
      workArea: monitor ? logicalWorkArea(monitor, window.screen) : null,
      ideal,
      min: { w: MIN_W, h: MIN_H },
      lastStandard: this.lastStandard,
      userFrame: this.userFrame
    });
    this.userFrame = target.userFrame;
    this.lastStandard = target.standard;

    // Wayland refuses to place windows: then zoom resizes in place.
    const { size, position } = target;
    const move = async () => {
      if (!position) return;
      await win.setPosition(new LogicalPosition(position.x, position.y)).catch(reportFailure('move the window'));
    };
    const resize = () => win.setSize(new LogicalSize(size.w, size.h));

    if (target.moveFirst) {
      await move();
      await resize();
    } else {
      await resize();
      await move();
    }
  }

  /** Linux: the OS resizes the window from the press. macOS: follow the
   * press trackGrow recorded. */
  private grow(): void {
    if (this.folded) return;

    const press = this.growPress;
    this.growPress = null;
    if (!press) {
      this.appWindow.startResizeDragging('SouthEast').catch(reportFailure('resize the window'));
      this.recoverNextPress();
      return;
    }

    this.followGrow(press);
  }

  /**
   * After the OS has taken a press over for a move or resize, pass the
   * next press on as the pointerdown it is.
   *
   * WebKitGTK never sees the release that ends the window manager's
   * move or resize, so it still counts the button as down. It then
   * turns the next press into a pointermove with `button` 0, the
   * Pointer Events rule for a second button pressed during a press
   * (WebKit's PointerCaptureController), not a pointerdown. Osmium's
   * boxes, buttons and title bar act on pointerdown, so that press did
   * nothing; the System 7 UI acted on mousedown and click, which still
   * fire. That pointermove is dispatched as a pointerdown instead, and
   * when its default is prevented, the mousedown WebKit sends next is
   * held back, as after a prevented pointerdown. The release then
   * reaches WebKit and ends the stale press. A pointerdown or pointerup
   * first means no release was lost: nothing to do.
   */
  private recoverNextPress(): void {
    this.stopPressRecovery?.();

    const types = ['pointermove', 'pointerdown', 'pointerup'] as const;
    const onPointer = (e: PointerEvent) => {
      if (e.pointerType !== 'mouse') return;
      if (e.type === 'pointermove' && e.button !== MAIN_BUTTON) return; // a move

      stop();
      if (e.type !== 'pointermove' || !e.target) return;

      e.stopImmediatePropagation();
      const press = new PointerEvent('pointerdown', pressLike(e));
      if (!e.target.dispatchEvent(press)) holdBackMouseDown();
    };
    const stop = () => {
      for (const type of types) window.removeEventListener(type, onPointer, true);
      this.stopPressRecovery = null;
    };

    for (const type of types) window.addEventListener(type, onPointer, true);
    this.stopPressRecovery = stop;
  }

  /**
   * The macOS grow loop: while the button is down, size the window by
   * the pointer's travel from the press, never below the minimum, top-
   * left pinned. One setSize per animation frame, and none while one is
   * on its way; the last size is always sent.
   */
  private followGrow(press: GrowPress): void {
    this.endGrow?.();

    const { grip, pointerId } = press;
    let target = press.size;
    let sent = press.size;
    let sending = false;
    let frame = 0;

    const send = () => {
      frame = 0;
      if (sending || (target.w === sent.w && target.h === sent.h)) return;

      sending = true;
      sent = target;
      this.appWindow
        .setSize(new LogicalSize(sent.w, sent.h))
        .catch(reportFailure('resize the window'))
        .finally(() => {
          sending = false;
          schedule();
        });
    };
    const schedule = () => {
      frame ||= requestAnimationFrame(send);
    };

    const move = (e: PointerEvent) => {
      if (e.pointerId !== pointerId) return;

      // The release may have gone elsewhere; a move without the button
      // ends the grow rather than resizing on hover.
      if ((e.buttons & 1) === 0) {
        stop();
        return;
      }

      target = {
        w: Math.max(MIN_W, press.size.w + Math.round(e.screenX - press.screenX)),
        h: Math.max(MIN_H, press.size.h + Math.round(e.screenY - press.screenY))
      };
      schedule();
    };
    const end = (e: PointerEvent) => {
      if (e.pointerId === pointerId) stop();
    };
    const stop = () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', end);
      window.removeEventListener('pointercancel', end);
      grip.removeEventListener('lostpointercapture', end);
      if (grip.hasPointerCapture(pointerId)) grip.releasePointerCapture(pointerId);
      this.endGrow = null;
    };

    // Capture keeps the moves coming once the pointer leaves the window,
    // which it does whenever the window grows. It fails only for a
    // pointer that is no longer down; the first move then ends the grow.
    try {
      grip.setPointerCapture(pointerId);
    } catch (error) {
      console.warn('Grow box: no pointer capture:', error);
    }
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', end);
    window.addEventListener('pointercancel', end);
    grip.addEventListener('lostpointercapture', end);
    this.endGrow = stop;
  }
}

/** The one window's manager, shared by the page (hostWindow's post) and
 * the commands (View > Zoom Window). */
export const windowManager = new WindowManager();
