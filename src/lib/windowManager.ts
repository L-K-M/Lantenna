// Owner: unit A (spec 8.4). Spec: 2.10 (window ops), 8.2.
//
// SCAFFOLD: dragWindow and winClose work, and subscribeActivity is
// unchanged from before the port. winShade, winZoom and winGrow are
// ignored, and trackGrow / watchResize install nothing.
// Final contract: apply(op) carries out Osmium's window ops on the Tauri
// window as table 2.10 says (the collapse box's shade and min size, the
// standard-size zoom, the grow box: Linux startResizeDragging, macOS a
// setSize loop fed by trackGrow); watchResize keeps the shade
// bookkeeping right when the OS resizes the window.

import { getCurrentWindow, LogicalSize, type Window } from '@tauri-apps/api/window';
import { invoke } from '@tauri-apps/api/core';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type { WindowOp } from 'osmium-ui';

// Must match ACTIVITY_CHANGED in src-tauri/src/window_activity.rs; nothing
// checks this at build time.
const ACTIVITY_CHANGED = 'window-activity-changed';

function reportFailure(what: string) {
  return (error: unknown) => console.error(`Failed to ${what}:`, error);
}

export class WindowManager {
  private currentWindow: Window | null = null;

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
   * Carry out a window op from Osmium's hostWindow (its `post`). Called
   * synchronously from the pointer event that caused it: startDragging
   * must be invoked before anything is awaited, or the OS drag misses
   * the press.
   */
  apply(op: WindowOp): void {
    switch (op.op) {
      case 'dragWindow':
        this.appWindow.startDragging().catch(reportFailure('drag the window'));
        return;
      case 'winClose':
        this.appWindow.close().catch(reportFailure('close the window'));
        return;
      case 'winShade':
      case 'winZoom':
      case 'winGrow':
        // Unit A (spec 2.10).
        return;
    }
  }

  /**
   * macOS grow box: follow presses on `frame`'s .osm-grow so a later
   * winGrow can resize the window from the press (tao can't start a
   * resize drag on macOS). Returns the disposer.
   */
  trackGrow(frame: HTMLElement): () => void {
    return () => {};
  }

  /** Keep the shade bookkeeping right when the OS resizes the window.
   * Returns the disposer. */
  watchResize(): () => void {
    return () => {};
  }

  async close(): Promise<void> {
    await this.appWindow.close();
  }

  async setSize(width: number, height: number): Promise<void> {
    await this.appWindow.setSize(new LogicalSize(width, height));
  }
}

/** The one window's manager, shared by the page (hostWindow's post) and
 * the commands (View > Zoom Window). */
export const windowManager = new WindowManager();
