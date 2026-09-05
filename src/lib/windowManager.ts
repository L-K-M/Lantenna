import { currentMonitor, getCurrentWindow, LogicalSize } from '@tauri-apps/api/window';
import { invoke } from '@tauri-apps/api/core';
import type { UnlistenFn } from '@tauri-apps/api/event';

const ACTIVITY_CHANGED = 'window-activity-changed';

export class WindowManager {
  private static readonly TITLE_BAR_HEIGHT = 36;
  private savedWindowSize: { width: number; height: number } | null = null;
  private isShaded = false;
  private appWindow = getCurrentWindow();

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

  async close(): Promise<void> {
    await this.appWindow.close();
  }

  async setSize(width: number, height: number): Promise<void> {
    await this.appWindow.setSize(new LogicalSize(width, height));
  }

  async resizeHeightBy(deltaHeight: number): Promise<void> {
    if (!Number.isFinite(deltaHeight)) {
      return;
    }

    const [scaleFactor, innerSize, outerSize, outerPosition, monitor] = await Promise.all([
      this.appWindow.scaleFactor(),
      this.appWindow.innerSize(),
      this.appWindow.outerSize(),
      this.appWindow.outerPosition(),
      currentMonitor()
    ]);

    const logicalInnerWidth = innerSize.width / scaleFactor;
    const logicalInnerHeight = innerSize.height / scaleFactor;
    const logicalOuterHeight = outerSize.height / scaleFactor;
    const chromeHeight = Math.max(0, logicalOuterHeight - logicalInnerHeight);

    const requestedInnerHeight = logicalInnerHeight + deltaHeight;
    let maxInnerHeight = Number.POSITIVE_INFINITY;

    if (monitor) {
      const monitorBottomPx = monitor.workArea.position.y + monitor.workArea.size.height;
      const availableOuterHeightPx = monitorBottomPx - outerPosition.y;
      if (availableOuterHeightPx > 0) {
        maxInnerHeight = Math.max(
          WindowManager.TITLE_BAR_HEIGHT,
          availableOuterHeightPx / scaleFactor - chromeHeight
        );
      }
    }

    const targetInnerHeight = Math.max(
      WindowManager.TITLE_BAR_HEIGHT,
      Math.min(requestedInnerHeight, maxInnerHeight)
    );

    if (Math.abs(targetInnerHeight - logicalInnerHeight) < 0.5) {
      return;
    }

    await this.appWindow.setSize(new LogicalSize(logicalInnerWidth, targetInnerHeight));
  }

  async toggleShade(): Promise<boolean> {
    const scaleFactor = await this.appWindow.scaleFactor();

    if (!this.isShaded) {
      const size = await this.appWindow.innerSize();
      const logicalWidth = size.width / scaleFactor;
      const logicalHeight = size.height / scaleFactor;
      this.savedWindowSize = { width: logicalWidth, height: logicalHeight };
      await this.appWindow.setSize(new LogicalSize(logicalWidth, WindowManager.TITLE_BAR_HEIGHT));
      this.isShaded = true;
    } else {
      if (this.savedWindowSize) {
        await this.appWindow.setSize(new LogicalSize(this.savedWindowSize.width, this.savedWindowSize.height));
      }
      this.isShaded = false;
    }

    return this.isShaded;
  }

  async startDragging(): Promise<void> {
    await this.appWindow.startDragging();
  }
}
