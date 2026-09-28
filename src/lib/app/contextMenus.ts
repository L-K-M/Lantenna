// Owner: unit E (spec 8.4). Spec: 4.4, 3.3.
//
// The contextual menus of both views, drawn by Osmium's showContextMenu
// (Mac OS 8.0's placement, tracking and look): one on a host, one on
// empty list or grid space. Help comes first, every item is also in the
// menu bar, keys are not drawn, and each item runs its command through
// run(), which re-checks it. Osmium closes an open menu when an alert
// comes up and opens none under one.
//
// The views call openHostMenu / openViewMenu while handling the press
// (a contextmenu event), so a press-drag-release chooses; keyboard-opened
// menus pass the selected row's Name label or tile as `at`.
// installContextMenuGuard() keeps the browser's own menu away everywhere
// else, text fields included (3.3; fixes BUG-13). closeContextMenu() ends
// an open menu before a native menu command runs (see nativeMenu.ts).
// installControlClick() makes Control-click a menu request on Linux.
// keyMenuWait() recognizes the contextmenu event that may follow the
// menu key, whose menu a view has already opened.

import { get } from 'svelte/store';
import { showContextMenu, type OsmiumContextMenu } from 'osmium-ui';
import { scanStore } from '$lib/util/scanStore';
import { commandContext, hostMenuSpec, osmiumMenuEntries, rowName, viewMenuSpec } from './commands';
import { platform } from './platform';

/** The last menu opened here; its close() does nothing once it's closed. */
let shown: OsmiumContextMenu | null = null;

/** Select `ip` (Control-click selects, as in the Finder), then show the
 * host menu for it at client point `at`. */
export function openHostMenu(ip: string, at: { x: number; y: number }): void {
  if (get(scanStore).selectedHostIp !== ip) scanStore.setSelectedHost(ip);

  const ctx = get(commandContext);
  // listName would say "Unknown" for a host with no name.
  const label = ctx.model.selected ? rowName(ctx.model.selected) : ip;
  shown = showContextMenu(at, osmiumMenuEntries(hostMenuSpec(ctx), ctx, 'contextual'), { label });
}

/** The menu for empty space in the list or the icon grid. */
export function openViewMenu(at: { x: number; y: number }): void {
  const ctx = get(commandContext);
  shown = showContextMenu(at, osmiumMenuEntries(viewMenuSpec(ctx), ctx, 'contextual'), { label: 'Hosts' });
}

/** Close the open contextual menu, if any, without choosing. */
export function closeContextMenu(): void {
  shown?.close();
  shown = null;
}

/**
 * Cancel the browser's contextual menu for every contextmenu event that
 * reaches the window. Registered in the bubble phase, last: the views'
 * handlers (and Osmium's list, which ignores an event already
 * default-prevented) see the event first. Returns the disposer.
 */
export function installContextMenuGuard(): () => void {
  const guard = (e: MouseEvent) => e.preventDefault();
  window.addEventListener('contextmenu', guard);
  return () => window.removeEventListener('contextmenu', guard);
}

/** A contextmenu event this soon after the menu key or Shift-F10, with
 * no press between, is that key's. */
const KEY_MENU_MS = 500;

/** keyMenuWait's answer to a view. */
export interface KeyMenuWait {
  /** The view opened the menu from the menu key or Shift-F10. */
  keyPressed(): void;
  /** A pointer press: the contextmenu event of a right-click or
   * Control-click that follows is not the key's. */
  pressed(): void;
  /** For a contextmenu event: whether it is the key's own (Chromium
   * sends one, WebKit none), to be dropped. True once per key. */
  takeKeyEvent(): boolean;
}

/**
 * The views open the menu from the menu key itself, as WebKit
 * (WKWebView, WebKitGTK) sends no contextmenu event for it; this tells
 * them which contextmenu event is the key's, so the menu opens once.
 */
export function keyMenuWait(): KeyMenuWait {
  let keyAt = -Infinity;

  return {
    keyPressed() {
      keyAt = performance.now();
    },
    pressed() {
      keyAt = -Infinity;
    },
    takeKeyEvent() {
      if (performance.now() - keyAt >= KEY_MENU_MS) return false;
      keyAt = -Infinity;
      return true;
    }
  };
}

/** A system contextmenu event this soon after one made from a
 * Control-click, with no press between them, is for the same press: the
 * menu is already open. */
const CONTROL_CLICK_MS = 500;

/**
 * Control-click opens the contextual menus on both platforms (3.3, 4.4),
 * but only macOS sends a contextmenu event for it: GTK (WebKitGTK, and
 * Chromium on Linux) sends none, and Osmium's list and the icon grid
 * leave a Control-press to the contextual menu, so it did nothing. On
 * Linux, a primary press with Control held on `area` (limited to
 * elements matching `within`) becomes the contextmenu event a
 * right-click sends, at the same point, which the views already answer.
 * The press's own focus change is `keyboard`'s focus, as a right-click
 * focuses the view. Returns the disposer (nothing to do on macOS).
 */
export function installControlClick(area: HTMLElement, keyboard: HTMLElement, within: string): () => void {
  if (platform !== 'linux') return () => {};

  /** When a menu request was made for the press still going on. */
  let madeAt = -Infinity;
  const onMouseDown = (e: MouseEvent) => {
    madeAt = -Infinity;
    if (e.button !== 0 || !e.ctrlKey || e.defaultPrevented) return;
    const target = e.target;
    if (!(target instanceof Element) || !target.closest(within)) return;

    e.preventDefault();
    keyboard.focus({ preventScroll: true });
    madeAt = performance.now();
    target.dispatchEvent(
      new MouseEvent('contextmenu', {
        bubbles: true,
        cancelable: true,
        composed: true,
        view: window,
        clientX: e.clientX,
        clientY: e.clientY,
        screenX: e.screenX,
        screenY: e.screenY,
        ctrlKey: true,
        buttons: e.buttons
      })
    );
  };
  // Should the system send one after all, for the same press (no other
  // press came since, a right-click's included), it is dropped.
  const dropSystemEvent = (e: MouseEvent) => {
    if (!e.isTrusted || performance.now() - madeAt >= CONTROL_CLICK_MS) return;
    madeAt = -Infinity;
    e.preventDefault();
    e.stopImmediatePropagation();
  };

  area.addEventListener('mousedown', onMouseDown);
  area.addEventListener('contextmenu', dropSystemEvent, true);
  return () => {
    area.removeEventListener('mousedown', onMouseDown);
    area.removeEventListener('contextmenu', dropSystemEvent, true);
  };
}
