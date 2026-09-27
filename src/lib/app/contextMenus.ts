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
// else, text fields included (3.3; fixes BUG-13).

import { get } from 'svelte/store';
import { showContextMenu } from 'osmium-ui';
import { scanStore } from '$lib/util/scanStore';
import { commandContext, hostMenuSpec, osmiumMenuEntries, viewMenuSpec } from './commands';

/** Select `ip` (Control-click selects, as in the Finder), then show the
 * host menu for it at client point `at`. */
export function openHostMenu(ip: string, at: { x: number; y: number }): void {
  if (get(scanStore).selectedHostIp !== ip) scanStore.setSelectedHost(ip);

  const ctx = get(commandContext);
  const label = ctx.model.selected?.listName ?? ip;
  showContextMenu(at, osmiumMenuEntries(hostMenuSpec(ctx), ctx, 'contextual'), { label });
}

/** The menu for empty space in the list or the icon grid. */
export function openViewMenu(at: { x: number; y: number }): void {
  const ctx = get(commandContext);
  showContextMenu(at, osmiumMenuEntries(viewMenuSpec(ctx), ctx, 'contextual'), { label: 'Hosts' });
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
