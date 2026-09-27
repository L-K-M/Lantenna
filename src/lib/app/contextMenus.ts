// Owner: unit E (spec 8.4). Spec: 4.4, 3.3.
//
// SCAFFOLD STUB: the menus don't open and the guard installs nothing.
// Osmium's showContextMenu (spec 7.1 O3) is not in the pinned Osmium
// yet; see scaffold-notes.md for the fallback.
// Final contract: openHostMenu / openViewMenu draw the contextual menus
// of 4.4 at a client point (keyboard-opened menus at the selected row's
// Name label or tile); installContextMenuGuard() calls preventDefault on
// every other contextmenu event in the window (3.3) and returns its
// disposer.

export function openHostMenu(ip: string, at: { x: number; y: number }): void {}

export function openViewMenu(at: { x: number; y: number }): void {}

export function installContextMenuGuard(): () => void {
  return () => {};
}
