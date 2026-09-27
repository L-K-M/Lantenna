// Owner: unit E (spec 8.4). Spec: 4.2 (macOS native menu bar and Sync).
//
// SCAFFOLD STUB: installs nothing; Tauri's default macOS menu stays.
// Final contract: builds the Mac OS 8-structured menu bar with
// @tauri-apps/api/menu, sets it as the app menu (Help as the NSApp help
// menu), keeps it in sync with commandContext once per animation frame,
// and returns a disposer. Called by +page.svelte on macOS only.

export function installNativeMenu(): () => void {
  return () => {};
}
