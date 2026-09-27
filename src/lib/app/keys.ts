// Owner: unit E (spec 8.4). Spec: 3.2, 4.2 (Page key handling).
//
// SCAFFOLD STUB: installs nothing.
// Final contract: page-handled keys while the list or the icon grid has
// the keyboard, with preventDefault: Command-Delete (Hide Host / Show
// Host; Control-Backspace on Linux) on both platforms, and Command-C
// (copy the IP) on macOS only. On Linux, Control-C belongs to the Osmium
// menu bar's Edit > Copy (edit.copy acts as edit.copyIp in list or icon
// context), which also flashes the Edit title; a second handler here
// would copy twice or keep the bar from seeing the key. Every other
// command key is left to the native menu (macOS) or the Osmium menu bar
// (Linux). Returns a disposer.

export function installPageKeys(): () => void {
  return () => {};
}
