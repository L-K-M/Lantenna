// Owner: unit E (spec 8.4). Spec: 3.2, 4.2 (Page key handling).
//
// SCAFFOLD STUB: installs nothing.
// Final contract: page-handled keys, both platforms: Command-C (copy the
// IP) and Command-Delete (Hide Host / Show Host) while the list or the
// icon grid has the keyboard, with preventDefault; every other command
// key is left to the native menu (macOS) or the Osmium menu bar (Linux).
// Returns a disposer.

export function installPageKeys(): () => void {
  return () => {};
}
