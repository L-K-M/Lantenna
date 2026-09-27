// Owner: integration pass. Spec: 8.2 (+layout.ts row), 8.6.
//
// `vite dev --mode mock` (spec 8.6): install the mock Tauri backend
// (unit G) before any route module loads. SvelteKit's client awaits
// init() before it imports the layout and the page, so the mock seeds
// the user data before scanStore and ui read localStorage at import,
// and no seed reload is needed (scaffold notes, "Mock backend"). In any
// other mode the condition is statically false and the import is
// dropped from the bundle.

export async function init(): Promise<void> {
  if (import.meta.env.MODE === 'mock') await import('$lib/dev/mockBackend');
}
