export const ssr = false;

/**
 * `vite dev --mode mock` (spec 8.6): install the mock Tauri backend
 * (unit G) before the page mounts. In any other mode the condition is
 * statically false and the import is dropped from the bundle. A load
 * function, not top-level code, because SvelteKit's dev server imports
 * this module in Node to read `ssr`.
 */
export async function load(): Promise<void> {
  if (import.meta.env.MODE === 'mock') await import('$lib/dev/mockBackend');
}
