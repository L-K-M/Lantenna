// Types for the vendored bundled-modules.mjs. With them, svelte-check
// (checkJs) reads this declaration instead of type-checking the vendored copy.
import type { Plugin } from 'vite';

export default function bundledModules(options?: { dir?: string }): Plugin;
