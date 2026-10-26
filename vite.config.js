import { defineConfig } from 'vite';
import { sveltekit } from '@sveltejs/kit/vite';
import bundledModules from './scripts/bundled-modules.mjs';

const host = process.env.TAURI_DEV_HOST;

// Minifying strips license comments; every chunk points to the notices file
// that `npm run build` writes next to it (scripts/third-party-notices.mjs).
const banner =
  '/*! Bundled third-party code keeps its own licenses: see Third-Party-Notices.txt at the site or app root. */';
// Emit fonts as files, never data: URIs, so the notices check can attribute them.
const keepFontFiles = (/** @type {string} */ file) =>
  /\.(?:woff2?|ttf|otf|eot)$/i.test(file) ? false : undefined;

export default defineConfig(async () => ({
  plugins: [sveltekit(), bundledModules()],
  // Vite 8 (Rolldown) adds postBanner after minification, so it survives.
  build: { assetsInlineLimit: keepFontFiles, rolldownOptions: { output: { postBanner: banner } } },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: 'ws',
          host,
          port: 1421
        }
      : undefined,
    watch: {
      ignored: ['**/src-tauri/**']
    }
  }
}));
