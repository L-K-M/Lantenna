import { defineConfig } from 'vite';
import { sveltekit } from '@sveltejs/kit/vite';

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;

export default defineConfig(async () => ({
  plugins: [sveltekit()],
  clearScreen: false,
  resolve: {
    alias: [
      {
        find: '@lkmc/system7-ui/styles.css',
        replacement: new URL('../system7-ui/src/styles/system7.css', import.meta.url).pathname
      },
      {
        find: '@lkmc/system7-ui',
        replacement: new URL('../system7-ui/src/index.ts', import.meta.url).pathname
      }
    ]
  },
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
    },
    fs: {
      allow: ['..']
    }
  }
}));
