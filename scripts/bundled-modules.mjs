// Vite / Rollup / Rolldown plugin that records which modules and assets end
// up in each output file, for third-party-notices.mjs. Bundlers drop license
// comments when minifying; this keeps the module graph so the notices list
// only what really ships.
//
// Works with Vite 6-8 (Rollup or Rolldown) and plain Rollup 4 or Rolldown.
// No dependencies. Copy it into the repo (e.g. scripts/bundled-modules.mjs).
//
//   import bundledModules from './scripts/bundled-modules.mjs';
//   export default defineConfig({
//     plugins: [sveltekit(), bundledModules()],
//     worker: { plugins: () => [bundledModules()] }, // only if the app has workers
//   });
//
// Output: one JSON file per bundle in <root>/node_modules/.cache/bundled-modules/
// (outside the shipped output; node_modules is never committed). The directory
// is cleared once per build process, so records of earlier builds never leak
// in. One build per process: watch mode and repeated build() calls in one
// process keep adding records, so do not generate notices from those.

import fs from 'node:fs';
import path from 'node:path';

// Style modules render no JavaScript, but their CSS ships as an asset.
const STYLE = /\.(?:css|less|sass|scss|styl|stylus|pcss|postcss|sss)$/i;
const STATE = Symbol.for('bundled-modules.state');

export default function bundledModules({ dir = 'node_modules/.cache/bundled-modules' } = {}) {
  // Vite bundles the config file, so every config load gets its own copy of
  // this module. Keep per-process state on globalThis.
  const state = (globalThis[STATE] ??= { cleared: new Set(), counter: 0 });
  let root = process.cwd();
  let worker = false;
  let ssr = false;
  const outDir = () => path.resolve(root, dir);

  return {
    name: 'bundled-modules',
    apply: 'build',
    configResolved(config) {
      root = config.root;
      worker = Boolean(config.isWorker);
      ssr = Boolean(config.build?.ssr);
    },
    buildStart() {
      if (!state.cleared.has(outDir())) {
        fs.rmSync(outDir(), { recursive: true, force: true });
        state.cleared.add(outDir());
      }
    },
    generateBundle(_options, bundle) {
      const environment = this.environment?.name ?? (ssr ? 'ssr' : 'client');
      const outputs = {};
      for (const [fileName, item] of Object.entries(bundle)) {
        if (item.type === 'chunk') {
          const modules = Object.entries(item.modules ?? {})
            .filter(([id, info]) => info.renderedLength > 0 || STYLE.test(id.split('?')[0]))
            .map(([id]) => id);
          if (modules.length) outputs[fileName] = { modules: modules.sort() };
        } else {
          const originals = item.originalFileNames ?? (item.originalFileName ? [item.originalFileName] : []);
          if (originals.length) outputs[fileName] = { assets: [...originals].sort() };
        }
      }
      fs.mkdirSync(outDir(), { recursive: true });
      const file = path.join(outDir(), `${environment}${worker ? '-worker' : ''}-${++state.counter}.json`);
      const record = { environment, worker, root, outputs };
      fs.writeFileSync(file, `${JSON.stringify(record, null, 1)}\n`);
    },
  };
}
