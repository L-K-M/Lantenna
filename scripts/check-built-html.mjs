// Owner: unit A (spec 8.4). Spec: 8.5 (Build check), 9.1.
//
// Fails the build when build/index.html contains a <style> element.
// Tauri adds a CSP nonce to style-src when the built HTML has one, which
// disables 'unsafe-inline' and breaks the styles Osmium inserts at run
// time (its sprite sheet, list views). Run after `vite build`.
import { readFile } from 'node:fs/promises';

const FILE = new URL('../build/index.html', import.meta.url);

const html = await readFile(FILE, 'utf8');

if (/<style[\s>]/i.test(html)) {
  console.error(
    'build/index.html contains a <style> element. Tauri would add a CSP ' +
      'nonce and break the styles Osmium UI inserts at run time. Move the ' +
      'CSS into a stylesheet.'
  );
  process.exit(1);
}

console.log('build/index.html has no <style> element.');
