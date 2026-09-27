// Owner: unit F (spec 8.4). Spec: 1.25 (3.1), 2.5, 2.6, 2.8, 6.
//
// The sprites are checked through what Osmium registers (the SVG data
// URIs behind --osm-sprite-lan-*), so the grids stay private.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type * as OsmiumModule from 'osmium-ui';
import type * as SpritesModule from './sprites';

const KINDS = [
  'camera',
  'iot',
  'kvm',
  'media',
  'mobile',
  'pc-generic',
  'pc-linux',
  'pc-mac',
  'pc-windows',
  'printer',
  'router',
  'server'
] as const;

/** Every registered name and its size in pixels. */
const SIZES: Readonly<Record<string, readonly [number, number]>> = {
  ...Object.fromEntries(KINDS.map((k) => [`lan-${k}`, [16, 16] as const])),
  'lan-antenna': [16, 16],
  'lan-star-off': [11, 11],
  'lan-star-on': [11, 11],
  'lan-star-header': [11, 11],
  'lan-star-badge': [9, 9]
};
const FOLLOWING = ['lan-star-on', 'lan-star-badge'];

let S: typeof SpritesModule;
let O: typeof OsmiumModule;

beforeEach(async () => {
  // Fresh modules: registerAppSprites registers once per page, and
  // Osmium keeps the current accent in module state.
  vi.resetModules();
  document.documentElement.removeAttribute('style');
  document.head.innerHTML = '';
  O = await import('osmium-ui');
  S = await import('./sprites');
});

/** The SVG behind a sprite: inline on <html> when it follows the
 * accent, else in the <style> registerSprites added. */
function svgOf(name: string): string {
  const inline = document.documentElement.style.getPropertyValue(`--osm-sprite-${name}`);
  const css = inline || (document.head.textContent ?? '');
  const match = new RegExp(`(?:^|--osm-sprite-${name}: )url\\("data:image/svg\\+xml,([^"]*)"\\)`).exec(css);
  if (!match) throw new Error(`${name} is not registered`);
  return decodeURIComponent(match[1]!);
}

function sizeOf(svg: string): [number, number] {
  const m = /<svg [^>]*width="(\d+)" height="(\d+)"/.exec(svg);
  if (!m) throw new Error('no size');
  return [Number(m[1]), Number(m[2])];
}

/** One run of pixels, as Osmium draws each subpath. */
const RUN = /M(\d+) (\d+)h(\d+)v1H\d+z/g;

/** The sprite back as a grid of lowercase #rrggbb colors (null:
 * transparent), from the one-run-per-subpath paths Osmium draws. Throws
 * on any path, fill or subpath it cannot read, so a change in Osmium's
 * encoding or a color in another notation fails the tests instead of
 * leaving pixels out of them. */
function gridOf(svg: string): (string | null)[][] {
  const [w, h] = sizeOf(svg);
  const grid = Array.from({ length: h }, () => Array<string | null>(w).fill(null));
  const paths = [...svg.matchAll(/<path fill="([^"]*)" d="([^"]*)"\/>/g)];
  if (paths.length !== svg.split('<path').length - 1) throw new Error(`unreadable <path> in ${svg}`);
  for (const [, fill, d] of paths) {
    if (!/^#[0-9a-f]{6}$/i.test(fill!)) throw new Error(`fill "${fill}" is not #rrggbb`);
    if (d!.replace(RUN, '') !== '') throw new Error(`path "${d}" is not one run per subpath`);
    for (const [, x, y, n] of d!.matchAll(RUN)) {
      for (let i = 0; i < Number(n); i++) grid[Number(y)]![Number(x) + i] = fill!.toLowerCase();
    }
  }
  return grid;
}

/** The Mac OS 8 system palette ('clut' 8): the 6 x 6 x 6 cube, and the
 * red, green, blue and gray ramps between its levels. */
function inSystemPalette(hex: string): boolean {
  const cube = ['00', '33', '66', '99', 'cc', 'ff'];
  const ramp = ['11', '22', '44', '55', '77', '88', 'aa', 'bb', 'dd', 'ee'];
  const [r, g, b] = [hex.slice(1, 3), hex.slice(3, 5), hex.slice(5, 7)];
  if (cube.includes(r) && cube.includes(g) && cube.includes(b)) return true;
  if (!ramp.includes(r) && !ramp.includes(g) && !ramp.includes(b)) return false;
  const level = [r, g, b].find((c) => c !== '00')!;
  const grayRamp = r === g && g === b;
  const oneChannel = [r, g, b].filter((c) => c !== '00').length === 1;
  return ramp.includes(level) && (grayRamp || oneChannel);
}

describe('sprite names', () => {
  it('names a CSS image for every host kind, star and the antenna', () => {
    expect(Object.keys(S.SMALL_ICON).sort()).toEqual([...KINDS].sort());
    for (const kind of KINDS) expect(S.SMALL_ICON[kind]).toBe(`var(--osm-sprite-lan-${kind})`);
    expect(S.STAR).toEqual({
      off: 'var(--osm-sprite-lan-star-off)',
      on: 'var(--osm-sprite-lan-star-on)',
      header: 'var(--osm-sprite-lan-star-header)',
      badge: 'var(--osm-sprite-lan-star-badge)'
    });
    expect(S.ANTENNA).toBe('lan-antenna');
  });

  it('registers nothing until asked', () => {
    expect(document.head.textContent).not.toContain('--osm-sprite-lan-');
  });
});

describe('registerAppSprites', () => {
  it('registers every sprite at its size without throwing', () => {
    expect(() => S.registerAppSprites()).not.toThrow();
    for (const [name, size] of Object.entries(SIZES)) expect(sizeOf(svgOf(name)), name).toEqual(size);
  });

  it('registers only once however often it is called', () => {
    S.registerAppSprites();
    S.registerAppSprites();
    expect(document.head.querySelectorAll('style[data-osmium-sprites]')).toHaveLength(1);
  });

  it('draws the fixed sprites in the Mac OS 8 system palette', () => {
    S.registerAppSprites();
    for (const name of Object.keys(SIZES).filter((n) => !FOLLOWING.includes(n))) {
      const colors = new Set(gridOf(svgOf(name)).flat().filter((c): c is string => c !== null));
      expect(colors.size, name).toBeGreaterThan(0);
      for (const c of colors) expect(inSystemPalette(c), `${name}: ${c}`).toBe(true);
    }
  });

  it('outlines every host icon in black', () => {
    // Every opaque pixel on the silhouette's edge is black, or the 44
    // gray that rounds a corner (Mac OS 8's Keyboard icon does the
    // same).
    S.registerAppSprites();
    for (const kind of KINDS) {
      const grid = gridOf(svgOf(`lan-${kind}`));
      const clear = (x: number, y: number) => grid[y]?.[x] == null;
      grid.forEach((row, y) =>
        row.forEach((c, x) => {
          if (c === null) return;
          if (!(clear(x - 1, y) || clear(x + 1, y) || clear(x, y - 1) || clear(x, y + 1))) return;
          expect(['#000000', '#444444'], `${kind} at ${x},${y}`).toContain(c);
        })
      );
    }
  });

  it('draws every star symmetric about its middle column', () => {
    // Lighting may differ left to right; the silhouette and the outline
    // (black, or the off star's 88 gray) may not.
    S.registerAppSprites();
    for (const name of ['lan-star-off', 'lan-star-on', 'lan-star-header', 'lan-star-badge']) {
      const shape = gridOf(svgOf(name)).map((row) =>
        row.map((c) => (c === null ? '.' : c === '#000000' || c === '#888888' ? '0' : 'f')).join('')
      );
      expect(shape.map((r) => [...r].reverse().join('')), name).toEqual(shape);
    }
  });

  it('keeps the host icons, the off and header stars and the antenna when the accent changes', () => {
    S.registerAppSprites();
    const fixed = Object.keys(SIZES).filter((n) => !FOLLOWING.includes(n));
    const before = fixed.map(svgOf);
    O.setAppearance({ accent: { release: '8.0', name: 'Gold' } });
    expect(fixed.map(svgOf)).toEqual(before);
    for (const name of fixed)
      expect(document.documentElement.style.getPropertyValue(`--osm-sprite-${name}`)).toBe('');
  });

  it('draws the filled star and the badge in the accent', () => {
    S.registerAppSprites();
    // Lavender, the default: its A1 to A3 (q p m).
    for (const name of FOLLOWING) {
      const svg = svgOf(name);
      for (const c of ['#ccccff', '#9999ff', '#6666cc']) expect(svg, name).toContain(`fill="${c}"`);
    }
    O.setAppearance({ accent: { release: '8.0', name: 'Gold' } });
    for (const name of FOLLOWING) {
      const svg = svgOf(name);
      // Mac OS 8.0 Gold: A1 ffff00, A2 cccc00, A3 999900.
      for (const c of ['#ffff00', '#cccc00', '#999900']) expect(svg, name).toContain(`fill="${c}"`);
      expect(svg, name).not.toContain('fill="#9999ff"');
      expect(svg, name).toContain('fill="#000000"');
    }
  });
});
