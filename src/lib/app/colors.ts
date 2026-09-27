// Owner: unit A (spec 8.4). Spec: 6.
//
// Lantenna's accent and highlight colors (spec 6). On macOS they follow
// the system accent the Mac OS 8 way: the nearest of Apple's 8.5
// variations, and the 8.5 highlight that goes with it. Linux reports no
// accent, so the page keeps Osmium's default, Lavender with Purple
// (Mac OS 8.5's "Mac OS Default" theme). The page calls
// applySystemColors at mount and on every activation, the modern
// stand-in for Appearance 1.1's appearance-changed event.
//
// The backend's highlight_color (a dark selected-row blue) and both text
// colors are ignored: Osmium keeps black text on the highlight, as Mac
// OS did.

import {
  getAppearance,
  nearestAccent,
  setAppearance,
  type AccentChoice,
  type Appearance,
  type Highlight85,
  type HighlightChoice,
  type Variation85
} from 'osmium-ui';
import { TauriService } from '$lib/tauri';
import type { SystemColors } from '$lib/types';

/** The 8.5 highlight that goes with each variation (spec 6). */
export const HIGHLIGHT_FOR_VARIATION: Readonly<Record<Variation85, Highlight85>> = {
  Azul: 'Azul',
  Bondi: 'Bondi',
  Copper: 'Poppy',
  Crimson: 'Plum',
  Emerald: 'Green',
  'French Blue': 'Azul',
  Gold: 'Yellow',
  Ivy: 'Green',
  Lavender: 'Purple',
  Magenta: 'Purple',
  Nutmeg: 'Poppy',
  Pistachio: 'Green',
  Plum: 'Plum',
  Poppy: 'Poppy',
  Rose: 'Plum',
  Sapphire: 'Azul',
  Silver: 'Gray',
  Sunny: 'Yellow',
  Teal: 'Teal',
  Turquoise: 'Bondi'
};

/** Osmium's README: white menu text reads about 1.9:1 on Pistachio and
 * 2.2:1 on Sunny, so those two give way to the nearest darker 8.5
 * variations. */
const READABLE_VARIATION: Readonly<Partial<Record<Variation85, Variation85>>> = {
  Pistachio: 'Emerald',
  Sunny: 'Gold'
};

/**
 * The appearance for the host's colors: null when the host reports no
 * accent (Linux) or there are no colors (the read failed). Throws a
 * RangeError, as nearestAccent does, when the accent isn't #rgb or
 * #rrggbb.
 */
export function appearanceFor(c: SystemColors | null): Appearance | null {
  const accent = c?.accent_color;
  if (!accent) return null;

  const nearest = nearestAccent(accent, '8.5').name;
  const name = READABLE_VARIATION[nearest] ?? nearest;

  return {
    accent: { release: '8.5', name },
    highlight: { release: '8.5', name: HIGHLIGHT_FOR_VARIATION[name] }
  };
}

/** Counts calls, so only the latest of overlapping reads applies. */
let latestRead = 0;

/**
 * Read the host's colors and apply them; called at mount and on every
 * activation. Never rejects: a failed read is logged and keeps the
 * colors the page has (Osmium's default until a read succeeds, the last
 * good ones after), so a transient failure can't flip the colors.
 */
export async function applySystemColors(): Promise<void> {
  const read = ++latestRead;

  try {
    const next = appearanceFor(await TauriService.getSystemColors());
    if (read !== latestRead || !next || sameAppearance(next, getAppearance())) return;

    setAppearance(next);
  } catch (error) {
    console.error('Failed to apply the system colors:', error);
  }
}

function sameAppearance(a: Appearance, b: Appearance): boolean {
  return sameChoice(a.accent, b.accent) && sameChoice(a.highlight, b.highlight);
}

function sameChoice(a: AccentChoice | HighlightChoice, b: AccentChoice | HighlightChoice): boolean {
  if (typeof a === 'string' || typeof b === 'string') return a === b;
  if ('color' in a || 'color' in b) return 'color' in a && 'color' in b && a.color === b.color;

  return a.release === b.release && a.name === b.name;
}
