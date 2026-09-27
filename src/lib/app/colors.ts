// Owner: unit A (spec 8.4). Spec: 6.
//
// SCAFFOLD STUB: appearanceFor returns null and applySystemColors does
// nothing, so the page keeps Osmium's default Lavender with Purple.
// HIGHLIGHT_FOR_VARIATION already holds table 6's data; unit A owns it.
// Final contract: appearanceFor maps get_system_colors' accent through
// nearestAccent(accent, "8.5") with Pistachio -> Emerald and Sunny ->
// Gold, plus the matching highlight below; null input (Linux, failure)
// gives null. applySystemColors reads the colors and calls setAppearance
// only when the result differs from getAppearance().

import type { Appearance, Highlight85, Variation85 } from 'osmium-ui';
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

export function appearanceFor(c: SystemColors | null): Appearance | null {
  return null;
}

/** Read the host's colors and apply them; called at mount and on every
 * activation. Never rejects. */
export function applySystemColors(): Promise<void> {
  return Promise.resolve();
}
