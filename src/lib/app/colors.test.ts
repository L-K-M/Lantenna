// Owner: unit A (spec 8.4). Spec: 6.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getAppearance, HIGHLIGHTS_85, setAppearance, VARIATIONS_85 } from 'osmium-ui';
import { appearanceFor, applySystemColors, HIGHLIGHT_FOR_VARIATION } from './colors';
import type { SystemColors } from '$lib/types';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));

const DEFAULT_APPEARANCE = getAppearance();

function colors(accent: string | null): SystemColors {
  // The highlight and text colors are ignored whatever they hold.
  return {
    accent_color: accent,
    accent_text_color: '#ffffff',
    highlight_color: '#0a4fd1',
    highlight_text_color: '#ffffff'
  };
}

beforeEach(() => {
  invoke.mockReset();
});

afterEach(() => {
  setAppearance(DEFAULT_APPEARANCE);
  vi.restoreAllMocks();
});

describe('appearanceFor', () => {
  // macOS's standard accents (controlAccentColor, light appearance).
  it.each([
    ['Blue (and Multicolor)', '#007AFF', 'Sapphire', 'Azul'],
    ['Purple', '#953D96', 'Magenta', 'Purple'],
    ['Pink', '#F74F9E', 'Crimson', 'Plum'],
    ['Red', '#E0383E', 'Crimson', 'Plum'],
    ['Orange', '#F7821B', 'Poppy', 'Poppy'],
    ['Yellow', '#FFC600', 'Gold', 'Yellow'],
    ['Green', '#62BA46', 'Emerald', 'Green'],
    ['Graphite', '#8C8C8C', 'Silver', 'Gray']
  ])('maps %s %s to %s with the %s highlight', (_name, accent, variation, highlight) => {
    expect(appearanceFor(colors(accent))).toEqual({
      accent: { release: '8.5', name: variation },
      highlight: { release: '8.5', name: highlight }
    });
  });

  it('swaps Pistachio for Emerald and Sunny for Gold', () => {
    // Pistachio's and Sunny's own swatch colors (A3).
    expect(appearanceFor(colors('#b5e040'))?.accent).toEqual({ release: '8.5', name: 'Emerald' });
    expect(appearanceFor(colors('#e6c144'))?.accent).toEqual({ release: '8.5', name: 'Gold' });
  });

  it('gives null without colors or without an accent (Linux)', () => {
    expect(appearanceFor(null)).toBeNull();
    expect(appearanceFor(colors(null))).toBeNull();
  });

  it('refuses an accent that isn’t a hex color', () => {
    expect(() => appearanceFor(colors('rgb(0, 122, 255)'))).toThrow(RangeError);
  });

  it('pairs every 8.5 variation with an 8.5 highlight', () => {
    expect(Object.keys(HIGHLIGHT_FOR_VARIATION).sort()).toEqual([...VARIATIONS_85].sort());
    for (const highlight of Object.values(HIGHLIGHT_FOR_VARIATION)) expect(HIGHLIGHTS_85).toContain(highlight);
  });
});

describe('applySystemColors', () => {
  it('applies the host’s accent and its highlight', async () => {
    invoke.mockResolvedValue(colors('#007AFF'));

    await applySystemColors();

    expect(invoke).toHaveBeenCalledWith('get_system_colors');
    expect(getAppearance()).toEqual({
      accent: { release: '8.5', name: 'Sapphire' },
      highlight: { release: '8.5', name: 'Azul' }
    });
    expect(document.documentElement.style.getPropertyValue('--osm-highlight')).toBe('#99ccff');
  });

  it('keeps Osmium’s Lavender and Purple on Linux', async () => {
    invoke.mockResolvedValue(colors(null));
    const before = getAppearance();

    await applySystemColors();

    expect(getAppearance()).toBe(before);
    expect(before).toEqual(DEFAULT_APPEARANCE);
  });

  it('writes nothing when the colors haven’t changed', async () => {
    invoke.mockResolvedValue(colors('#007AFF'));
    await applySystemColors();
    const applied = getAppearance();

    await applySystemColors();

    expect(getAppearance()).toBe(applied);
  });

  it('follows a changed accent on the next read', async () => {
    invoke.mockResolvedValue(colors('#007AFF'));
    await applySystemColors();
    invoke.mockResolvedValue(colors('#62BA46'));

    await applySystemColors();

    expect(getAppearance().accent).toEqual({ release: '8.5', name: 'Emerald' });
  });

  it('keeps the colors it has when a read fails, and says why', async () => {
    const report = vi.spyOn(console, 'error').mockImplementation(() => {});
    invoke.mockResolvedValue(colors('#007AFF'));
    await applySystemColors();
    const applied = getAppearance();
    const error = new Error('no colors');
    invoke.mockRejectedValue(error);

    await expect(applySystemColors()).resolves.toBeUndefined();

    expect(getAppearance()).toBe(applied);
    expect(report).toHaveBeenCalledWith('Failed to apply the system colors:', error);
  });

  it('reports a malformed accent instead of applying it', async () => {
    const report = vi.spyOn(console, 'error').mockImplementation(() => {});
    invoke.mockResolvedValue(colors('blue'));
    const before = getAppearance();

    await applySystemColors();

    expect(getAppearance()).toBe(before);
    expect(report).toHaveBeenCalledWith('Failed to apply the system colors:', expect.any(RangeError));
  });

  it('applies only the latest of overlapping reads', async () => {
    let answerFirst!: (c: SystemColors) => void;
    invoke.mockReturnValueOnce(new Promise((resolve) => (answerFirst = resolve)));
    invoke.mockResolvedValueOnce(colors('#62BA46'));

    const first = applySystemColors();
    await applySystemColors();
    answerFirst(colors('#007AFF'));
    await first;

    expect(getAppearance().accent).toEqual({ release: '8.5', name: 'Emerald' });
  });
});
