import { afterEach, expect, it } from 'vitest';
import { get } from 'svelte/store';
import { classifyFocus, keyboardFocus, type FocusKind } from './focus';

afterEach(() => {
  document.body.textContent = '';
});

function build(): Record<string, HTMLElement> {
  document.body.innerHTML = `
    <div class="lan-list"><div id="grid" tabindex="0"><button id="star" tabindex="-1"></button></div></div>
    <div class="lan-icons"><div id="tile" tabindex="0"></div></div>
    <input id="find" class="osm-edit">
    <label class="osm-checkbox"><input id="check" type="checkbox"></label>
    <div class="lan-list"><input id="inList"></div>
    <textarea id="notes" readonly></textarea>
    <button id="scan">Scan</button>`;
  const byId = (id: string) => document.getElementById(id)!;
  return Object.fromEntries(
    ['grid', 'star', 'tile', 'find', 'check', 'inList', 'notes', 'scan'].map((id) => [id, byId(id)])
  );
}

it('classifies the list, the icon grid, text fields and the rest', () => {
  const el = build();
  const kinds: Record<string, FocusKind> = {
    grid: 'list', star: 'list', tile: 'icons', find: 'text', check: 'other', inList: 'text',
    notes: 'readonly-text', scan: 'other'
  };

  for (const [id, kind] of Object.entries(kinds)) expect(classifyFocus(el[id]), id).toBe(kind);
  expect(classifyFocus(null)).toBe('other');
  expect(classifyFocus(document.body)).toBe('other');
});

it('follows focus moving between places and leaving for nowhere', async () => {
  const el = build();
  const seen: FocusKind[] = [];
  const stop = keyboardFocus.subscribe((kind) => seen.push(kind));

  el.grid.focus();
  el.find.focus();
  el.find.blur();
  await Promise.resolve();
  stop();

  expect(seen).toEqual(['other', 'list', 'text', 'other']);
  expect(get(keyboardFocus)).toBe('other');
});

it('reads focus leaving for nowhere after the event, not during it', async () => {
  const el = build();
  const seen: FocusKind[] = [];
  const stop = keyboardFocus.subscribe((kind) => seen.push(kind));
  el.tile.focus();

  // As a browser does when the focused tile is removed or moved (during
  // Svelte's update): nothing is written while the event is dispatched.
  el.tile.dispatchEvent(new FocusEvent('focusout', { bubbles: true, relatedTarget: null }));
  el.tile.remove();
  expect(seen).toEqual(['other', 'icons']);

  await Promise.resolve();
  expect(seen).toEqual(['other', 'icons', 'other']);
  stop();
});

it('keeps the kind when the window loses focus but the element keeps it', async () => {
  const el = build();
  const stop = keyboardFocus.subscribe(() => {});
  el.find.focus();

  el.find.dispatchEvent(new FocusEvent('focusout', { bubbles: true, relatedTarget: null }));
  await Promise.resolve();
  expect(get(keyboardFocus)).toBe('text');
  stop();
});
