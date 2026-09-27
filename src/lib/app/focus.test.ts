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
    <button id="scan">Scan</button>`;
  const byId = (id: string) => document.getElementById(id)!;
  return Object.fromEntries(
    ['grid', 'star', 'tile', 'find', 'check', 'inList', 'scan'].map((id) => [id, byId(id)])
  );
}

it('classifies the list, the icon grid, text fields and the rest', () => {
  const el = build();
  const kinds: Record<string, FocusKind> = {
    grid: 'list', star: 'list', tile: 'icons', find: 'text', check: 'other', inList: 'text', scan: 'other'
  };

  for (const [id, kind] of Object.entries(kinds)) expect(classifyFocus(el[id]), id).toBe(kind);
  expect(classifyFocus(null)).toBe('other');
  expect(classifyFocus(document.body)).toBe('other');
});

it('follows focus moving between places and leaving for nowhere', () => {
  const el = build();
  const seen: FocusKind[] = [];
  const stop = keyboardFocus.subscribe((kind) => seen.push(kind));

  el.grid.focus();
  el.find.focus();
  el.find.blur();
  stop();

  expect(seen).toEqual(['other', 'list', 'text', 'other']);
  expect(get(keyboardFocus)).toBe('other');
});
