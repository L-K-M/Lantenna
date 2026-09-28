import { afterEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import { classifyFocus, installKeyboardHome, keyboardFocus, type FocusKind } from './focus';
import { activeView } from './views';

/** Osmium's alert state, driven by the tests. */
const modal = vi.hoisted(() => ({ on: false, listeners: new Set<(on: boolean) => void>() }));
vi.mock('osmium-ui', () => ({
  isModal: () => modal.on,
  onModalChange: (listener: (on: boolean) => void) => {
    modal.listeners.add(listener);
    return () => modal.listeners.delete(listener);
  }
}));

afterEach(() => {
  document.body.textContent = '';
  activeView.set(null);
  modal.on = false;
  window.getSelection()?.removeAllRanges();
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

describe('the keyboard\'s home', () => {
  /** Mutation observers, then the check's microtask. */
  const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

  function home() {
    document.body.innerHTML = `
      <div id="frame"><div class="osm-content">
        <div class="lan-list"><div id="grid" tabindex="0"></div></div>
        <div class="lan-pane" id="pane">
          <button id="deep">Deep Scan</button>
          <input id="hidden" type="checkbox">
          <span id="value">192.168.1.31</span>
        </div>
      </div></div>`;
    const byId = (id: string) => document.getElementById(id)!;
    const grid = byId('grid');
    const focus = vi.fn(() => grid.focus());
    activeView.set({ element: grid, focus, reveal: vi.fn(), extraHeight: () => 0, idealColumnsWidth: () => null });
    const dispose = installKeyboardHome(byId('frame'));
    return { byId, grid, focus, dispose };
  }

  it('gives the view the keyboard at launch', async () => {
    const h = home();
    await settle();
    expect(h.focus).toHaveBeenCalledTimes(1);
    expect(document.activeElement).toBe(h.grid);
    h.dispose();
  });

  it('takes it back from a control that dims, hides or goes away', async () => {
    const h = home();
    await settle();

    h.byId('deep').focus();
    h.byId('deep').setAttribute('disabled', '');
    await settle();
    expect(document.activeElement).toBe(h.grid);

    h.byId('hidden').focus();
    h.byId('pane').hidden = true;
    await settle();
    expect(document.activeElement).toBe(h.grid);

    h.byId('pane').hidden = false;
    h.byId('hidden').focus();
    h.byId('hidden').remove();
    await settle();
    expect(document.activeElement).toBe(h.grid);
    expect(h.focus).toHaveBeenCalledTimes(4);
    h.dispose();
  });

  it('leaves the keyboard to an alert, and takes it back when the alert gives none', async () => {
    const h = home();
    await settle();

    modal.on = true;
    h.grid.blur();
    await settle();
    expect(document.activeElement).toBe(document.body);

    modal.on = false;
    for (const listener of modal.listeners) listener(false);
    await settle();
    expect(document.activeElement).toBe(h.grid);
    h.dispose();
  });

  it('waits for a press to end, and keeps text the press selected', async () => {
    const h = home();
    await settle();

    document.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true }));
    h.grid.blur();
    await settle();
    expect(document.activeElement).toBe(document.body);
    document.dispatchEvent(new PointerEvent('pointerup', { bubbles: true }));
    await settle();
    expect(document.activeElement).toBe(h.grid);

    document.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true }));
    h.grid.blur();
    window.getSelection()!.selectAllChildren(h.byId('value'));
    document.dispatchEvent(new PointerEvent('pointerup', { bubbles: true }));
    await settle();
    expect(document.activeElement).toBe(document.body);
    expect(window.getSelection()!.toString()).toBe('192.168.1.31');
    h.dispose();
  });

  it('lets only the latest press’s selection keep the keyboard off the view', async () => {
    const h = home();
    await settle();
    const press = (select?: () => void) => {
      document.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true }));
      select?.();
      document.dispatchEvent(new PointerEvent('pointerup', { bubbles: true }));
    };

    h.grid.blur();
    press(() => window.getSelection()!.selectAllChildren(h.byId('value')));
    await settle();
    expect(document.activeElement).toBe(document.body);

    // A later press on the gray or a button leaves the selection as it
    // was (Chromium): it no longer keeps the keyboard away.
    press();
    await settle();
    expect(document.activeElement).toBe(h.grid);
    h.dispose();
  });

  it('takes it back when the selection empties after the press (WebKitGTK)', async () => {
    const h = home();
    await settle();

    h.grid.blur();
    document.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true }));
    window.getSelection()!.selectAllChildren(h.byId('value'));
    document.dispatchEvent(new PointerEvent('pointerup', { bubbles: true }));
    await settle();
    expect(document.activeElement).toBe(document.body);

    window.getSelection()!.removeAllRanges();
    document.dispatchEvent(new Event('selectionchange'));
    await settle();
    expect(document.activeElement).toBe(h.grid);
    h.dispose();
  });

  it('takes it back at the next key after a press the page never saw end', async () => {
    const h = home();
    await settle();

    // The OS took the mouse (a window move): no pointerup comes.
    document.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true }));
    h.grid.blur();
    await settle();
    expect(document.activeElement).toBe(document.body);

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
    await settle();
    expect(document.activeElement).toBe(h.grid);
    h.dispose();
  });

  it('lets Tab take the keyboard out of the page, and brings it home at the next other key', async () => {
    const h = home();
    await settle();
    const key = (type: string, k: string) => document.dispatchEvent(new KeyboardEvent(type, { key: k, bubbles: true }));

    // Tab past the last control: the tab order wraps through <body>,
    // or the web view hands the keyboard to the first control.
    h.byId('deep').focus();
    key('keydown', 'Tab');
    h.byId('deep').blur();
    key('keyup', 'Tab');
    await settle();
    expect(document.activeElement).toBe(document.body);

    // Shift for a Shift-Tab back keeps it there too.
    key('keydown', 'Shift');
    await settle();
    expect(document.activeElement).toBe(document.body);

    key('keydown', 'ArrowDown');
    await settle();
    expect(document.activeElement).toBe(h.grid);
    expect(h.focus).toHaveBeenCalledTimes(2);
    h.dispose();
  });

  it('forgets the Tab once the keyboard is back in the page', async () => {
    const h = home();
    await settle();
    const key = (type: string, k: string) => document.dispatchEvent(new KeyboardEvent(type, { key: k, bubbles: true }));

    h.byId('deep').focus();
    key('keydown', 'Tab');
    h.byId('deep').blur();
    h.byId('hidden').focus();
    key('keyup', 'Tab');

    // A control that dims under the keyboard later still sends it home.
    h.byId('hidden').setAttribute('disabled', '');
    await settle();
    expect(document.activeElement).toBe(h.grid);
    h.dispose();
  });

  it('ends a Tab whose keyup never came at the next press, key or window focus change', async () => {
    const key = (type: string, k: string) => document.dispatchEvent(new KeyboardEvent(type, { key: k, bubbles: true }));
    const press = (type: string) => document.dispatchEvent(new PointerEvent(type, { bubbles: true }));

    // Tab takes the keyboard to the browser's toolbar: no keyup.
    for (const end of ['press', 'key', 'blur', 'focus']) {
      const h = home();
      await settle();
      h.byId('deep').focus();
      key('keydown', 'Tab');
      h.byId('deep').blur();
      await settle();

      // Back with a click in the list, a key, or the window's focus.
      if (end === 'press') {
        press('pointerdown');
        h.grid.focus();
        press('pointerup');
      } else {
        h.grid.focus();
        if (end === 'key') key('keydown', 'ArrowDown');
        else window.dispatchEvent(new FocusEvent(end));
      }
      await settle();

      // A click on the gray then gives the keyboard back to the view.
      press('pointerdown');
      h.grid.blur();
      press('pointerup');
      await settle();
      expect(document.activeElement, end).toBe(h.grid);
      h.dispose();
    }
  });

  it('waits while the window is collapsed', async () => {
    const h = home();
    await settle();
    const frame = h.byId('frame');

    frame.classList.add('osm-shaded');
    h.grid.blur();
    await settle();
    expect(h.focus).toHaveBeenCalledTimes(1);

    frame.classList.remove('osm-shaded');
    await settle();
    expect(document.activeElement).toBe(h.grid);
    h.dispose();
  });
});
