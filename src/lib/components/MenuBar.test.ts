// The Linux menu bar: Osmium's bar with the menus of 4.3, keys with
// Control, text-editing keys (but Undo) left to the browser, and Edit items that
// describe the field the keyboard was in when the menu opened.
import { render } from '@testing-library/svelte';
import { afterEach, expect, it, vi } from 'vitest';
import MenuBar from './MenuBar.svelte';

function titles(bar: HTMLElement): HTMLElement[] {
  return Array.from(bar.querySelectorAll<HTMLElement>('.osm-menubar-title'));
}

function openMenu(): HTMLElement | null {
  return document.querySelector<HTMLElement>('.osm-menu.osm-pulldown');
}

/** Items as text: '-' separators, '[x]' dimmed, keys after. */
function items(menu: HTMLElement): string[] {
  return Array.from(menu.children).map((li) => {
    if (!li.classList.contains('osm-menu-item')) return '-';
    const key = li.querySelector('.osm-menu-key')?.textContent;
    const title = li.firstChild?.textContent ?? '';
    const shown = li.getAttribute('aria-disabled') === 'true' ? `[${title}]` : title;
    return key ? `${shown} ${key}` : shown;
  });
}

function keydown(target: EventTarget, init: KeyboardEventInit): KeyboardEvent {
  const e = new KeyboardEvent('keydown', { bubbles: true, cancelable: true, ...init });
  target.dispatchEvent(e);
  return e;
}

afterEach(() => {
  if (openMenu()) keydown(document, { key: 'Escape' });
  document.body.querySelectorAll('input').forEach((i) => i.remove());
});

function mount() {
  const { container } = render(MenuBar);
  return container.querySelector<HTMLElement>('.lan-menubar')!;
}

it('draws the menus of 4.3 behind the antenna', () => {
  const bar = mount();
  expect(bar.classList.contains('osm-menubar')).toBe(true);
  expect(bar.getAttribute('role')).toBe('menubar');

  const [antenna, ...rest] = titles(bar);
  expect(antenna!.getAttribute('aria-label')).toBe('Lantenna');
  expect(antenna!.querySelector<HTMLElement>('.osm-menubar-icon')!.style.backgroundImage).toBe(
    'var(--osm-sprite-lan-antenna)'
  );
  expect(rest.map((t) => t.textContent)).toEqual(['File', 'Edit', 'Scan', 'Host', 'Favorites', 'View', 'Help']);
});

it('opens a menu from the keyboard with Control keys drawn as ⌘', () => {
  const bar = mount();
  const file = titles(bar)[1]!;
  file.focus();
  keydown(file, { key: 'Enter' });

  const menu = openMenu()!;
  expect(items(menu)).toEqual(['Close Window ⌘W', '-', 'Quit ⌘Q']);
  expect(menu.querySelector('.osm-menu-item')!.getAttribute('aria-keyshortcuts')).toBe('Control+W');

  keydown(document, { key: 'ArrowRight' });
  keydown(document, { key: 'ArrowRight' });
  keydown(document, { key: 'ArrowRight' });
  keydown(document, { key: 'ArrowRight' });
  keydown(document, { key: 'ArrowRight' });
  keydown(document, { key: 'ArrowRight' });
  expect(items(openMenu()!)).toEqual(['Show Balloons', '-', 'Lantenna Help']);
});

it('runs an enabled item’s key equivalent', () => {
  mount();
  const find = document.createElement('input');
  find.id = 'lan-find';
  find.value = 'nas';
  document.body.append(find);

  const e = keydown(document.body, { key: 'f', ctrlKey: true });
  expect(e.defaultPrevented).toBe(true);
  expect(document.activeElement).toBe(find);
  expect([find.selectionStart, find.selectionEnd]).toEqual([0, 3]);
});

it('leaves editing keys in a text field to the browser, flashing Edit, but runs Undo', () => {
  const bar = mount();
  const field = document.createElement('input');
  document.body.append(field);
  field.focus();

  for (const key of ['x', 'c', 'v', 'a']) {
    expect(keydown(field, { key, ctrlKey: true }).defaultPrevented, key).toBe(false);
  }
  expect(titles(bar)[2]!.classList.contains('osm-open')).toBe(true);

  // WebKitGTK binds nothing to Control-Z: the item undoes.
  const exec = vi.spyOn(document, 'execCommand').mockReturnValue(true);
  expect(keydown(field, { key: 'z', ctrlKey: true }).defaultPrevented).toBe(true);
  expect(exec).toHaveBeenCalledWith('undo');
  exec.mockRestore();
});

it('describes the field the keyboard was in when the menu opened, across menus', () => {
  const bar = mount();
  const field = document.createElement('input');
  document.body.append(field);
  field.focus();

  const edit = titles(bar)[2]!;
  vi.spyOn(edit, 'getBoundingClientRect').mockReturnValue(DOMRect.fromRect({ x: 60, y: 0, width: 40, height: 19 }));
  const press = { bubbles: true, cancelable: true, button: 0, clientX: 70, clientY: 5 };
  edit.dispatchEvent(new PointerEvent('pointerdown', press));
  const enabledEdits = () => items(openMenu()!).slice(0, 6);
  expect(enabledEdits()).toEqual(['Undo ⌘Z', '-', 'Cut ⌘X', 'Copy ⌘C', 'Paste ⌘V', 'Select All ⌘A']);

  // To Scan and back: the keyboard is in the menu now, not the field.
  keydown(document, { key: 'ArrowRight' });
  keydown(document, { key: 'ArrowLeft' });
  expect(openMenu()!.getAttribute('aria-label')).toBe('Edit');
  expect(enabledEdits()).toEqual(['Undo ⌘Z', '-', 'Cut ⌘X', 'Copy ⌘C', 'Paste ⌘V', 'Select All ⌘A']);

  // Closed, the menu gives the keyboard back to the field.
  keydown(document, { key: 'Escape' });
  expect(document.activeElement).toBe(field);
});

it('dims the text items with the keyboard elsewhere', () => {
  const bar = mount();
  const edit = titles(bar)[2]!;
  edit.focus();
  keydown(edit, { key: 'Enter' });
  expect(items(openMenu()!).slice(0, 6)).toEqual([
    '[Undo] ⌘Z',
    '-',
    '[Cut] ⌘X',
    '[Copy] ⌘C',
    '[Paste] ⌘V',
    '[Select All] ⌘A'
  ]);
});
