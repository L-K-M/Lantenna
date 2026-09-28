// Page keys on macOS: Command-C copies the selected host's IP and
// Command-Delete hides or shows it, in the list or the icon grid only;
// everything else is the native menu's.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { readable } from 'svelte/store';

const state = vi.hoisted(() => ({ enabled: true, selection: false }));

vi.mock('./platform', () => ({ platform: 'mac', isMac: true, cmdName: 'Command' }));

vi.mock('./commands', () => ({
  commandContext: readable({}),
  describe: vi.fn(() => ({ title: '', enabled: state.enabled })),
  run: vi.fn()
}));

vi.mock('$lib/util/selection', () => ({ hasTextSelection: () => state.selection }));

const { run } = await import('./commands');
const { installPageKeys } = await import('./keys');

let dispose: () => void = () => {};

function place(className: string): HTMLElement {
  const host = document.createElement('div');
  host.className = className;
  const grid = document.createElement('div');
  grid.tabIndex = 0;
  host.append(grid);
  document.body.append(host);
  return grid;
}

function press(target: Element, init: KeyboardEventInit): KeyboardEvent {
  const e = new KeyboardEvent('keydown', { bubbles: true, cancelable: true, ...init });
  target.dispatchEvent(e);
  return e;
}

beforeEach(() => {
  vi.mocked(run).mockClear();
  state.enabled = true;
  state.selection = false;
  dispose = installPageKeys();
});

afterEach(() => {
  dispose();
  document.body.replaceChildren();
});

it('copies the IP on Command-C and hides on Command-Delete in the list and the icons', () => {
  for (const view of ['lan-list', 'lan-icons']) {
    expect(press(place(view), { key: 'c', metaKey: true }).defaultPrevented).toBe(true);
    expect(press(place(view), { key: 'C', metaKey: true }).defaultPrevented).toBe(true); // Caps Lock
    expect(press(place(view), { key: 'Backspace', metaKey: true }).defaultPrevented).toBe(true);
  }
  expect(vi.mocked(run).mock.calls.map(([ref]) => ref.id)).toEqual([
    'edit.copyIp',
    'edit.copyIp',
    'host.toggleHidden',
    'edit.copyIp',
    'edit.copyIp',
    'host.toggleHidden'
  ]);
});

it('leaves Command-C to the native Copy in text, with a text selection, or with nothing to copy', () => {
  const field = document.createElement('input');
  place('lan-list').append(field);
  expect(press(field, { key: 'c', metaKey: true }).defaultPrevented).toBe(false);

  state.selection = true;
  expect(press(place('lan-list'), { key: 'c', metaKey: true }).defaultPrevented).toBe(false);

  state.selection = false;
  state.enabled = false;
  expect(press(place('lan-list'), { key: 'c', metaKey: true }).defaultPrevented).toBe(false);
  expect(run).not.toHaveBeenCalled();
});

it('leaves every other Command key to the native menu', () => {
  for (const key of ['r', '.', 'f', 'o', 'i', 'd', 'w', 'q', 'v', 'x', 'z']) {
    expect(press(place('lan-list'), { key, metaKey: true }).defaultPrevented, key).toBe(false);
  }
  // Control is not the command key on macOS.
  expect(press(place('lan-list'), { key: 'Backspace', ctrlKey: true }).defaultPrevented).toBe(false);
  expect(press(place('lan-list'), { key: 'c', ctrlKey: true }).defaultPrevented).toBe(false);
  expect(run).not.toHaveBeenCalled();
});

it('keeps Command-A from the native Select All in the list and the icons only', () => {
  for (const view of ['lan-list', 'lan-icons']) {
    expect(press(place(view), { key: 'a', metaKey: true }).defaultPrevented, view).toBe(true);
  }
  const field = document.createElement('input');
  place('lan-list').append(field);
  expect(press(field, { key: 'a', metaKey: true }).defaultPrevented).toBe(false);
  // Command-Shift-Z redoes through the native menu's predefined Redo.
  expect(press(field, { key: 'z', metaKey: true, shiftKey: true }).defaultPrevented).toBe(false);
  expect(run).not.toHaveBeenCalled();
});
