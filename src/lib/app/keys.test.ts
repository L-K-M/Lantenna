// Page keys on Linux (happy-dom's user agent): Control-Backspace in the
// list or the icon grid, and nothing else.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { readable } from 'svelte/store';

const state = vi.hoisted(() => ({ enabled: true, selection: false }));

vi.mock('./commands', () => ({
  commandContext: readable({}),
  describe: vi.fn(() => ({ title: '', enabled: state.enabled })),
  run: vi.fn()
}));

vi.mock('$lib/util/selection', () => ({ hasTextSelection: () => state.selection }));

const { run } = await import('./commands');
const { installPageKeys } = await import('./keys');
const { isMac } = await import('./platform');

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

it('runs on Linux here', () => {
  expect(isMac).toBe(false);
});

it('hides or shows the selected host on Control-Backspace in the list and the icons', () => {
  for (const view of ['lan-list', 'lan-icons']) {
    const e = press(place(view), { key: 'Backspace', ctrlKey: true });
    expect(e.defaultPrevented, view).toBe(true);
  }
  expect(vi.mocked(run).mock.calls).toEqual([[{ id: 'host.toggleHidden' }], [{ id: 'host.toggleHidden' }]]);
});

it('leaves Control-C to the Osmium menu bar', () => {
  const e = press(place('lan-list'), { key: 'c', ctrlKey: true });
  expect(e.defaultPrevented).toBe(false);
  expect(run).not.toHaveBeenCalled();
});

it('leaves the key alone elsewhere, with other modifiers, or when the command is dimmed', () => {
  const field = document.createElement('input');
  place('lan-list').append(field);
  const outside = document.createElement('button');
  document.body.append(outside);

  const cases: [Element, KeyboardEventInit][] = [
    [field, { key: 'Backspace', ctrlKey: true }], // deletes a word
    [outside, { key: 'Backspace', ctrlKey: true }],
    [place('lan-list'), { key: 'Backspace' }],
    [place('lan-list'), { key: 'Backspace', metaKey: true }],
    [place('lan-list'), { key: 'Backspace', ctrlKey: true, shiftKey: true }],
    [place('lan-list'), { key: 'Backspace', ctrlKey: true, altKey: true }],
    [place('lan-list'), { key: 'Backspace', ctrlKey: true, repeat: true }],
    [place('lan-list'), { key: 'Delete', ctrlKey: true }]
  ];
  for (const [target, init] of cases) {
    expect(press(target, init).defaultPrevented, JSON.stringify(init)).toBe(false);
  }

  state.enabled = false;
  expect(press(place('lan-list'), { key: 'Backspace', ctrlKey: true }).defaultPrevented).toBe(false);
  expect(run).not.toHaveBeenCalled();
});

it('leaves a key a view already handled', () => {
  const grid = place('lan-list');
  grid.addEventListener('keydown', (e) => e.preventDefault());
  press(grid, { key: 'Backspace', ctrlKey: true });
  expect(run).not.toHaveBeenCalled();
});

it('stops listening once disposed', () => {
  dispose();
  press(place('lan-list'), { key: 'Backspace', ctrlKey: true });
  expect(run).not.toHaveBeenCalled();
});
