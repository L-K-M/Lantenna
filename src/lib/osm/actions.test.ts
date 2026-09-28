import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MENU_SEPARATOR } from 'osmium-ui';
import { areaBalloon, balloon, checkboxBalloon, dimmable, osmButton, popup, type PopupParams } from './actions';

const osm = vi.hoisted(() => ({
  popup: { selected: 0, setItems: vi.fn(), setSelected: vi.fn(), destroy: vi.fn() },
  mountPopup: vi.fn(),
  pushButton: vi.fn(),
  balloon: { element: { id: 'osm-balloon-9' }, setContent: vi.fn(), detach: vi.fn() },
  attachBalloon: vi.fn()
}));

vi.mock('osmium-ui', async (importOriginal) => ({
  ...await importOriginal<typeof import('osmium-ui')>(),
  mountPopup: osm.mountPopup,
  pushButton: osm.pushButton,
  attachBalloon: osm.attachBalloon
}));

beforeEach(() => {
  vi.clearAllMocks();
  osm.popup.selected = 0;
  osm.mountPopup.mockReturnValue(osm.popup);
  osm.attachBalloon.mockReturnValue(osm.balloon);
});

function params(over: Partial<PopupParams> = {}): PopupParams {
  return { items: ['Fast', 'Balanced', 'Thorough'], selected: 1, label: 'Depth', onChange: vi.fn(), ...over };
}

it('mounts a pop-up and follows only real changes', () => {
  const button = document.createElement('button');
  const first = params();
  const action = popup(button, first);

  expect(osm.mountPopup).toHaveBeenCalledWith(button, expect.objectContaining({
    items: first.items, selected: 1, label: 'Depth'
  }));
  osm.popup.selected = 1;

  // Same titles in a new array: nothing to rebuild.
  action.update!(params({ items: ['Fast', 'Balanced', 'Thorough'] }));
  expect(osm.popup.setItems).not.toHaveBeenCalled();
  expect(osm.popup.setSelected).not.toHaveBeenCalled();

  action.update!(params({ selected: 2 }));
  expect(osm.popup.setSelected).toHaveBeenCalledWith(2);

  const items: PopupParams['items'] = [{ title: 'No interfaces found', disabled: true }, MENU_SEPARATOR];
  action.update!(params({ items, selected: 0, disabled: true }));
  expect(osm.popup.setItems).toHaveBeenCalledWith(items, 0);
  expect(button.disabled).toBe(true);

  action.destroy!();
  expect(osm.popup.destroy).toHaveBeenCalledOnce();
});

it('reports choices to the latest onChange', () => {
  const later = vi.fn();
  const action = popup(document.createElement('button'), params());
  action.update!(params({ onChange: later }));

  osm.mountPopup.mock.calls[0][1].onChange(2);

  expect(later).toHaveBeenCalledWith(2);
});

it('runs the latest button action', () => {
  const first = vi.fn();
  const second = vi.fn();
  const action = osmButton(document.createElement('button'), first);
  action.update!(second);

  osm.pushButton.mock.calls[0][1]();

  expect(first).not.toHaveBeenCalled();
  expect(second).toHaveBeenCalledOnce();
});

it('presses a button once for a held Return, as Return elsewhere', () => {
  const button = document.createElement('button');
  osmButton(button, vi.fn());
  const enter = (repeat: boolean) => {
    const e = new KeyboardEvent('keydown', { key: 'Enter', repeat, bubbles: true, cancelable: true });
    button.dispatchEvent(e);
    return e.defaultPrevented;
  };

  // The browser clicks on each keydown it isn't kept from.
  expect(enter(false)).toBe(false);
  expect(enter(true)).toBe(true);
  expect(enter(true)).toBe(true);
});

describe('a dimmable button', () => {
  afterEach(() => {
    document.body.textContent = '';
  });

  function mounted(dimmed: boolean) {
    const button = document.body.appendChild(document.createElement('button'));
    const run = vi.fn();
    osmButton(button, run);
    const action = dimmable(button, dimmed);
    const press = () => osm.pushButton.mock.calls[0][1]();
    return { button, run, action, press };
  }

  const state = (b: HTMLButtonElement) => ({ disabled: b.disabled, ariaDisabled: b.getAttribute('aria-disabled') });

  it('is disabled while dimmed without the keyboard', () => {
    const { button, action } = mounted(true);
    expect(state(button)).toEqual({ disabled: true, ariaDisabled: null });

    action.update!(false);
    expect(state(button)).toEqual({ disabled: false, ariaDisabled: null });
  });

  it('keeps the keyboard when it dims, and ignores presses until it is enabled again', () => {
    const { button, run, action, press } = mounted(false);
    button.focus();

    action.update!(true);
    expect(document.activeElement).toBe(button);
    expect(state(button)).toEqual({ disabled: false, ariaDisabled: 'true' });
    press();
    expect(run).not.toHaveBeenCalled();

    action.update!(false);
    expect(state(button)).toEqual({ disabled: false, ariaDisabled: null });
    press();
    expect(run).toHaveBeenCalledOnce();
  });

  it('is disabled as usual once the keyboard leaves', async () => {
    const { button, action } = mounted(false);
    const other = document.body.appendChild(document.createElement('button'));
    button.focus();
    action.update!(true);

    other.focus();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(state(button)).toEqual({ disabled: true, ariaDisabled: null });
  });

  it('stays dimmed with the keyboard while the window loses focus', async () => {
    const { button, action } = mounted(false);
    button.focus();
    action.update!(true);

    // The element keeps the DOM focus; only the events come.
    button.dispatchEvent(new FocusEvent('focusout', { bubbles: true, relatedTarget: null }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(state(button)).toEqual({ disabled: false, ariaDisabled: 'true' });
  });
});

it('attaches Balloon Help and detaches it on destroy', () => {
  const target = document.createElement('button');
  const action = balloon(target, 'Scan button');

  expect(osm.attachBalloon).toHaveBeenCalledWith(target, { content: 'Scan button', trigger: 'balloon-help', tip: 'anchor' });
  action.update!('Stop button');
  expect(osm.balloon.setContent).toHaveBeenCalledWith('Stop button');
  action.destroy!();
  expect(osm.balloon.detach).toHaveBeenCalledOnce();
});

it('points an area’s balloon at the pointer, or for the keyboard at its middle, not a far corner', () => {
  const target = document.createElement('div');
  const action = areaBalloon(target, 'Host list');
  expect(osm.attachBalloon).toHaveBeenCalledWith(target, {
    content: 'Host list',
    trigger: 'balloon-help',
    tip: 'pointer',
    // Osmium clamps the inset to the target's center.
    anchor: { x: 1e6, y: 1e6 }
  });
  action.destroy?.();
  expect(osm.balloon.detach).toHaveBeenCalledOnce();
});

it('points a checkbox’s balloon past its title, describing the box itself', () => {
  const label = document.createElement('label');
  label.innerHTML = '<input type="checkbox">Show hidden hosts';
  const input = label.querySelector('input')!;
  // Osmium names the balloon in its target's description.
  osm.attachBalloon.mockImplementation((target: HTMLElement) => {
    target.setAttribute('aria-describedby', 'osm-balloon-9');
    return osm.balloon;
  });

  const action = checkboxBalloon(label, 'Show hidden hosts checkbox');
  expect(osm.attachBalloon).toHaveBeenCalledWith(label, {
    content: 'Show hidden hosts checkbox',
    trigger: 'balloon-help',
    tip: 'anchor'
  });
  expect(input.getAttribute('aria-describedby')).toBe('osm-balloon-9');
  expect(label.hasAttribute('aria-describedby')).toBe(false);

  action.update!('Show hidden hosts checkbox (dimmed)');
  expect(osm.balloon.setContent).toHaveBeenCalledWith('Show hidden hosts checkbox (dimmed)');
  action.destroy!();
  expect(osm.balloon.detach).toHaveBeenCalledOnce();
  expect(input.hasAttribute('aria-describedby')).toBe(false);
});
