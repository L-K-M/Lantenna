import { beforeEach, expect, it, vi } from 'vitest';
import { MENU_SEPARATOR } from 'osmium-ui';
import { balloon, osmButton, popup, type PopupParams } from './actions';

const osm = vi.hoisted(() => ({
  popup: { selected: 0, setItems: vi.fn(), setSelected: vi.fn(), destroy: vi.fn() },
  mountPopup: vi.fn(),
  pushButton: vi.fn(),
  balloon: { setContent: vi.fn(), detach: vi.fn() },
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

it('attaches Balloon Help and detaches it on destroy', () => {
  const target = document.createElement('button');
  const action = balloon(target, 'Scan button');

  expect(osm.attachBalloon).toHaveBeenCalledWith(target, { content: 'Scan button', trigger: 'balloon-help' });
  action.update!('Stop button');
  expect(osm.balloon.setContent).toHaveBeenCalledWith('Stop button');
  action.destroy!();
  expect(osm.balloon.detach).toHaveBeenCalledOnce();
});
