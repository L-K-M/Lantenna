import { beforeEach, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';

const storage = vi.hoisted(() => ({
  values: new Map<string, string>(),
  writes: [] as [string, unknown][]
}));

vi.mock('$lib/util/storage', () => ({
  readString: (key: string) => storage.values.get(key) ?? null,
  writeString: (key: string, value: string | null) => storage.writes.push([key, value]),
  readJson: <T>(key: string, guard: (v: unknown) => v is T): T | null => {
    const raw = storage.values.get(key);
    if (raw === undefined) return null;
    const value: unknown = JSON.parse(raw);
    return guard(value) ? value : null;
  },
  writeJson: (key: string, value: unknown) => storage.writes.push([key, value])
}));

async function freshUi() {
  vi.resetModules();
  return (await import('./ui')).ui;
}

beforeEach(() => {
  storage.values.clear();
  storage.writes = [];
});

it('starts from the defaults of spec 3.5', async () => {
  const ui = await freshUi();

  expect(get(ui)).toEqual({
    viewMode: 'list',
    scope: 'all',
    infoPaneShown: true,
    infoTab: 'general',
    listSort: { column: 'favorite', order: 'normal' },
    columnWidths: null,
    balloons: 'hidden',
    active: true,
    shaded: false
  });
});

it('restores remembered settings and ignores malformed ones', async () => {
  storage.values.set('lantenna.viewMode', 'icons');
  storage.values.set('lantenna.infoPane', 'hidden');
  storage.values.set('lantenna.infoTab', 'ports');
  storage.values.set('lantenna.listSort', JSON.stringify({ column: 'ip', order: 'reversed' }));
  storage.values.set('lantenna.listColumns', JSON.stringify({ name: 240 }));
  storage.values.set('lantenna.balloonHelp', 'shown');
  let ui = await freshUi();

  expect(get(ui)).toMatchObject({
    viewMode: 'icons',
    infoPaneShown: false,
    infoTab: 'ports',
    listSort: { column: 'ip', order: 'reversed' },
    columnWidths: { name: 240 },
    balloons: 'shown'
  });

  storage.values.set('lantenna.infoTab', 'banner');
  storage.values.set('lantenna.listSort', JSON.stringify({ column: 'size', order: 'normal' }));
  storage.values.set('lantenna.listColumns', JSON.stringify({ name: -1 }));
  ui = await freshUi();

  expect(get(ui)).toMatchObject({
    infoTab: 'general',
    listSort: { column: 'favorite', order: 'normal' },
    columnWidths: null
  });
});

it('remembers settings on change only, and never the session state', async () => {
  const ui = await freshUi();
  const updates = vi.fn();
  const stop = ui.subscribe(updates);

  ui.setViewMode('list');
  ui.setViewMode('icons');
  ui.setInfoPane(false);
  ui.setInfoTab('fingerprint');
  ui.setListSort({ column: 'favorite', order: 'normal' });
  ui.setListSort({ column: 'name', order: 'normal' });
  ui.setColumnWidth('name', 260);
  ui.setColumnWidth('name', 260);
  ui.setBalloons('shown');
  ui.setScope('new');
  ui.setActive(false);
  ui.setShaded(true);
  stop();

  expect(storage.writes).toEqual([
    ['lantenna.viewMode', 'icons'],
    ['lantenna.infoPane', 'hidden'],
    ['lantenna.infoTab', 'fingerprint'],
    ['lantenna.listSort', { column: 'name', order: 'normal' }],
    ['lantenna.listColumns', { name: 260 }],
    ['lantenna.balloonHelp', 'shown']
  ]);
  // The initial value plus one update per real change.
  expect(updates).toHaveBeenCalledTimes(10);
  expect(get(ui)).toMatchObject({ scope: 'new', active: false, shaded: true });
});
