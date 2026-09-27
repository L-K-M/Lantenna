import { afterEach, describe as group, expect, it } from 'vitest';
import { get } from 'svelte/store';
import { MENU_SEPARATOR, balloonHelp, isModal, setBalloonHelp, showAlert, type OsmiumAlert } from 'osmium-ui';
import {
  commandContext,
  describe,
  hostMenuSpec,
  menuBarSpec,
  osmiumMenuEntries,
  viewMenuSpec,
  type CommandContext,
  type CommandId,
  type CommandRef,
  type SpecEntry
} from './commands';
import { EN0, EN7, context, host, row, selecting } from './commands.fixture';

let alert: OsmiumAlert | null = null;

afterEach(async () => {
  alert?.close();
  await alert?.result;
  alert = null;
  setBalloonHelp('hidden');
});

it('sees an alert that opened while nothing read the context', async () => {
  expect(get(commandContext).modal).toBe(false);

  alert = showAlert({ kind: 'stop', message: 'Lantenna couldn’t start its scanner.' });
  expect(isModal()).toBe(true);
  expect(get(commandContext).modal).toBe(true);

  alert.close();
  await alert.result;
  expect(get(commandContext).modal).toBe(false);
});

const ref = (id: CommandId, arg?: string): CommandRef => (arg === undefined ? { id } : { id, arg });

/** Every command a spec for `ctx` names, menu bar and contextual. */
function allRefs(ctx: CommandContext): CommandRef[] {
  const entries: SpecEntry[] = [
    ...menuBarSpec(ctx).flatMap((m) => m.entries),
    ...menuBarSpec({ ...ctx, platform: 'mac' }).flatMap((m) => m.entries),
    ...hostMenuSpec(ctx),
    ...viewMenuSpec(ctx)
  ];
  return entries.filter((e): e is CommandRef => e !== 'separator' && !('predefined' in e));
}

/** A menu as text: titles, '-' for separators, '<name>' for predefined
 * items, dimmed items in brackets, check marks and keys after. */
function dump(entries: readonly SpecEntry[], ctx: CommandContext, place: 'menubar' | 'contextual' = 'menubar') {
  return entries.map((e) => {
    if (e === 'separator') return '-';
    if ('predefined' in e) return `<${e.predefined}>`;
    const info = describe(e, ctx, place);
    const title = info.enabled ? info.title : `[${info.title}]`;
    return `${title}${info.checked ? ' ✓' : ''}${info.key ? ` ⌘${info.key}` : ''}`;
  });
}

const printer = host('192.168.1.31', { name: 'BRN30055C.local', ports: [80, 445], mac: '30:05:5C:12:34:56' });
const bare = host('192.168.1.77');

group('describe', () => {
  it('scans when idle with an interface, stops while scanning, waits while stopping', () => {
    expect(describe(ref('scan.toggle'), context())).toEqual({ title: 'Scan Network', enabled: true, key: 'R' });
    expect(describe(ref('scan.toggle'), context({ store: { loading: true } })).enabled).toBe(false);
    expect(describe(ref('scan.toggle'), context({ store: { interfaces: [], selectedInterface: null } })).enabled).toBe(
      false
    );
    // A stale key that no longer resolves.
    expect(describe(ref('scan.toggle'), context({ store: { selectedInterface: 'en9|10.9.9.9' } })).enabled).toBe(false);

    expect(describe(ref('scan.toggle'), context({ store: { scanning: true } }))).toEqual({
      title: 'Stop Scan',
      enabled: true,
      key: '.'
    });
    expect(describe(ref('scan.toggle'), context({ store: { scanning: true, stopping: true } }))).toEqual({
      title: 'Stopping…',
      enabled: false,
      key: '.'
    });
  });

  it('checks the current interface and depth, and dims them while scanning', () => {
    const idle = context({ store: { interfaces: [EN0, EN7], selectedInterface: 'en7' } });
    expect(describe(ref('scan.interface', 'en0|192.168.1.23'), idle)).toEqual({
      title: 'en0 (192.168.1.0/24)',
      enabled: true,
      checked: false
    });
    // A legacy key (bare name) still resolves to its interface.
    expect(describe(ref('scan.interface', 'en7|10.0.0.5'), idle).checked).toBe(true);
    expect(describe(ref('scan.depth', 'balanced'), idle)).toEqual({ title: 'Balanced', enabled: true, checked: true });
    expect(describe(ref('scan.depth', 'thorough'), idle).checked).toBe(false);

    const scanning = context({ store: { scanning: true } });
    expect(describe(ref('scan.interface', 'en0|192.168.1.23'), scanning).enabled).toBe(false);
    expect(describe(ref('scan.depth', 'fast'), scanning).enabled).toBe(false);

    const none = context({ store: { interfaces: [], selectedInterface: null } });
    expect(menuBarSpec(none)[3]!.entries.slice(0, 4)).toEqual([
      { id: 'scan.toggle' },
      'separator',
      { id: 'scan.interface' },
      'separator'
    ]);
    expect(describe(ref('scan.interface'), none)).toEqual({
      title: 'No interfaces found',
      enabled: false,
      checked: false
    });
  });

  it('dims every host command without a selection', () => {
    const ctx = context({ focus: 'list' });
    for (const id of [
      'edit.copy',
      'edit.copyIp',
      'edit.copyName',
      'edit.copyDetectedName',
      'edit.copyMac',
      'host.open',
      'host.getInfo',
      'host.rename',
      'host.clearName',
      'host.toggleHidden',
      'host.deepScan',
      'host.wake',
      'fav.toggle'
    ] as const) {
      expect(describe(ref(id), ctx).enabled, id).toBe(false);
    }
    expect(describe(ref('host.toggleHidden'), ctx).title).toBe('Hide Host');
    expect(describe(ref('fav.toggle'), ctx).title).toBe('Add to Favorites');
    expect(describe(ref('edit.copyHostList'), ctx).enabled).toBe(false);
  });

  it('enables the host commands for a selected host', () => {
    const ctx = selecting(row(printer, { customName: 'Office Printer' }));
    for (const id of [
      'edit.copyIp',
      'edit.copyName',
      'edit.copyDetectedName',
      'edit.copyMac',
      'edit.copyHostList',
      'host.open',
      'host.getInfo',
      'host.rename',
      'host.clearName',
      'host.toggleHidden',
      'host.deepScan',
      'host.wake',
      'fav.toggle'
    ] as const) {
      expect(describe(ref(id), ctx).enabled, id).toBe(true);
    }
    expect(describe(ref('host.open'), ctx).key).toBe('O');
    expect(describe(ref('host.getInfo'), ctx).key).toBe('I');
    expect(describe(ref('host.deepScan'), ctx).key).toBe('D');
    expect(describe(ref('host.openUrl', 'http://192.168.1.31'), ctx).enabled).toBe(true);
    expect(describe(ref('host.openUrl', 'http://192.168.1.99'), ctx).enabled).toBe(false);
  });

  it('dims what a bare host lacks: name, MAC, target, custom name', () => {
    const ctx = selecting(row(bare));
    expect(describe(ref('edit.copyIp'), ctx).enabled).toBe(true);
    expect(describe(ref('edit.copyName'), ctx).enabled).toBe(false);
    expect(describe(ref('edit.copyDetectedName'), ctx).enabled).toBe(false);
    expect(describe(ref('edit.copyMac'), ctx).enabled).toBe(false);
    expect(describe(ref('host.open'), ctx).enabled).toBe(false);
    expect(describe(ref('host.wake'), ctx).enabled).toBe(false);
    expect(describe(ref('host.clearName'), ctx).enabled).toBe(false);

    // A custom name alone is a host name, not a detected one.
    const named = selecting(row(bare, { customName: 'Spare' }));
    expect(describe(ref('edit.copyName'), named).enabled).toBe(true);
    expect(describe(ref('edit.copyDetectedName'), named).enabled).toBe(false);
  });

  it('dims Wake while a wake-up packet is sending and Deep Scan while one runs', () => {
    const r = row(printer);
    expect(describe(ref('host.wake'), selecting(r, { wakingIp: '192.168.1.40' })).enabled).toBe(false);
    const deep = { phase: 'ports' as const, scanned: 3, total: 9, found: 0, running: true, current_ip: '192.168.1.40' };
    expect(describe(ref('host.deepScan'), selecting(r, { progress: { hostScanProgress: deep } })).enabled).toBe(false);
    const done = { ...deep, running: false };
    expect(describe(ref('host.deepScan'), selecting(r, { progress: { hostScanProgress: done } })).enabled).toBe(true);
  });

  it('names the host in the menu bar’s favorites item, not in the contextual one', () => {
    const r = row(printer, { customName: 'Office Printer' });
    expect(describe(ref('fav.toggle'), selecting(r)).title).toBe('Add “Office Printer” to Favorites');
    expect(describe(ref('fav.toggle'), selecting(r), 'contextual').title).toBe('Add to Favorites');

    const favorite = row(printer, { favorite: true });
    expect(describe(ref('fav.toggle'), selecting(favorite)).title).toBe('Remove “BRN30055C.local” from Favorites');
    expect(describe(ref('fav.toggle'), selecting(favorite), 'contextual').title).toBe('Remove from Favorites');

    expect(describe(ref('fav.toggle'), selecting(row(bare))).title).toBe('Add “192.168.1.77” to Favorites');
  });

  it('offers Show Host for a shown hidden host', () => {
    const hidden = row(bare, { hidden: true, status: 'Hidden' });
    expect(describe(ref('host.toggleHidden'), selecting(hidden))).toEqual({ title: 'Show Host', enabled: true });
  });

  it('acts on text only where the keyboard edits it', () => {
    const edits = ['edit.undo', 'edit.cut', 'edit.copy', 'edit.paste', 'edit.selectAll'] as const;
    const enabled = (ctx: CommandContext) => edits.filter((id) => describe(ref(id), ctx).enabled);

    expect(enabled(context({ focus: 'text' }))).toEqual(edits);
    expect(enabled(context({ focus: 'readonly-text' }))).toEqual(['edit.copy', 'edit.selectAll']);
    expect(enabled(context({ focus: 'other' }))).toEqual([]);
    expect(enabled(context({ focus: 'list' }))).toEqual([]);
    // Copy in the list copies the selected host's IP.
    expect(enabled(selecting(row(bare), { focus: 'list' }))).toEqual(['edit.copy']);
    expect(enabled(selecting(row(bare), { focus: 'icons' }))).toEqual(['edit.copy']);
    expect(enabled(selecting(row(bare), { focus: 'other' }))).toEqual([]);
    expect(edits.map((id) => describe(ref(id), context()).key)).toEqual(['Z', 'X', 'C', 'V', 'A']);
  });

  it('follows the view state', () => {
    const ctx = context({
      ui: { viewMode: 'icons', scope: 'new', infoPaneShown: false, shaded: true, balloons: 'shown' }
    });
    expect(describe(ref('view.mode', 'list'), ctx)).toEqual({ title: 'as List', enabled: true, checked: false });
    expect(describe(ref('view.mode', 'icons'), ctx)).toEqual({ title: 'as Icons', enabled: true, checked: true });
    expect(describe(ref('view.scope', 'new'), ctx)).toEqual({ title: 'New Hosts', enabled: true, checked: true });
    expect(describe(ref('view.scope', 'favorites'), ctx).title).toBe('Favorite Hosts');
    expect(describe(ref('view.infoPane'), ctx).title).toBe('Show Host Information');
    expect(describe(ref('view.infoPane'), context()).title).toBe('Hide Host Information');
    expect(describe(ref('view.zoom'), ctx)).toEqual({ title: 'Zoom Window', enabled: false });
    expect(describe(ref('view.zoom'), context()).enabled).toBe(true);
    expect(describe(ref('view.collapse'), ctx)).toEqual({ title: 'Expand Window', enabled: true });
    expect(describe(ref('view.collapse'), context()).title).toBe('Collapse Window');
    expect(describe(ref('help.balloons'), ctx).title).toBe('Hide Balloons');
    expect(describe(ref('help.balloons'), context()).title).toBe('Show Balloons');
  });

  it('enables Show Hidden Hosts while some host is hidden or it is on', () => {
    expect(describe(ref('view.showHidden'), context())).toEqual({
      title: 'Show Hidden Hosts',
      enabled: false,
      checked: false
    });
    expect(describe(ref('view.showHidden'), context({ model: { hiddenCount: 2 } })).enabled).toBe(true);
    // On with nothing hidden: stays enabled so it can be turned off.
    expect(describe(ref('view.showHidden'), context({ store: { showHiddenEntries: true } }))).toEqual({
      title: 'Show Hidden Hosts',
      enabled: true,
      checked: true
    });
  });

  it('titles Help by place', () => {
    expect(describe(ref('help.help'), context())).toEqual({ title: 'Lantenna Help', enabled: true });
    expect(describe(ref('help.help'), context(), 'contextual')).toEqual({ title: 'Help', enabled: true });
  });

  it('dims every command while an alert is up', () => {
    const r = row(printer, { customName: 'Office Printer', favorite: true });
    const live = selecting(r, {
      focus: 'text',
      store: { favoriteIps: [r.ip], showHiddenEntries: true },
      model: { hiddenCount: 1 }
    });
    const modal = { ...live, modal: true };
    const refs = allRefs(live);
    expect(refs.filter((c) => describe(c, live).enabled).length).toBeGreaterThan(30);
    for (const c of refs) {
      expect(describe(c, modal).enabled, `${c.id} ${c.arg ?? ''}`).toBe(false);
      expect(describe(c, modal).title).toBe(describe(c, live).title);
    }
  });
});

group('menu specs', () => {
  const r = row(printer, { customName: 'Office Printer', favorite: true });
  const ctx = selecting(r, {
    store: {
      interfaces: [EN0, EN7],
      favoriteIps: ['192.168.1.5', '192.168.1.9', '192.168.1.31', '10.0.0.2', '192.168.1.200'],
      hosts: [printer, host('192.168.1.9', { name: 'zeta' }), host('192.168.1.200', { name: 'Alpha' })],
      customNames: { '192.168.1.31': 'Office Printer', '10.0.0.2': 'nas' }
    },
    focus: 'list'
  });

  it('builds the Linux menu bar of 4.3', () => {
    const menus = menuBarSpec(ctx);
    expect(menus.map((m) => [m.id, m.title, m.icon ?? null])).toEqual([
      ['app', 'Lantenna', 'lan-antenna'],
      ['file', 'File', null],
      ['edit', 'Edit', null],
      ['scan', 'Scan', null],
      ['host', 'Host', null],
      ['favorites', 'Favorites', null],
      ['view', 'View', null],
      ['help', 'Help', null]
    ]);
    expect(Object.fromEntries(menus.map((m) => [m.title, dump(m.entries, ctx)]))).toEqual({
      Lantenna: ['About Lantenna…', '-', 'Check for Updates…'],
      File: ['Close Window ⌘W', '-', 'Quit ⌘Q'],
      Edit: [
        '[Undo] ⌘Z',
        '-',
        '[Cut] ⌘X',
        'Copy ⌘C',
        '[Paste] ⌘V',
        '[Select All] ⌘A',
        '-',
        'Copy IP Address',
        'Copy Host Name',
        'Copy Detected Name',
        'Copy MAC Address',
        'Copy Host List',
        '-',
        'Find ⌘F'
      ],
      Scan: [
        'Scan Network ⌘R',
        '-',
        'en0 (192.168.1.0/24) ✓',
        'en7 (10.0.0.0/16)',
        '-',
        'Fast',
        'Balanced ✓',
        'Thorough'
      ],
      Host: [
        'Open ⌘O',
        'http://192.168.1.31',
        'smb://192.168.1.31',
        'Get Info ⌘I',
        '-',
        'Rename…',
        'Clear Custom Name',
        'Hide Host',
        '-',
        'Deep Scan ⌘D',
        'Wake'
      ],
      // Sorted by name, then IP; unnamed last.
      Favorites: [
        'Remove “Office Printer” from Favorites',
        '-',
        'Alpha (192.168.1.200)',
        'nas (10.0.0.2)',
        'Office Printer (192.168.1.31)',
        'zeta (192.168.1.9)',
        '192.168.1.5'
      ],
      View: [
        'as List ✓',
        'as Icons',
        '-',
        'All Hosts ✓',
        'Favorite Hosts',
        'New Hosts',
        '-',
        '[Show Hidden Hosts]',
        '-',
        'Hide Host Information',
        '-',
        'Zoom Window',
        'Collapse Window'
      ],
      Help: ['Show Balloons', '-', 'Lantenna Help']
    });
  });

  it('builds the macOS menu bar of 4.2 with its predefined items', () => {
    const mac = { ...ctx, platform: 'mac' as const };
    const menus = menuBarSpec(mac);
    const titles = ['Lantenna', 'File', 'Edit', 'Scan', 'Host', 'Favorites', 'View', 'Help'];
    expect(menus.map((m) => m.title)).toEqual(titles);
    expect(menus[0]!.icon).toBeUndefined();
    expect(dump(menus[0]!.entries, mac)).toEqual([
      'About Lantenna…',
      '-',
      'Check for Updates…',
      '-',
      '<services>',
      '-',
      '<hide>',
      '<hideOthers>',
      '<showAll>',
      '-',
      '<quit>'
    ]);
    expect(dump(menus[1]!.entries, mac)).toEqual(['Close Window ⌘W']);
    expect(dump(menus[2]!.entries, mac)).toEqual([
      '<undo>',
      '<redo>',
      '-',
      '<cut>',
      '<copy>',
      '<paste>',
      '<selectAll>',
      '-',
      'Copy IP Address',
      'Copy Host Name',
      'Copy Detected Name',
      'Copy MAC Address',
      'Copy Host List',
      '-',
      'Find ⌘F'
    ]);
    // Scan, Host, Favorites, View and Help are the same on both.
    expect(menus.slice(3)).toEqual(menuBarSpec(ctx).slice(3));
  });

  it('lists target URLs only for a host with two or more', () => {
    const one = selecting(row(host('192.168.1.40', { ports: [22] })));
    expect(dump(menuBarSpec(one)[4]!.entries, one).slice(0, 2)).toEqual(['Open ⌘O', 'Get Info ⌘I']);
    expect(dump(hostMenuSpec(one), one, 'contextual').slice(2, 4)).toEqual(['Open ⌘O', 'Get Info ⌘I']);
    const none = context();
    expect(dump(menuBarSpec(none)[4]!.entries, none).slice(0, 2)).toEqual(['[Open] ⌘O', '[Get Info] ⌘I']);
    expect(dump(menuBarSpec(none)[5]!.entries, none)).toEqual(['[Add to Favorites]']);
  });

  it('builds the host contextual menu of 4.4', () => {
    expect(dump(hostMenuSpec(ctx), ctx, 'contextual')).toEqual([
      'Help',
      '-',
      'Open ⌘O',
      'http://192.168.1.31',
      'smb://192.168.1.31',
      'Get Info ⌘I',
      '-',
      'Copy IP Address',
      'Copy Host Name',
      'Copy MAC Address',
      '-',
      'Remove from Favorites',
      'Rename…',
      'Clear Custom Name',
      'Hide Host',
      '-',
      'Deep Scan ⌘D',
      'Wake'
    ]);
  });

  it('builds the empty-space contextual menu of 4.4', () => {
    expect(dump(viewMenuSpec(ctx), ctx, 'contextual')).toEqual([
      'Help',
      '-',
      'Scan Network ⌘R',
      '-',
      'as List ✓',
      'as Icons',
      '-',
      'All Hosts ✓',
      'Favorite Hosts',
      'New Hosts',
      '[Show Hidden Hosts]'
    ]);
    const scanning = context({ store: { scanning: true } });
    expect(dump(viewMenuSpec(scanning), scanning, 'contextual')[2]).toBe('Stop Scan ⌘.');
  });
});

group('osmiumMenuEntries', () => {
  const r = row(printer);

  it('dims items without an action, draws keys and marks, drops predefined items', () => {
    const ctx = selecting(r, { focus: 'list' });
    const entries = osmiumMenuEntries(
      [
        { id: 'host.open' },
        'separator',
        { predefined: 'quit' },
        { id: 'host.clearName' },
        { id: 'view.mode', arg: 'list' }
      ],
      ctx,
      'menubar'
    );
    expect(entries).toHaveLength(4);
    expect(entries[0]).toEqual({ title: 'Open', key: 'O', action: expect.any(Function) });
    expect(entries[1]).toBe(MENU_SEPARATOR);
    expect(entries[2]).toEqual({ title: 'Clear Custom Name' });
    expect(entries[3]).toEqual({ title: 'as List', checked: true, action: expect.any(Function) });
  });

  it('leaves keys out of contextual menus', () => {
    const [open] = osmiumMenuEntries([{ id: 'host.open' }], selecting(r), 'contextual');
    expect(open).toEqual({ title: 'Open', action: expect.any(Function) });
  });

  it('leaves text-editing keys to the browser while text has the keyboard', () => {
    const edits: SpecEntry[] = [{ id: 'edit.undo' }, { id: 'edit.copy' }, { id: 'edit.copyIp' }];
    const inText = osmiumMenuEntries(edits, selecting(r, { focus: 'text' }), 'menubar');
    expect(inText.map((e) => (e === MENU_SEPARATOR ? null : e.keyDispatch))).toEqual(['browser', 'browser', undefined]);
    const inList = osmiumMenuEntries(edits, selecting(r, { focus: 'list' }), 'menubar');
    expect(inList.map((e) => (e === MENU_SEPARATOR ? null : e.keyDispatch))).toEqual([undefined, undefined, undefined]);
  });

  it('draws Show Balloons with Osmium’s own item', () => {
    const [item] = osmiumMenuEntries([{ id: 'help.balloons' }], context(), 'menubar');
    expect(item).toMatchObject({ title: 'Show Balloons' });
    (item as { action: () => void }).action();
    expect(balloonHelp()).toBe('shown');

    const [dimmed] = osmiumMenuEntries([{ id: 'help.balloons' }], context({ modal: true }), 'menubar');
    expect(dimmed).toEqual({ title: 'Show Balloons' });
  });
});
