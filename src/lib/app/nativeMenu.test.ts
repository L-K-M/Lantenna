// The macOS native menu against a mocked @tauri-apps/api/menu: the tree
// of 4.2, patching vs rebuilding, re-asserted check marks, failures.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Writable } from 'svelte/store';
import type { CommandContext } from './commands';

const tauri = vi.hoisted(() => {
  const log: string[] = [];
  const state: {
    appMenu: unknown;
    helpMenu: unknown;
    failNew: boolean;
    /** Submenu.new fails once this many submenus exist (null: never). */
    failSubmenuAfter: number | null;
    made: { closed: boolean }[];
  } = {
    appMenu: null,
    helpMenu: null,
    failNew: false,
    failSubmenuAfter: null,
    made: []
  };
  let rid = 1;
  /** What muda shows for a title passed to MenuItem.new, Submenu.new
   * and setText: a single '&' is a mnemonic marker, '&&' is '&'. */
  const shown = (text: string) => text.replaceAll('&&', '\0').replaceAll('&', '').replaceAll('\0', '&');

  class Base {
    readonly rid = rid++;
    closed = false;
    text = '';
    constructor() {
      state.made.push(this);
    }
    async close() {
      this.closed = true;
    }
  }

  class MenuItem extends Base {
    enabled = true;
    accelerator: string | null = null;
    action: (() => void) | undefined;
    static async new(o: { text: string; enabled?: boolean; accelerator?: string; action?: () => void }) {
      const item = new this();
      item.init(o);
      return item;
    }
    init(o: { text: string; enabled?: boolean; accelerator?: string; action?: () => void }) {
      this.text = shown(o.text);
      this.enabled = o.enabled ?? true;
      this.accelerator = o.accelerator ?? null;
      this.action = o.action;
    }
    async setText(text: string) {
      log.push(`text ${this.text} -> ${shown(text)}`);
      this.text = shown(text);
    }
    async setEnabled(enabled: boolean) {
      log.push(`enabled ${this.text} -> ${enabled}`);
      this.enabled = enabled;
    }
    async setAccelerator(accelerator: string | null) {
      log.push(`accelerator ${this.text} -> ${accelerator}`);
      this.accelerator = accelerator;
    }
  }

  class CheckMenuItem extends MenuItem {
    checked = false;
    static override async new(o: { text: string; enabled?: boolean; checked?: boolean; action?: () => void }) {
      const item = new this();
      item.init(o);
      // muda makes a check item with its text as given.
      item.text = o.text;
      item.checked = o.checked ?? false;
      return item;
    }
    async setChecked(checked: boolean) {
      log.push(`checked ${this.text} -> ${checked}`);
      this.checked = checked;
    }
  }

  class PredefinedMenuItem extends Base {
    item = '';
    static async new(o: { item: string; text?: string }) {
      const p = new PredefinedMenuItem();
      p.item = o.item;
      p.text = o.text ?? (o.item === 'Separator' ? '-' : o.item);
      return p;
    }
  }

  class Submenu extends Base {
    items: Base[] = [];
    static async new(o: { text: string; items: Base[] }) {
      if (state.failNew) throw new Error('menu new: not allowed');
      const submenus = state.made.filter((m) => m instanceof Submenu).length;
      if (state.failSubmenuAfter !== null && submenus >= state.failSubmenuAfter) throw new Error('menu new: out of memory');
      const s = new Submenu();
      s.text = shown(o.text);
      s.items = [...o.items];
      return s;
    }
    async remove(item: Base) {
      log.push(`remove ${this.text}: ${item.text}`);
      // As muda does.
      if (!this.items.includes(item)) throw new Error('NotAChildOfThisMenu');
      this.items = this.items.filter((i) => i !== item);
    }
    async append(items: Base | Base[]) {
      const list = Array.isArray(items) ? items : [items];
      log.push(`append ${this.text}: ${list.map((i) => i.text).join(', ')}`);
      this.items.push(...list);
    }
    async setText(text: string) {
      this.text = shown(text);
    }
    async setAsHelpMenuForNSApp() {
      state.helpMenu = this;
    }
  }

  class Menu extends Base {
    items: Submenu[] = [];
    static async new(o: { items: Submenu[] }) {
      const m = new Menu();
      m.items = o.items;
      return m;
    }
    async setAsAppMenu() {
      state.appMenu = this;
      return null;
    }
  }

  return { log, state, MenuItem, CheckMenuItem, PredefinedMenuItem, Submenu, Menu };
});

vi.mock('@tauri-apps/api/menu', () => ({
  Menu: tauri.Menu,
  Submenu: tauri.Submenu,
  MenuItem: tauri.MenuItem,
  CheckMenuItem: tauri.CheckMenuItem,
  PredefinedMenuItem: tauri.PredefinedMenuItem
}));

vi.mock('./commands', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./commands')>();
  const { writable } = await import('svelte/store');
  const { context } = await import('./commands.fixture');
  return { ...actual, commandContext: writable(context({ platform: 'mac' })), run: vi.fn() };
});

const commands = await import('./commands');
const { openViewMenu } = await import('./contextMenus');
const { installNativeMenu } = await import('./nativeMenu');
const { EN0, EN7, context, host, row, selecting } = await import('./commands.fixture');

const ctxStore = commands.commandContext as Writable<CommandContext>;
type Menu = InstanceType<typeof tauri.Menu>;
type Submenu = InstanceType<typeof tauri.Submenu>;
type Item = InstanceType<typeof tauri.MenuItem> & { checked?: boolean; item?: string };

const macContext = (parts: Parameters<typeof context>[0] = {}) => context({ platform: 'mac', ...parts });

/** Let a scheduled frame run its pass to the end. */
async function settle() {
  for (let i = 0; i < 3; i++) {
    await new Promise((resolve) => requestAnimationFrame(() => resolve(null)));
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

function appMenu(): Menu {
  return tauri.state.appMenu as Menu;
}

function submenu(title: string): Submenu {
  return appMenu().items.find((s) => s.text === title)!;
}

function item(menu: string, text: string): Item {
  return submenu(menu).items.find((i) => i.text === text) as Item;
}

/** A submenu as text: '[x]' dimmed, '✓' checked, accelerators after. */
function dump(s: Submenu): string[] {
  return (s.items as Item[]).map((i) => {
    if (i instanceof tauri.PredefinedMenuItem) return i.item === 'Separator' ? '-' : `<${i.text}>`;
    const text = i.enabled ? i.text : `[${i.text}]`;
    return `${text}${i.checked ? ' ✓' : ''}${i.accelerator ? ` ${i.accelerator}` : ''}`;
  });
}

let dispose: () => void = () => {};
let warn: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  tauri.log.length = 0;
  tauri.state.appMenu = null;
  tauri.state.helpMenu = null;
  tauri.state.failNew = false;
  tauri.state.failSubmenuAfter = null;
  tauri.state.made.length = 0;
  vi.mocked(commands.run).mockClear();
  ctxStore.set(macContext());
  warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  dispose();
  warn.mockRestore();
});

async function install() {
  dispose = installNativeMenu();
  await vi.waitFor(() => expect(tauri.state.appMenu).not.toBeNull());
  await settle();
}

it('builds the Mac OS 8 menu bar of 4.2 and sets it as the app menu', async () => {
  const r = row(host('192.168.1.31', { name: 'printer.local', ports: [80], mac: '30:05:5C:12:34:56' }));
  ctxStore.set(selecting(r, { platform: 'mac', store: { interfaces: [EN0, EN7] } }));
  await install();

  expect(appMenu().items.map((s) => s.text)).toEqual([
    'Lantenna',
    'File',
    'Edit',
    'Scan',
    'Host',
    'Favorites',
    'View',
    'Help'
  ]);
  expect(tauri.state.helpMenu).toBe(submenu('Help'));
  expect(Object.fromEntries(appMenu().items.map((s) => [s.text, dump(s)]))).toEqual({
    Lantenna: [
      'About Lantenna…',
      '-',
      'Check for Updates…',
      '-',
      '<Services>',
      '-',
      '<Hide Lantenna>',
      '<Hide Others>',
      '<Show All>',
      '-',
      '<Quit Lantenna>'
    ],
    File: ['Close Window CmdOrCtrl+W'],
    Edit: [
      '<Undo>',
      '<Redo>',
      '-',
      '<Cut>',
      '<Copy>',
      '<Paste>',
      '<Select All>',
      '-',
      'Copy IP Address',
      'Copy Host Name',
      'Copy Detected Name',
      'Copy MAC Address',
      'Copy Host List',
      '-',
      'Find CmdOrCtrl+F'
    ],
    Scan: [
      'Scan Network CmdOrCtrl+R',
      '-',
      'en0 (192.168.1.0/24) ✓',
      'en7 (10.0.0.0/16)',
      '-',
      'Fast',
      'Balanced ✓',
      'Thorough'
    ],
    Host: [
      'Open CmdOrCtrl+O',
      'Get Info CmdOrCtrl+I',
      '-',
      'Rename…',
      '[Clear Custom Name]',
      'Hide Host',
      '-',
      'Deep Scan CmdOrCtrl+D',
      'Wake'
    ],
    Favorites: ['Add “printer.local” to Favorites'],
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
  // Check marks are CheckMenuItems; everything else plain.
  expect(item('Scan', 'Fast')).toBeInstanceOf(tauri.CheckMenuItem);
  expect(item('View', 'Show Hidden Hosts')).toBeInstanceOf(tauri.CheckMenuItem);
  expect(item('Scan', 'Scan Network')).not.toBeInstanceOf(tauri.CheckMenuItem);
});

it('patches only what changed, once per frame', async () => {
  await install();
  tauri.log.length = 0;

  ctxStore.set(macContext({ store: { scanning: true } }));
  ctxStore.set(macContext({ store: { scanning: true, stopping: false } }));
  await settle();

  expect(tauri.log.sort()).toEqual(
    [
      'text Scan Network -> Stop Scan',
      'accelerator Stop Scan -> CmdOrCtrl+.',
      'enabled en0 (192.168.1.0/24) -> false',
      'enabled Fast -> false',
      'enabled Balanced -> false',
      'enabled Thorough -> false'
    ].sort()
  );

  tauri.log.length = 0;
  ctxStore.set(macContext({ store: { scanning: true, stopping: true } }));
  await settle();
  expect(tauri.log).toEqual(['text Stop Scan -> Stopping…', 'enabled Stopping… -> false']);
});

it('rebuilds a submenu when its structure changes, and only that one', async () => {
  await install();
  const oldItems = [...submenu('Favorites').items];
  tauri.log.length = 0;

  ctxStore.set(
    macContext({
      store: { favoriteIps: ['192.168.1.31'], hosts: [host('192.168.1.31', { name: 'printer.local' })] }
    })
  );
  await settle();

  expect(tauri.log).toEqual([
    'remove Favorites: Add to Favorites',
    'append Favorites: Add to Favorites',
    'append Favorites: -',
    'append Favorites: printer.local (192.168.1.31)'
  ]);
  expect(oldItems.every((i) => i.closed)).toBe(true);
  expect(dump(submenu('Favorites'))).toEqual(['[Add to Favorites]', '-', 'printer.local (192.168.1.31)']);

  // A new name for the same favorite is a patch, not a rebuild.
  tauri.log.length = 0;
  ctxStore.set(
    macContext({
      store: {
        favoriteIps: ['192.168.1.31'],
        hosts: [host('192.168.1.31', { name: 'printer.local' })],
        customNames: { '192.168.1.31': 'Office Printer' }
      }
    })
  );
  await settle();
  expect(tauri.log).toEqual(['text printer.local (192.168.1.31) -> Office Printer (192.168.1.31)']);
});

it('shows an ampersand in a host’s name, which muda would read as a mnemonic', async () => {
  const gateway = host('192.168.1.1', { name: 'AT&T Gateway' });
  const store = { favoriteIps: ['192.168.1.1'], hosts: [gateway] };
  ctxStore.set(selecting(row(gateway, { favorite: true }), { platform: 'mac', store }));
  await install();
  expect(dump(submenu('Favorites'))).toEqual([
    'Remove “AT&T Gateway” from Favorites',
    '-',
    'AT&T Gateway (192.168.1.1)'
  ]);

  // Renamed: setText.
  const renamed = { ...store, customNames: { '192.168.1.1': 'Tom & Jerry && Co' } };
  ctxStore.set(selecting(row(gateway, { favorite: true, customName: 'Tom & Jerry && Co' }), { platform: 'mac', store: renamed }));
  await settle();
  expect(dump(submenu('Favorites'))).toEqual([
    'Remove “Tom & Jerry && Co” from Favorites',
    '-',
    'Tom & Jerry && Co (192.168.1.1)'
  ]);

  // The item still runs its command: the page compares plain titles.
  item('Favorites', 'Tom & Jerry && Co (192.168.1.1)').action!();
  expect(commands.run).toHaveBeenCalledWith({ id: 'fav.reveal', arg: '192.168.1.1' });
});

it('runs the command of a chosen item', async () => {
  await install();
  item('File', 'Close Window').action!();
  expect(commands.run).toHaveBeenCalledWith({ id: 'file.close' });
});

it('puts back a check mark muda toggled on click', async () => {
  await install();
  const balanced = item('Scan', 'Balanced');
  tauri.log.length = 0;

  // muda unchecks the checked item it was clicked on; the depth stays.
  balanced.checked = false;
  balanced.action!();
  expect(commands.run).toHaveBeenCalledWith({ id: 'scan.depth', arg: 'balanced' });
  await settle();

  expect(tauri.log).toEqual(['checked Balanced -> true']);
  expect(balanced.checked).toBe(true);
});

it('logs a failed update and tries again on the next pass', async () => {
  await install();
  const scan = item('Scan', 'Scan Network');
  const setText = vi.spyOn(scan, 'setText').mockRejectedValueOnce('menu set_text failed');

  ctxStore.set(macContext({ store: { scanning: true } }));
  await settle();
  expect(warn).toHaveBeenCalledWith('Lantenna couldn’t update the menu bar:', 'menu set_text failed');
  expect(scan.text).toBe('Scan Network');

  ctxStore.set(macContext({ store: { scanning: true, query: 'x' } }));
  await settle();
  expect(setText).toHaveBeenCalledTimes(2);
  expect(scan.text).toBe('Stop Scan');
});

it('keeps the default menu when the menu can’t be built', async () => {
  tauri.state.failNew = true;
  dispose = installNativeMenu();
  await vi.waitFor(() =>
    expect(warn).toHaveBeenCalledWith('Lantenna couldn’t build the menu bar:', expect.any(Error))
  );

  tauri.state.failNew = false;
  ctxStore.set(macContext({ store: { scanning: true } }));
  await settle();
  expect(tauri.state.appMenu).toBeNull();
  expect(warn).toHaveBeenCalledOnce();
});

it('releases what a first build made before it failed', async () => {
  // Three menus built, the fourth's submenu refused.
  tauri.state.failSubmenuAfter = 3;
  dispose = installNativeMenu();
  await vi.waitFor(() =>
    expect(warn).toHaveBeenCalledWith('Lantenna couldn’t build the menu bar:', expect.any(Error))
  );
  await settle();

  expect(tauri.state.made.length).toBeGreaterThan(3);
  expect(tauri.state.made.filter((h) => !h.closed)).toEqual([]);
  expect(tauri.state.appMenu).toBeNull();
});

it('stops syncing and ignores items once disposed', async () => {
  await install();
  dispose();
  tauri.log.length = 0;

  ctxStore.set(macContext({ store: { scanning: true } }));
  await settle();
  item('File', 'Close Window').action!();

  expect(tauri.log).toEqual([]);
  expect(commands.run).not.toHaveBeenCalled();
});

it('does nothing for an item chosen after its meaning changed', async () => {
  ctxStore.set(macContext({ store: { scanning: true } }));
  await install();
  expect(item('Scan', 'Stop Scan')).toBeDefined();

  // The scan ends before the next pass retitles the item.
  ctxStore.set(macContext());
  item('Scan', 'Stop Scan').action!();
  expect(commands.run).not.toHaveBeenCalled();
});

it('syncs without animation frames, as while the window is minimized', async () => {
  await install();
  const raf = vi.spyOn(window, 'requestAnimationFrame').mockReturnValue(1);
  try {
    ctxStore.set(macContext({ store: { scanning: true } }));
    await vi.waitFor(() => expect(item('Scan', 'Stop Scan')).toBeDefined(), { timeout: 1000 });
    expect(raf).toHaveBeenCalled();
  } finally {
    raf.mockRestore();
  }
});

it('draws “No interfaces found” as a plain dimmed item, with no check mark', async () => {
  ctxStore.set(macContext({ store: { interfaces: [], selectedInterface: null } }));
  await install();

  const none = item('Scan', 'No interfaces found');
  expect(none).not.toBeInstanceOf(tauri.CheckMenuItem);
  expect(none.enabled).toBe(false);
});

it('closes an open contextual menu before running a command', async () => {
  await install();
  openViewMenu({ x: 40, y: 60 });
  expect(document.querySelector('.osm-contextmenu')).not.toBeNull();

  item('Edit', 'Find').action!();
  expect(document.querySelector('.osm-contextmenu')).toBeNull();
  expect(commands.run).toHaveBeenCalledWith({ id: 'edit.find' });
});

it('finishes a rebuild that failed part way on the next pass, releasing what it made', async () => {
  const favorites = (ips: string[]) =>
    macContext({
      store: { favoriteIps: ips, hosts: ips.map((ip) => host(ip, { name: `h${ip.slice(-1)}.local` })) }
    });
  ctxStore.set(favorites(['10.0.0.1', '10.0.0.2']));
  await install();
  const menu = submenu('Favorites');
  const before = [...menu.items];

  // The second removal fails: three old items stay, the new ones go.
  const create = vi.spyOn(tauri.MenuItem, 'new');
  const remove = vi.spyOn(menu, 'remove');
  remove.mockImplementationOnce(tauri.Submenu.prototype.remove).mockRejectedValueOnce('menu remove failed');
  ctxStore.set(favorites(['10.0.0.1']));
  await settle();
  expect(warn).toHaveBeenCalledWith('Lantenna couldn’t rebuild the menu bar:', 'menu remove failed');
  const made = await Promise.all(create.mock.results.map((r) => r.value as Promise<Item>));
  create.mockRestore();
  expect(made.length).toBeGreaterThan(0);
  expect(made.every((i) => i.closed)).toBe(true);

  // Any next pass completes it, even back to the old structure's twin.
  ctxStore.set(favorites(['10.0.0.1', '10.0.0.2']));
  await settle();
  expect(dump(menu)).toEqual(['[Add to Favorites]', '-', 'h1.local (10.0.0.1)', 'h2.local (10.0.0.2)']);
  expect(before.every((i) => i.closed)).toBe(true);
  expect(menu.items.some((i) => i.closed)).toBe(false);
  expect(warn).toHaveBeenCalledOnce();
});

it('releases every menu handle when disposed', async () => {
  await install();
  const tree = appMenu();
  const handles = [tree, ...tree.items, ...tree.items.flatMap((s) => s.items)];

  dispose();
  dispose = () => {};
  await settle();
  expect(handles.filter((h) => !h.closed)).toEqual([]);
});
