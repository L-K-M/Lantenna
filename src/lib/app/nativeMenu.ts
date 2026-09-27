// Owner: unit E (spec 8.4). Spec: 4.2 (macOS native menu bar and Sync).
//
// The macOS menu bar, built in the page with @tauri-apps/api/menu in
// Mac OS 8's structure (menuBarSpec) and set as the app menu, its Help
// menu as NSApp's help menu. Item actions run in the page and call
// run(), which re-checks the command, so a click on an item the page
// has already dimmed does nothing.
//
// Sync: every commandContext change asks for one pass per animation
// frame, or after FALLBACK_MS (web views stop animation frames while
// the page is hidden, a minimized window say, and the menu bar stays
// usable then). A pass patches items whose title, enabled state, check
// mark or accelerator changed, and rebuilds a submenu's items only when
// its structure changed (interfaces, target URLs, favorites). muda
// toggles a check item's mark itself on click, so after a check item's
// action its mark is set from the model again. An item whose title no
// longer matches the state (Stop Scan chosen just as the scan ended)
// does nothing, rather than what its new title says. Every call is
// async IPC; a failure is logged and retried on the next pass, never
// shown.
//
// Called by +page.svelte on macOS only, after mount (never at import:
// the mock backend may be installed after this module loads).

import { get } from 'svelte/store';
import {
  CheckMenuItem,
  Menu,
  MenuItem,
  PredefinedMenuItem,
  Submenu,
  type PredefinedMenuItemOptions
} from '@tauri-apps/api/menu';
import {
  commandContext,
  describe,
  menuBarSpec,
  run,
  type CommandContext,
  type CommandId,
  type CommandInfo,
  type CommandRef,
  type MenuSpec,
  type PredefinedItem,
  type SpecEntry
} from './commands';

type NativeItem = MenuItem | CheckMenuItem | PredefinedMenuItem;

/** The longest a change waits for its pass when no frame comes. */
const FALLBACK_MS = 250;

/** Commands drawn with a check mark, built as CheckMenuItem (an item's
 * kind can't change once built). */
const CHECK_IDS: ReadonlySet<CommandId> = new Set([
  'scan.interface',
  'scan.depth',
  'view.mode',
  'view.scope',
  'view.showHidden'
]);

/** Titles are given so they don't depend on muda's defaults. */
const PREDEFINED: Readonly<Record<PredefinedItem, PredefinedMenuItemOptions>> = {
  services: { item: 'Services', text: 'Services' },
  hide: { item: 'Hide', text: 'Hide Lantenna' },
  hideOthers: { item: 'HideOthers', text: 'Hide Others' },
  showAll: { item: 'ShowAll', text: 'Show All' },
  quit: { item: 'Quit', text: 'Quit Lantenna' },
  undo: { item: 'Undo', text: 'Undo' },
  redo: { item: 'Redo', text: 'Redo' },
  cut: { item: 'Cut', text: 'Cut' },
  copy: { item: 'Copy', text: 'Copy' },
  paste: { item: 'Paste', text: 'Paste' },
  selectAll: { item: 'SelectAll', text: 'Select All' }
};

/** What an item currently shows; a field is undefined when unknown (a
 * check mark muda just toggled), so the next pass sets it. */
interface Applied {
  title?: string;
  enabled?: boolean;
  checked?: boolean;
  accelerator?: string | null;
}

interface ItemRecord {
  /** null for separators and predefined items, which never change. */
  readonly ref: CommandRef | null;
  readonly handle: NativeItem;
  readonly applied: Applied;
}

interface SubmenuRecord {
  readonly submenu: Submenu;
  title: string;
  structure: string;
  items: ItemRecord[];
}

function accelerator(key: string | undefined): string | null {
  return key === undefined ? null : `CmdOrCtrl+${key}`;
}

/** Entries with the same structure keep their items; anything else
 * (another interface, target or favorite) rebuilds the submenu. */
function structureOf(entries: readonly SpecEntry[]): string {
  const key = (e: SpecEntry) =>
    e === 'separator' ? e : 'predefined' in e ? `predefined:${e.predefined}` : [e.id, e.arg ?? null];
  return JSON.stringify(entries.map(key));
}

function warn(what: string) {
  return (error: unknown) => console.warn(`Lantenna couldn’t ${what}:`, error);
}

/** Build the menu bar, keep it in sync; returns the disposer. */
export function installNativeMenu(): () => void {
  let disposed = false;
  let failed = false;
  let frame = 0;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let busy = false;
  let again = false;
  let submenus: Map<string, SubmenuRecord> | null = null;

  function onAction(record: ItemRecord): void {
    if (disposed || record.ref === null) return;

    // Act on what the item said when it was chosen, or not at all.
    if (describe(record.ref, get(commandContext)).title === record.applied.title) run(record.ref);
    if (record.handle instanceof CheckMenuItem) {
      // muda toggled the mark; put the model's back.
      record.applied.checked = undefined;
      schedule();
    }
  }

  async function createItem(entry: SpecEntry, ctx: CommandContext): Promise<ItemRecord> {
    if (entry === 'separator') {
      return { ref: null, handle: await PredefinedMenuItem.new({ item: 'Separator' }), applied: {} };
    }

    if ('predefined' in entry) {
      return { ref: null, handle: await PredefinedMenuItem.new({ ...PREDEFINED[entry.predefined] }), applied: {} };
    }

    const info = describe(entry, ctx);
    const applied: Applied = { title: info.title, enabled: info.enabled };
    // The record exists before its handle, for the action's closure.
    let record: ItemRecord | null = null;
    const action = () => {
      if (record) onAction(record);
    };

    let handle: NativeItem;
    if (CHECK_IDS.has(entry.id)) {
      applied.checked = info.checked ?? false;
      handle = await CheckMenuItem.new({ text: info.title, enabled: info.enabled, checked: applied.checked, action });
    } else {
      applied.accelerator = accelerator(info.key);
      handle = await MenuItem.new({
        text: info.title,
        enabled: info.enabled,
        ...(applied.accelerator === null ? {} : { accelerator: applied.accelerator }),
        action
      });
    }

    record = { ref: entry, handle, applied };
    return record;
  }

  function createItems(spec: MenuSpec, ctx: CommandContext): Promise<ItemRecord[]> {
    return Promise.all(spec.entries.map((entry) => createItem(entry, ctx)));
  }

  async function build(ctx: CommandContext): Promise<Map<string, SubmenuRecord>> {
    const records = new Map<string, SubmenuRecord>();

    for (const spec of menuBarSpec(ctx)) {
      const items = await createItems(spec, ctx);
      const submenu = await Submenu.new({ text: spec.title, items: items.map((i) => i.handle) });
      records.set(spec.id, { submenu, title: spec.title, structure: structureOf(spec.entries), items });
    }

    const menu = await Menu.new({ items: [...records.values()].map((r) => r.submenu) });
    if (disposed) return records;

    await menu.setAsAppMenu();
    // macOS adds its Help search field to this menu.
    await records.get('help')?.submenu.setAsHelpMenuForNSApp().catch(warn('set the Help menu'));
    return records;
  }

  /** Set only what changed; each call's failure leaves its field
   * unapplied, so the next pass tries again. */
  function patchItem(record: ItemRecord, info: CommandInfo): Promise<unknown>[] {
    const { handle, applied } = record;
    if (handle instanceof PredefinedMenuItem) return [];

    const calls: Promise<unknown>[] = [];
    const set = <K extends keyof Applied>(field: K, value: Applied[K], call: () => Promise<void>) => {
      if (applied[field] === value) return;
      calls.push(
        call().then(
          () => {
            applied[field] = value;
          },
          warn('update the menu bar')
        )
      );
    };

    set('title', info.title, () => handle.setText(info.title));
    set('enabled', info.enabled, () => handle.setEnabled(info.enabled));
    if (handle instanceof CheckMenuItem) {
      const checked = info.checked ?? false;
      set('checked', checked, () => handle.setChecked(checked));
    } else {
      const key = accelerator(info.key);
      set('accelerator', key, () => handle.setAccelerator(key));
    }
    return calls;
  }

  async function rebuild(record: SubmenuRecord, spec: MenuSpec, ctx: CommandContext): Promise<void> {
    const items = await createItems(spec, ctx);
    const old = record.items;

    for (const item of old) await record.submenu.remove(item.handle);
    await record.submenu.append(items.map((i) => i.handle));
    record.items = items;
    record.structure = structureOf(spec.entries);

    await Promise.all(old.map((item) => item.handle.close().catch(warn('release a menu item'))));
  }

  async function sync(records: Map<string, SubmenuRecord>, ctx: CommandContext): Promise<void> {
    for (const spec of menuBarSpec(ctx)) {
      const record = records.get(spec.id);
      if (!record) continue; // the menus themselves never change

      if (record.title !== spec.title) {
        const title = spec.title;
        await record.submenu.setText(title).then(() => {
          record.title = title;
        }, warn('update the menu bar'));
      }

      if (structureOf(spec.entries) !== record.structure) {
        await rebuild(record, spec, ctx).catch(warn('rebuild the menu bar'));
        continue;
      }

      await Promise.all(
        record.items.flatMap((item) => (item.ref === null ? [] : patchItem(item, describe(item.ref, ctx))))
      );
    }
  }

  /** One pass at a time; changes during a pass run another. */
  async function flush(): Promise<void> {
    if (busy) {
      again = true;
      return;
    }

    busy = true;
    try {
      do {
        again = false;
        const ctx = get(commandContext);
        if (submenus === null) submenus = await build(ctx);
        else await sync(submenus, ctx);
      } while (again && !disposed);
    } catch (error) {
      // Only the first build can get here (sync logs per call): the
      // default menu stays, and nothing is retried.
      failed = true;
      warn('build the menu bar')(error);
    } finally {
      busy = false;
    }
  }

  function cancel(): void {
    if (frame !== 0) cancelAnimationFrame(frame);
    if (timer !== null) clearTimeout(timer);
    frame = 0;
    timer = null;
  }

  function schedule(): void {
    if (disposed || failed || timer !== null) return;
    const pass = () => {
      cancel();
      void flush();
    };
    frame = requestAnimationFrame(pass);
    timer = setTimeout(pass, FALLBACK_MS);
  }

  const unsubscribe = commandContext.subscribe(schedule);

  return () => {
    disposed = true;
    cancel();
    unsubscribe();
  };
}
