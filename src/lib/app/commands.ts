// Owner: unit E (spec 8.4). Spec: 4.1 (command table), 4.2, 4.3, 4.4.
//
// One command model for the macOS native menu (nativeMenu.ts), the Linux
// Osmium menu bar (MenuBar.svelte), both contextual menus
// (contextMenus.ts), the page keys (keys.ts) and the buttons' enabled
// states. describe() is pure over a CommandContext; run() re-checks
// describe(...).enabled against the current context, so a stale native
// menu click is harmless. While an alert is up (ctx.modal) every Lantenna
// command is disabled, as Mac OS 8 dimmed menus under a modal alert.
//
// Import direction: commands.ts builds commandContext from actions.ts,
// hostModel.ts, ui.ts and focus.ts when it loads, so none of those may
// import commands.ts (a cycle would read their stores before they exist
// and throw). Components and keys/menus modules import commands.ts.

import { derived, get, readable, type Readable } from 'svelte/store';
import { getVersion } from '@tauri-apps/api/app';
import {
  MENU_SEPARATOR,
  balloonHelp,
  balloonMenuItem,
  isModal,
  onModalChange,
  setBalloonHelp,
  type MenuEntry,
  type MenuItem
} from 'osmium-ui';
import type { HostViewMode, ScanApproach } from '$lib/types';
import { ANTENNA } from '$lib/osm/sprites';
import {
  findInterfaceByKey,
  interfaceKey,
  scanProgress,
  scanStore,
  type ScanProgressState,
  type ScanStoreState
} from '$lib/util/scanStore';
import { hasTextSelection, textSelection } from '$lib/util/selection';
import { windowManager } from '$lib/windowManager';
import {
  beginRename,
  copyHostList,
  copyValue,
  deepScan,
  openHost,
  openUrl,
  revealHost,
  showInfo,
  wakeHost,
  wakingIp
} from './actions';
import { DEPTHS, SCOPES } from './choices';
import { noteAlert, stopAlert } from './feedback';
import { keyboardFocus, type FocusKind } from './focus';
import { customNameFor, knownName } from './hostNames';
import { hostModel, type HostModel, type HostRow } from './hostModel';
import { ipOrder } from './hostSort';
import { cmdName, platform, type Platform } from './platform';
import { ui, type ShowScope, type UiState } from './ui';
import { checkForUpdatesNow } from './updates';
import { FIND_FIELD_ID, hostedWindow } from './views';

export type CommandId =
  | 'app.about'
  | 'app.checkUpdates'
  | 'app.quit'
  | 'file.close'
  | 'edit.undo'
  | 'edit.cut'
  | 'edit.copy'
  | 'edit.paste'
  | 'edit.selectAll'
  | 'edit.copyIp'
  | 'edit.copyName'
  | 'edit.copyDetectedName'
  | 'edit.copyMac'
  | 'edit.copyHostList'
  | 'edit.find'
  | 'scan.toggle'
  | 'scan.interface'
  | 'scan.depth'
  | 'host.open'
  | 'host.openUrl'
  | 'host.getInfo'
  | 'host.rename'
  | 'host.clearName'
  | 'host.toggleHidden'
  | 'host.deepScan'
  | 'host.wake'
  | 'fav.toggle'
  | 'fav.reveal'
  | 'view.mode'
  | 'view.scope'
  | 'view.showHidden'
  | 'view.infoPane'
  | 'view.zoom'
  | 'view.collapse'
  | 'help.balloons'
  | 'help.help';

/** `arg`: the interface key, depth, URL, IP, view mode or scope for the
 * parameterized commands. */
export interface CommandRef {
  readonly id: CommandId;
  readonly arg?: string;
}

export interface CommandInfo {
  readonly title: string;
  readonly enabled: boolean;
  readonly checked?: boolean;
  /** A one-character key equivalent (Osmium menu keys are one character). */
  readonly key?: string;
}

export interface CommandContext {
  store: ScanStoreState;
  progress: ScanProgressState;
  ui: UiState;
  model: HostModel;
  focus: FocusKind;
  modal: boolean;
  wakingIp: string | null;
  /** The document has text selected outside any field (pane values). */
  textSelected: boolean;
  shaded: boolean;
  platform: Platform;
}

/** Whether an Osmium alert is up. The start function reads the current
 * state, so a get() after a change made while nothing subscribed (an
 * alert opened, say) sees it. */
const modal: Readable<boolean> = readable(false, (set) => {
  set(isModal());
  return onModalChange(set);
});

export const commandContext: Readable<CommandContext> = derived(
  [scanStore, scanProgress, ui, hostModel, keyboardFocus, modal, wakingIp, textSelection],
  ([$store, $progress, $ui, $model, $focus, $modal, $wakingIp, $textSelected]) => ({
    store: $store,
    progress: $progress,
    ui: $ui,
    model: $model,
    focus: $focus,
    modal: $modal,
    wakingIp: $wakingIp,
    textSelected: $textSelected,
    shaded: $ui.shaded,
    platform
  })
);

/** Where an item is drawn. Titles can differ: fav.toggle is `Add
 * “<name>” to Favorites` in the menu bar and `Add to Favorites` in a
 * contextual menu; help.help is `Lantenna Help` and `Help` (4.1, 4.4).
 * Buttons use the menu bar's. */
export type CommandPlace = 'menubar' | 'contextual';

const HELP_URL = 'https://github.com/L-K-M/Lantenna#readme';

const VIEW_MODES: readonly (readonly [HostViewMode, string])[] = [
  ['list', 'as List'],
  ['icons', 'as Icons']
];

function titleOf<T extends string>(table: readonly (readonly [T, string])[], value: string | undefined) {
  return table.find(([v]) => v === value)?.[1] ?? null;
}

/** Where the keyboard edits text: the Edit menu's text items act there. */
function inText(focus: FocusKind): boolean {
  return focus === 'text' || focus === 'readonly-text';
}

function inHostView(focus: FocusKind): boolean {
  return focus === 'list' || focus === 'icons';
}

/** A favorite's name for the Favorites menu: the custom name, else the
 * detected name (favorites need not be listed, so this reads the store,
 * where stale favorites keep their snapshot). */
function favoriteName(store: ScanStoreState, ip: string): string | null {
  const custom = customNameFor(store.customNames, ip);
  const host = store.hosts.find((h) => h.ip === ip);
  return host ? knownName(host, custom) : custom;
}

/** A host's name for people: in "Add “<name>” to Favorites" and as its
 * contextual menu's accessible name. */
export function rowName(row: HostRow): string {
  return knownName(row.host, row.customName) ?? row.ip;
}

const dimmed = (title: string, extra: Partial<CommandInfo> = {}): CommandInfo => ({ ...extra, title, enabled: false });

/** What `ref` looks like and whether it can run in `ctx`. Pure. */
export function describe(ref: CommandRef, ctx: CommandContext, place: CommandPlace = 'menubar'): CommandInfo {
  const info = describeIgnoringModal(ref, ctx, place);
  // Mac OS 8 dims every menu item while an alert is up.
  return ctx.modal && info.enabled ? { ...info, enabled: false } : info;
}

function describeIgnoringModal(ref: CommandRef, ctx: CommandContext, place: CommandPlace): CommandInfo {
  const row = ctx.model.selected;
  const { store } = ctx;

  switch (ref.id) {
    case 'app.about':
      return { title: 'About Lantenna…', enabled: true };
    case 'app.checkUpdates':
      return { title: 'Check for Updates…', enabled: true };
    case 'app.quit':
      return { title: 'Quit', enabled: true, key: 'Q' };
    case 'file.close':
      return { title: 'Close Window', enabled: true, key: 'W' };

    case 'edit.undo':
      return { title: 'Undo', enabled: ctx.focus === 'text', key: 'Z' };
    case 'edit.cut':
      return { title: 'Cut', enabled: ctx.focus === 'text', key: 'X' };
    case 'edit.copy':
      return {
        title: 'Copy',
        enabled: inText(ctx.focus) || ctx.textSelected || (inHostView(ctx.focus) && row !== null),
        key: 'C'
      };
    case 'edit.paste':
      return { title: 'Paste', enabled: ctx.focus === 'text', key: 'V' };
    case 'edit.selectAll':
      return { title: 'Select All', enabled: inText(ctx.focus), key: 'A' };

    case 'edit.copyIp':
      return { title: 'Copy IP Address', enabled: row !== null };
    case 'edit.copyName':
      return { title: 'Copy Host Name', enabled: row !== null && knownName(row.host, row.customName) !== null };
    case 'edit.copyDetectedName':
      return { title: 'Copy Detected Name', enabled: Boolean(row?.host.name) };
    case 'edit.copyMac':
      return { title: 'Copy MAC Address', enabled: Boolean(row?.host.fingerprint?.mac_address) };
    case 'edit.copyHostList':
      return { title: 'Copy Host List', enabled: ctx.model.rows.length > 0 };
    case 'edit.find':
      return { title: 'Find', enabled: true, key: 'F' };

    case 'scan.toggle': {
      if (store.stopping) return dimmed('Stopping…', { key: '.' });
      if (store.scanning) return { title: 'Stop Scan', enabled: true, key: '.' };

      const resolvable = findInterfaceByKey(store.interfaces, store.selectedInterface) !== null;
      return { title: 'Scan Network', enabled: resolvable && !store.loading, key: 'R' };
    }
    case 'scan.interface': {
      const item = store.interfaces.find((i) => interfaceKey(i) === ref.arg);
      // The Scan menu's only item when there are none, as in the pop-up.
      // A message, not an option, so it has no check mark.
      if (!item) return ref.arg === undefined ? dimmed('No interfaces found') : dimmed(ref.arg, { checked: false });

      const current = findInterfaceByKey(store.interfaces, store.selectedInterface);
      return {
        title: `${item.name} (${item.subnet})`,
        enabled: !store.scanning,
        checked: current !== null && interfaceKey(current) === ref.arg
      };
    }
    case 'scan.depth': {
      const title = titleOf(DEPTHS, ref.arg);
      if (title === null) return dimmed(ref.arg ?? '', { checked: false });
      return { title, enabled: !store.scanning, checked: store.scanApproach === ref.arg };
    }

    case 'host.open':
      return { title: 'Open', enabled: row?.primaryTarget != null, key: 'O' };
    case 'host.openUrl':
      return { title: ref.arg ?? '', enabled: row !== null && row.targets.some((t) => t.url === ref.arg) };
    case 'host.getInfo':
      return { title: 'Get Info', enabled: row !== null, key: 'I' };
    case 'host.rename':
      return { title: 'Rename…', enabled: row !== null };
    case 'host.clearName':
      return { title: 'Clear Custom Name', enabled: row?.customName != null };
    case 'host.toggleHidden':
      return { title: row?.hidden ? 'Show Host' : 'Hide Host', enabled: row !== null };
    case 'host.deepScan':
      return { title: 'Deep Scan', enabled: row !== null && !ctx.progress.hostScanProgress?.running, key: 'D' };
    case 'host.wake':
      return {
        title: 'Wake',
        enabled: Boolean(row?.host.fingerprint?.mac_address) && ctx.wakingIp === null
      };

    case 'fav.toggle': {
      const favorite = row?.favorite ?? false;
      if (place === 'contextual' || row === null) {
        return { title: favorite ? 'Remove from Favorites' : 'Add to Favorites', enabled: row !== null };
      }

      const name = rowName(row);
      const title = favorite ? `Remove “${name}” from Favorites` : `Add “${name}” to Favorites`;
      return { title, enabled: true };
    }
    case 'fav.reveal': {
      const ip = ref.arg ?? '';
      if (!store.favoriteIps.includes(ip)) return dimmed(ip);

      const name = favoriteName(store, ip);
      return { title: name ? `${name} (${ip})` : ip, enabled: true };
    }

    case 'view.mode': {
      const title = titleOf(VIEW_MODES, ref.arg);
      if (title === null) return dimmed(ref.arg ?? '', { checked: false });
      return { title, enabled: true, checked: ctx.ui.viewMode === ref.arg };
    }
    case 'view.scope': {
      const title = titleOf(SCOPES, ref.arg);
      if (title === null) return dimmed(ref.arg ?? '', { checked: false });
      return { title, enabled: true, checked: ctx.ui.scope === ref.arg };
    }
    case 'view.showHidden':
      return {
        title: 'Show Hidden Hosts',
        // An "on" state with nothing hidden stays enabled so it can be
        // turned off (3.1, 1.8).
        enabled: ctx.model.hiddenCount > 0 || store.showHiddenEntries,
        checked: store.showHiddenEntries
      };
    case 'view.infoPane':
      return { title: ctx.ui.infoPaneShown ? 'Hide Host Information' : 'Show Host Information', enabled: true };
    case 'view.zoom':
      return { title: 'Zoom Window', enabled: !ctx.shaded };
    case 'view.collapse':
      return { title: ctx.shaded ? 'Expand Window' : 'Collapse Window', enabled: true };

    case 'help.balloons':
      return { title: ctx.ui.balloons === 'shown' ? 'Hide Balloons' : 'Show Balloons', enabled: true };
    case 'help.help':
      return { title: place === 'contextual' ? 'Help' : 'Lantenna Help', enabled: true };
  }
}

/** Run `ref` if it is enabled in the current context; otherwise do
 * nothing (a stale native menu click, a key under an alert). */
export function run(ref: CommandRef): void {
  const ctx = get(commandContext);
  if (!describe(ref, ctx).enabled) return;

  const ip = ctx.model.selected?.ip ?? null;

  switch (ref.id) {
    case 'app.about':
      void showAbout();
      return;
    case 'app.checkUpdates':
      void checkForUpdatesNow();
      return;
    case 'app.quit':
    case 'file.close':
      closeWindow();
      return;

    case 'edit.undo':
      document.execCommand('undo');
      return;
    case 'edit.cut':
      editClipboard('cut');
      return;
    case 'edit.copy':
      if (inText(ctx.focus) || hasTextSelection()) editClipboard('copy');
      else if (ip !== null) void copyValue('ip', ip);
      return;
    case 'edit.paste':
      void paste();
      return;
    case 'edit.selectAll':
      selectAll();
      return;

    case 'edit.copyIp':
      if (ip !== null) void copyValue('ip', ip);
      return;
    case 'edit.copyName':
      if (ip !== null) void copyValue('name', ip);
      return;
    case 'edit.copyDetectedName':
      if (ip !== null) void copyValue('detectedName', ip);
      return;
    case 'edit.copyMac':
      if (ip !== null) void copyValue('mac', ip);
      return;
    case 'edit.copyHostList':
      void copyHostList();
      return;
    case 'edit.find':
      focusFind();
      return;

    case 'scan.toggle':
      if (ctx.store.scanning) void scanStore.cancelScan();
      else void scanStore.startScan();
      return;
    case 'scan.interface':
      if (ref.arg !== undefined) scanStore.setInterface(ref.arg);
      return;
    case 'scan.depth':
      scanStore.setScanApproach(ref.arg as ScanApproach);
      return;

    case 'host.open':
      if (ip !== null) void openHost(ip);
      return;
    case 'host.openUrl':
      if (ref.arg !== undefined) void openUrl(ref.arg);
      return;
    case 'host.getInfo':
      expandWindow();
      showInfo('general');
      return;
    case 'host.rename':
      expandWindow();
      beginRename();
      return;
    case 'host.clearName':
      if (ip !== null) scanStore.setCustomName(ip, '');
      return;
    case 'host.toggleHidden':
      if (ip !== null) scanStore.toggleHidden(ip);
      return;
    case 'host.deepScan':
      if (ip !== null) void deepScan(ip);
      return;
    case 'host.wake':
      if (ip !== null) void wakeHost(ip);
      return;

    case 'fav.toggle':
      if (ip !== null) scanStore.toggleFavorite(ip);
      return;
    case 'fav.reveal':
      if (ref.arg !== undefined) {
        expandWindow();
        revealHost(ref.arg);
      }
      return;

    case 'view.mode':
      ui.setViewMode(ref.arg as HostViewMode);
      return;
    case 'view.scope':
      ui.setScope(ref.arg as ShowScope);
      return;
    case 'view.showHidden':
      scanStore.setShowHiddenEntries(!ctx.store.showHiddenEntries);
      return;
    case 'view.infoPane':
      ui.setInfoPane(!ctx.ui.infoPaneShown);
      return;
    case 'view.zoom':
      // HostedWindow has no zoom method; the op goes the way the zoom
      // box's does.
      windowManager.apply({ op: 'winZoom' });
      return;
    case 'view.collapse':
      get(hostedWindow)?.setShaded(!ctx.shaded);
      return;

    case 'help.balloons':
      // Osmium's own state, so the command toggles what the page shows
      // even if ui has not caught up yet.
      setBalloonHelp(balloonHelp() === 'shown' ? 'hidden' : 'shown');
      return;
    case 'help.help':
      void openUrl(HELP_URL);
      return;
  }
}

// ---- actions that are only the commands' ---------------------------------

async function showAbout(): Promise<void> {
  let version: string | null = null;
  try {
    version = await getVersion();
  } catch (error) {
    // The About box still names the program; the version is only missing.
    console.warn('Lantenna couldn’t read its version:', error);
  }

  await noteAlert({
    message: version === null ? 'Lantenna' : `Lantenna ${version}`,
    explanation: 'Finds the computers and devices on your network.\n\ngithub.com/L-K-M/Lantenna',
    buttons: { ok: 'OK' }
  });
}

function closeWindow(): void {
  const hosted = get(hostedWindow);
  if (hosted) hosted.close();
  else windowManager.apply({ op: 'winClose' });
}

/** Commands that move the keyboard into the content unfold a collapsed
 * window first; otherwise they would act on hidden controls. */
function expandWindow(): void {
  const hosted = get(hostedWindow);
  if (hosted?.shaded) hosted.setShaded(false);
}

function focusFind(): void {
  expandWindow();
  const field = document.getElementById(FIND_FIELD_ID);
  if (!(field instanceof HTMLInputElement)) {
    console.warn(`Lantenna has no Find field (#${FIND_FIELD_ID}).`);
    return;
  }

  field.focus();
  field.select();
}

/** Whether the field with the keyboard, or else the document, has
 * text selected. A field whose type has no selection counts. */
function textSelected(): boolean {
  const field = document.activeElement;
  if (field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) {
    return field.selectionStart === null || field.selectionStart !== field.selectionEnd;
  }
  return hasTextSelection();
}

/** Linux Edit menu clicks on text (keys go to the browser instead).
 * With nothing selected there is nothing to cut or copy, and the keys
 * do nothing then; WebKit's execCommand reports it as a failure. */
function editClipboard(command: 'cut' | 'copy'): void {
  if (!textSelected()) return;
  if (document.execCommand(command)) return;

  const key = command === 'cut' ? 'X' : 'C';
  void stopAlert(
    `Lantenna couldn’t ${command} to the Clipboard.`,
    `Press ${cmdName}-${key} to ${command} the selection instead.`
  );
}

function selectAll(): void {
  const field = document.activeElement;
  if (field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) field.select();
  else document.execCommand('selectAll');
}

/** Edit > Paste from a menu click: the page must read the Clipboard
 * itself, which WebKitGTK may refuse (spec 5.4). */
async function paste(): Promise<void> {
  const field = document.activeElement;
  let text: string;
  try {
    if (!navigator.clipboard?.readText) throw new Error('Clipboard is not available');
    text = await navigator.clipboard.readText();
  } catch (error) {
    console.warn('Lantenna couldn’t read the Clipboard:', error);
    await stopAlert('Lantenna couldn’t read the Clipboard.', `Press ${cmdName}-V to paste into the field instead.`);
    return;
  }

  if (field instanceof HTMLElement && document.activeElement !== field) field.focus();
  if (document.execCommand('insertText', false, text)) return;

  // execCommand('insertText') is missing: insert as typing would.
  if (field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) {
    const end = field.value.length;
    field.setRangeText(text, field.selectionStart ?? end, field.selectionEnd ?? end, 'end');
    field.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertFromPaste', data: text }));
  }
}

// ---- menu specs -----------------------------------------------------------

/** Native items macOS draws and runs itself (4.2): the app menu's
 * Services, Hide Lantenna, Hide Others, Show All and Quit Lantenna, and
 * the Edit menu's editing items. nativeMenu.ts builds them with
 * PredefinedMenuItem; they never reach describe() or run(). */
export type PredefinedItem =
  | 'services'
  | 'hide'
  | 'hideOthers'
  | 'showAll'
  | 'quit'
  | 'undo'
  | 'redo'
  | 'cut'
  | 'copy'
  | 'paste'
  | 'selectAll';

/** A menu entry: a command, a separator, or (macOS menu bar only) a
 * predefined native item. */
export type SpecEntry = CommandRef | 'separator' | { readonly predefined: PredefinedItem };

export interface MenuSpec {
  readonly id: string;
  readonly title: string;
  /** Sprite name for an icon title (the antenna), as Osmium's Menu.icon. */
  readonly icon?: string;
  readonly entries: readonly SpecEntry[];
}

const SEP = 'separator' as const;

function cmd(id: CommandId, arg?: string): CommandRef {
  return arg === undefined ? { id } : { id, arg };
}

function predefined(item: PredefinedItem): SpecEntry {
  return { predefined: item };
}

/** Open, then each target URL when the host has two or more (4.2, 4.4). */
function openEntries(ctx: CommandContext): SpecEntry[] {
  const targets = ctx.model.selected?.targets ?? [];
  return [cmd('host.open'), ...(targets.length >= 2 ? targets.map((t) => cmd('host.openUrl', t.url)) : [])];
}

/** The interfaces, or a dimmed "No interfaces found" once the store has
 * read none. Nothing while it is still reading them, as the pop-up shows
 * nothing then: the menu shouldn't claim what the window doesn't. */
function interfaceEntries(ctx: CommandContext): SpecEntry[] {
  const { interfaces, loading } = ctx.store;
  if (interfaces.length > 0) return interfaces.map((i) => cmd('scan.interface', interfaceKey(i)));
  return loading ? [] : [cmd('scan.interface')];
}

const nameOrder = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

/** Favorites sorted by name, then IP; unnamed ones last, by IP. */
function favoriteEntries(ctx: CommandContext): SpecEntry[] {
  const named = ctx.store.favoriteIps.map((ip) => ({ ip, name: favoriteName(ctx.store, ip) }));
  named.sort((a, b) => {
    if (a.name !== null && b.name === null) return -1;
    if (a.name === null && b.name !== null) return 1;
    const byName = a.name !== null && b.name !== null ? nameOrder.compare(a.name, b.name) : 0;
    return byName || ipOrder(a.ip) - ipOrder(b.ip);
  });
  return named.map(({ ip }) => cmd('fav.reveal', ip));
}

function scanMenu(ctx: CommandContext): MenuSpec {
  const interfaces = interfaceEntries(ctx);
  return {
    id: 'scan',
    title: 'Scan',
    entries: [
      cmd('scan.toggle'),
      SEP,
      ...(interfaces.length > 0 ? [...interfaces, SEP] : []),
      ...DEPTHS.map(([depth]) => cmd('scan.depth', depth))
    ]
  };
}

function hostMenu(ctx: CommandContext): MenuSpec {
  return {
    id: 'host',
    title: 'Host',
    entries: [
      ...openEntries(ctx),
      cmd('host.getInfo'),
      SEP,
      cmd('host.rename'),
      cmd('host.clearName'),
      cmd('host.toggleHidden'),
      SEP,
      cmd('host.deepScan'),
      cmd('host.wake')
    ]
  };
}

function favoritesMenu(ctx: CommandContext): MenuSpec {
  const favorites = favoriteEntries(ctx);
  return {
    id: 'favorites',
    title: 'Favorites',
    entries: [cmd('fav.toggle'), ...(favorites.length > 0 ? [SEP, ...favorites] : [])]
  };
}

const VIEW_MENU: MenuSpec = {
  id: 'view',
  title: 'View',
  entries: [
    ...VIEW_MODES.map(([mode]) => cmd('view.mode', mode)),
    SEP,
    ...SCOPES.map(([scope]) => cmd('view.scope', scope)),
    SEP,
    cmd('view.showHidden'),
    SEP,
    cmd('view.infoPane'),
    SEP,
    cmd('view.zoom'),
    cmd('view.collapse')
  ]
};

const COPY_ENTRIES: readonly SpecEntry[] = [
  cmd('edit.copyIp'),
  cmd('edit.copyName'),
  cmd('edit.copyDetectedName'),
  cmd('edit.copyMac'),
  cmd('edit.copyHostList')
];

const MAC_APP_MENU: MenuSpec = {
  id: 'app',
  title: 'Lantenna',
  entries: [
    cmd('app.about'),
    SEP,
    cmd('app.checkUpdates'),
    SEP,
    predefined('services'),
    SEP,
    predefined('hide'),
    predefined('hideOthers'),
    predefined('showAll'),
    SEP,
    predefined('quit')
  ]
};

const LINUX_APP_MENU: MenuSpec = {
  id: 'app',
  title: 'Lantenna',
  icon: ANTENNA,
  entries: [cmd('app.about'), SEP, cmd('app.checkUpdates')]
};

const MAC_FILE_MENU: MenuSpec = { id: 'file', title: 'File', entries: [cmd('file.close')] };

const LINUX_FILE_MENU: MenuSpec = { id: 'file', title: 'File', entries: [cmd('file.close'), SEP, cmd('app.quit')] };

/** The predefined items keep WKWebView's native text editing (4.2). */
const MAC_EDIT_MENU: MenuSpec = {
  id: 'edit',
  title: 'Edit',
  entries: [
    predefined('undo'),
    predefined('redo'),
    SEP,
    predefined('cut'),
    predefined('copy'),
    predefined('paste'),
    predefined('selectAll'),
    SEP,
    ...COPY_ENTRIES,
    SEP,
    cmd('edit.find')
  ]
};

/** No Redo: Mac OS 8 had none (4.3). */
const LINUX_EDIT_MENU: MenuSpec = {
  id: 'edit',
  title: 'Edit',
  entries: [
    cmd('edit.undo'),
    SEP,
    cmd('edit.cut'),
    cmd('edit.copy'),
    cmd('edit.paste'),
    cmd('edit.selectAll'),
    SEP,
    ...COPY_ENTRIES,
    SEP,
    cmd('edit.find')
  ]
};

/** On Linux the renderer draws help.balloons with Osmium's
 * balloonMenuItem() (4.3). */
const HELP_MENU: MenuSpec = { id: 'help', title: 'Help', entries: [cmd('help.balloons'), SEP, cmd('help.help')] };

/** The menu bar for ctx.platform (4.2 macOS, 4.3 Linux). The menus and
 * their titles are the same in every state; items follow the state. */
export function menuBarSpec(ctx: CommandContext): readonly MenuSpec[] {
  const mac = ctx.platform === 'mac';
  return [
    mac ? MAC_APP_MENU : LINUX_APP_MENU,
    mac ? MAC_FILE_MENU : LINUX_FILE_MENU,
    mac ? MAC_EDIT_MENU : LINUX_EDIT_MENU,
    scanMenu(ctx),
    hostMenu(ctx),
    favoritesMenu(ctx),
    VIEW_MENU,
    HELP_MENU
  ];
}

/** The contextual menu on a host (4.4): Help first, every item also in
 * the menu bar, no keys, no submenus. */
export function hostMenuSpec(ctx: CommandContext): readonly SpecEntry[] {
  return [
    cmd('help.help'),
    SEP,
    ...openEntries(ctx),
    cmd('host.getInfo'),
    SEP,
    cmd('edit.copyIp'),
    cmd('edit.copyName'),
    cmd('edit.copyMac'),
    SEP,
    cmd('fav.toggle'),
    cmd('host.rename'),
    cmd('host.clearName'),
    cmd('host.toggleHidden'),
    SEP,
    cmd('host.deepScan'),
    cmd('host.wake')
  ];
}

/** The contextual menu on empty list or grid space (4.4). */
export function viewMenuSpec(ctx: CommandContext): readonly SpecEntry[] {
  return [
    cmd('help.help'),
    SEP,
    cmd('scan.toggle'),
    SEP,
    ...VIEW_MODES.map(([mode]) => cmd('view.mode', mode)),
    SEP,
    ...SCOPES.map(([scope]) => cmd('view.scope', scope)),
    cmd('view.showHidden')
  ];
}

// ---- Osmium menus (Linux menu bar, contextual menus) ----------------------

/** The Edit items that leave their key equivalents to the browser while
 * text has the keyboard, so native editing (and its clipboard, which
 * needs no permission) handles them. Not Undo: WebKitGTK binds no key
 * to it (its editing keys come from GTK's text widget, which has no
 * undo; browsers built on it add their own), so Control-Z runs the
 * item, whose execCommand('undo') the engine does. */
const TEXT_EDIT_IDS: ReadonlySet<CommandId> = new Set([
  'edit.cut',
  'edit.copy',
  'edit.paste',
  'edit.selectAll'
]);

/**
 * `entries` as Osmium menu entries for the Linux menu bar or a
 * contextual menu: dimmed items have no action, keys only in the menu
 * bar, and predefined (macOS-only) entries left out. Each action runs
 * the command through run(), which re-checks it, and only while its
 * title is unchanged. help.balloons is
 * Osmium's balloonMenuItem() (4.3). Reads the document's text selection
 * for Copy's key (DOM), so call it when the menu is built.
 */
export function osmiumMenuEntries(
  entries: readonly SpecEntry[],
  ctx: CommandContext,
  place: CommandPlace
): MenuEntry[] {
  const result: MenuEntry[] = [];

  for (const entry of entries) {
    if (entry === SEP) {
      result.push(MENU_SEPARATOR);
      continue;
    }

    if ('predefined' in entry) continue;

    const info = describe(entry, ctx, place);
    if (entry.id === 'help.balloons' && info.enabled) {
      result.push(balloonMenuItem());
      continue;
    }

    const browserKey =
      TEXT_EDIT_IDS.has(entry.id) && (inText(ctx.focus) || (entry.id === 'edit.copy' && hasTextSelection()));
    // The state can change while the menu is open (a scan ends under
    // Stop Scan): the item acts only if it still means what it says.
    const action = () => {
      if (describe(entry, get(commandContext), place).title === info.title) run(entry);
    };
    const item: MenuItem = {
      title: info.title,
      ...(info.enabled ? { action } : {}),
      ...(place === 'menubar' && info.key !== undefined ? { key: info.key } : {}),
      ...(browserKey ? { keyDispatch: 'browser' as const } : {}),
      ...(info.checked !== undefined ? { checked: info.checked } : {})
    };
    result.push(item);
  }

  return result;
}
