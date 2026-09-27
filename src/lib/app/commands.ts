// Owner: unit E (spec 8.4). Spec: 4.1 (command table), 4.2, 4.3, 4.4.
//
// SCAFFOLD STUB: commandContext is already derived from the real stores;
// describe() reports every command dimmed with its id as title, run()
// does nothing, and the menu specs are empty.
// Final contract: one command model for the macOS native menu, the
// Linux Osmium menu bar, both contextual menus and the buttons' enabled
// states. run() re-checks describe(...).enabled against the current
// context, so a stale native menu click is harmless; while an alert is
// up (ctx.modal) every Lantenna command is disabled.
//
// Import direction: commands.ts builds commandContext from actions.ts,
// hostModel.ts, ui.ts and focus.ts when it loads, so none of those may
// import commands.ts (a cycle would read their stores before they exist
// and throw). Components and keys/menus modules import commands.ts.

import { derived, readable, type Readable } from 'svelte/store';
import { isModal, onModalChange } from 'osmium-ui';
import { scanProgress, scanStore, type ScanProgressState, type ScanStoreState } from '$lib/util/scanStore';
import { wakingIp } from './actions';
import { keyboardFocus, type FocusKind } from './focus';
import { hostModel, type HostModel } from './hostModel';
import { platform, type Platform } from './platform';
import { ui, type UiState } from './ui';

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
  [scanStore, scanProgress, ui, hostModel, keyboardFocus, modal, wakingIp],
  ([$store, $progress, $ui, $model, $focus, $modal, $wakingIp]) => ({
    store: $store,
    progress: $progress,
    ui: $ui,
    model: $model,
    focus: $focus,
    modal: $modal,
    wakingIp: $wakingIp,
    shaded: $ui.shaded,
    platform
  })
);

/** Where an item is drawn. Titles can differ: fav.toggle is `Add
 * “<name>” to Favorites` in the menu bar and `Add to Favorites` in a
 * contextual menu; help.help is `Lantenna Help` and `Help` (4.1, 4.4).
 * Buttons use the menu bar's. */
export type CommandPlace = 'menubar' | 'contextual';

export function describe(ref: CommandRef, ctx: CommandContext, place: CommandPlace = 'menubar'): CommandInfo {
  return { title: ref.arg ?? ref.id, enabled: false };
}

export function run(ref: CommandRef): void {}

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

/** The menu bar for ctx.platform (4.2 macOS, 4.3 Linux). */
export function menuBarSpec(ctx: CommandContext): readonly MenuSpec[] {
  return [];
}

/** The contextual menu on a host (4.4). */
export function hostMenuSpec(ctx: CommandContext): readonly SpecEntry[] {
  return [];
}

/** The contextual menu on empty list or grid space (4.4). */
export function viewMenuSpec(ctx: CommandContext): readonly SpecEntry[] {
  return [];
}
