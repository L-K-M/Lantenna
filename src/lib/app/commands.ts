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

/** Whether an Osmium alert is up. */
const modal: Readable<boolean> = readable(isModal(), (set) => onModalChange(set));

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

export function describe(ref: CommandRef, ctx: CommandContext): CommandInfo {
  return { title: ref.arg ?? ref.id, enabled: false };
}

export function run(ref: CommandRef): void {}

export type SpecEntry = CommandRef | 'separator';

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
