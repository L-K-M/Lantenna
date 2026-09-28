// Owner: unit E (spec 8.4). Spec: 3.2, 4.2 (Page key handling).
//
// Page-handled keys while the list or the icon grid has the keyboard,
// with preventDefault: Command-Delete (Hide Host / Show Host; Control-
// Backspace on Linux) on both platforms, since Osmium menu keys are one
// character and can't carry it, and Command-C (copy the IP) on macOS
// only, where the native Edit > Copy is a predefined item that copies
// text, not hosts. On Linux, Control-C belongs to the Osmium menu bar's
// Edit > Copy (edit.copy acts as edit.copyIp in list or icon context),
// which also flashes the Edit title; a second handler here would copy
// twice or keep the bar from seeing the key.
//
// Select All (Command-A; Control-A on Linux) is kept from the engine
// there: the Edit item is dimmed (hosts are selected one at a time), but
// the engine's select-all would select the pane's values, and the next
// Copy would copy them instead of the host's IP (3.2). On macOS this
// also keeps the predefined Select All from running.
//
// On Linux, Control-Shift-Z and Control-Y in a text field redo. The Edit
// menu has no Redo (4.3), and WebKitGTK binds no key to it, as it binds
// none to Undo (which Control-Z runs through the menu bar); Chromium
// redoes natively, and execCommand('redo') does the same there.
//
// WKWebView gives the page the first chance at Command keys and passes
// the rest to the native menu, so every other key is left alone. A key
// whose command is dimmed (no selection) is left alone too: the native
// menu, or the browser, does what it does with it.

import { get } from 'svelte/store';
import { hasTextSelection } from '$lib/util/selection';
import { commandContext, describe, run, type CommandRef } from './commands';
import { classifyFocus } from './focus';
import { isMac } from './platform';

/** What the page does with a keydown: run a command, keep the key
 * from the engine, or redo. */
type PageKey = { readonly run: CommandRef } | 'ignore' | 'redo';

/** Whether `e` is the platform's command key with `key` and no other
 * modifier but, with `shift`, Shift. */
function commandKey(e: KeyboardEvent, key: string, shift = false): boolean {
  const commandHeld = isMac ? e.metaKey && !e.ctrlKey : e.ctrlKey && !e.metaKey;
  return commandHeld && !e.altKey && e.shiftKey === shift && e.key.toLowerCase() === key;
}

/** What a keydown asks of the page, or null for any other key. */
function pageKey(e: KeyboardEvent): PageKey | null {
  if (e.defaultPrevented || e.isComposing) return null;

  const where = classifyFocus(e.target instanceof Element ? e.target : null);
  // Held, too: each repeat would select again.
  if ((where === 'list' || where === 'icons') && commandKey(e, 'a')) return 'ignore';
  if (e.repeat) return null;

  if (where === 'text') {
    return !isMac && (commandKey(e, 'z', true) || commandKey(e, 'y')) ? 'redo' : null;
  }
  if (where !== 'list' && where !== 'icons') return null;

  if (commandKey(e, 'backspace')) return { run: { id: 'host.toggleHidden' } };
  // Selected pane text copies as text (the native Copy does that).
  if (isMac && commandKey(e, 'c') && !hasTextSelection()) return { run: { id: 'edit.copyIp' } };
  return null;
}

/** Listen for the page keys; returns the disposer. Bubble phase, so a
 * view's own handler that took the key comes first. */
export function installPageKeys(): () => void {
  const onKeyDown = (e: KeyboardEvent) => {
    const key = pageKey(e);
    if (key === null) return;

    if (key === 'ignore') {
      e.preventDefault();
      return;
    }

    if (key === 'redo') {
      e.preventDefault();
      document.execCommand('redo');
      return;
    }

    if (!describe(key.run, get(commandContext)).enabled) return;
    e.preventDefault();
    run(key.run);
  };

  window.addEventListener('keydown', onKeyDown);
  return () => window.removeEventListener('keydown', onKeyDown);
}
