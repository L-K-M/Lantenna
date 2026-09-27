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
// WKWebView gives the page the first chance at Command keys and passes
// the rest to the native menu, so every other key is left alone. A key
// whose command is dimmed (no selection) is left alone too: the native
// menu, or the browser, does what it does with it.

import { get } from 'svelte/store';
import { commandContext, describe, hasTextSelection, run, type CommandRef } from './commands';
import { classifyFocus } from './focus';
import { isMac } from './platform';

/** The command a keydown asks of the page, or null for any other key. */
function pageCommand(e: KeyboardEvent): CommandRef | null {
  if (e.defaultPrevented || e.repeat || e.isComposing || e.altKey || e.shiftKey) return null;

  const commandHeld = isMac ? e.metaKey && !e.ctrlKey : e.ctrlKey && !e.metaKey;
  if (!commandHeld) return null;

  const where = classifyFocus(e.target instanceof Element ? e.target : null);
  if (where !== 'list' && where !== 'icons') return null;

  if (e.key === 'Backspace') return { id: 'host.toggleHidden' };
  // Selected pane text copies as text (the native Copy does that).
  if (isMac && e.key.toLowerCase() === 'c' && !hasTextSelection()) return { id: 'edit.copyIp' };
  return null;
}

/** Listen for the page keys; returns the disposer. Bubble phase, so a
 * view's own handler that took the key comes first. */
export function installPageKeys(): () => void {
  const onKeyDown = (e: KeyboardEvent) => {
    const ref = pageCommand(e);
    if (ref === null || !describe(ref, get(commandContext)).enabled) return;

    e.preventDefault();
    run(ref);
  };

  window.addEventListener('keydown', onKeyDown);
  return () => window.removeEventListener('keydown', onKeyDown);
}
