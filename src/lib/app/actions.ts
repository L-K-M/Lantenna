// Owner: unit C (spec 8.4). Spec: 1.16, 1.17, 1.19 to 1.21 (3.1), 2.7, 5.3, 5.4.
//
// SCAFFOLD STUB: every action does nothing and resolves; wakingIp stays
// null.
// Final contract: host actions shared by the pane's buttons, the menus
// and the views. Results go to the host status line (feedback.setHostNote),
// failures to stop alerts (feedback.stopAlert); success of a copy is
// silent.
//
// Restore from the pre-port HostInspector.svelte (`git show
// 97d42ae:src/lib/components/HostInspector.svelte`): writeClipboardText
// (navigator.clipboard with a hidden-textarea execCommand('copy')
// fallback; spec 3.1 1.19 keeps it) and the wake sending. Fall back to
// execCommand also when writeText rejects, not only when it is missing:
// Edit > Copy IP Address from the macOS native menu runs outside a page
// user gesture, and WKWebView may refuse the Clipboard API there
// (unverified; a manual check).
//
// Must not import commands.ts: commands.ts derives commandContext from
// wakingIp when it loads, so the cycle would read wakingIp before it
// exists.

import { readable, type Readable } from 'svelte/store';
import type { InfoTab } from './ui';

/** Open the host's primary target (HTTP, HTTPS, SMB, SSH, VNC). */
export function openHost(ip: string): Promise<void> {
  return Promise.resolve();
}

export function openUrl(url: string): Promise<void> {
  return Promise.resolve();
}

export function wakeHost(ip: string): Promise<void> {
  return Promise.resolve();
}

export function deepScan(ip: string): Promise<void> {
  return Promise.resolve();
}

export function copyValue(what: 'ip' | 'name' | 'detectedName' | 'mac', ip: string): Promise<void> {
  return Promise.resolve();
}

/** Edit > Copy Host List: the visible rows as tab-separated text. */
export function copyHostList(): Promise<void> {
  return Promise.resolve();
}

/** Get Info: show the pane and bring `tab` (default General) to the front. */
export function showInfo(tab?: InfoTab): void {}

/** Host > Rename…: show the pane, General tab, focus and select the name. */
export function beginRename(): void {}

/** Favorites menu: make `ip` listed, then select, reveal and focus it. */
export function revealHost(ip: string): void {}

/** The IP a wake-up packet is being sent to, or null. */
export const wakingIp: Readable<string | null> = readable(null);
