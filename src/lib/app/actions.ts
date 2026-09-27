// Owner: unit C (spec 8.4). Spec: 1.16, 1.17, 1.19 to 1.21 (3.1), 2.7, 5.3, 5.4.
//
// Host actions shared by the pane's buttons, the menus and the views.
// Results go to the host status line (feedback.setHostNote), failures to
// stop alerts (feedback.stopAlert); a copy that works is silent. Alerts
// are not awaited: an action's promise settles when its work is done,
// not when the reader dismisses the alert about it.
//
// Live states are not notes: the pane shows "Sending a wake-up packet…"
// from wakingIp and the deep scan's progress from scanProgress. Deep
// scan results ("Deep scan finished …", "A deep scan is already
// running.") and failures come from the store's scan events, which
// feedback.ts turns into notes and alerts.
//
// Must not import commands.ts: commands.ts derives commandContext from
// wakingIp when it loads, so the cycle would read wakingIp before it
// exists.

import { get, writable, type Readable } from 'svelte/store';
import { TauriService } from '$lib/tauri';
import type { Host } from '$lib/types';
import { errorMessage } from '$lib/util/errors';
import { formatClock, formatRelativeTime } from '$lib/util/format';
import { hostMatchesQuery } from '$lib/util/hostSearch';
import { primaryPortTarget } from '$lib/util/portTargets';
import { scanStore } from '$lib/util/scanStore';
import { explainError } from './errorText';
import { clearHostNote, noteAlert, setHostNote, stopAlert } from './feedback';
import { hostModel, type HostRow } from './hostModel';
import { customNameFor, knownName } from './hostNames';
import { ui, type InfoTab } from './ui';
import { activeView, hostedWindow, infoPaneApi } from './views';

/** 5.3: double-click or Return on a host with nothing to open. */
const NO_TARGET_NOTE =
  'This host has no web, file sharing, remote login or screen sharing service to open.';

/** 5.4: the same, while the pane (and so the status line) is hidden. */
const NO_TARGET_EXPLANATION =
  'Lantenna opens web pages (HTTP and HTTPS), file servers (SMB), remote logins (SSH) and screen sharing (VNC). To see this host’s open ports, choose Show Host Information from the View menu.';

const WAKE_ADVICE = 'Check that this computer is connected to the network, then try again.';

/** Edit > Copy Host List's header line (3.1, 1.19). */
const HOST_LIST_HEADER = ['Name', 'IP Address', 'Status', 'Kind', 'Vendor', 'Ports', 'Last Seen'];

function findHost(ip: string): Host | null {
  return get(scanStore).hosts.find((host) => host.ip === ip) ?? null;
}

function customName(ip: string): string | null {
  return customNameFor(get(scanStore).customNames, ip);
}

/** Get Info, Rename… and the Favorites menu are asks to see the host, so
 * a collapsed window unfolds first (its content can't take the keyboard
 * while folded). */
function expandWindow(): void {
  if (get(ui).shaded) get(hostedWindow)?.setShaded(false);
}

/** Open the host's primary target (HTTP, HTTPS, SMB, SSH, VNC). Without
 * one, say so in the status line, or in a note alert while the pane is
 * hidden (the Open command is dimmed then; double-click and Return on
 * the host still come here). */
export async function openHost(ip: string): Promise<void> {
  const host = findHost(ip);
  if (!host) return;

  const target = primaryPortTarget(host);
  if (target) {
    await openUrl(target.url);
    return;
  }

  if (get(ui).infoPaneShown) {
    setHostNote(ip, NO_TARGET_NOTE);
    return;
  }

  const name = knownName(host, customName(ip)) ?? ip;
  void noteAlert({ message: `“${name}” has no service Lantenna can open.`, explanation: NO_TARGET_EXPLANATION });
}

/** Open `url` with the system (the backend allows only its schemes). */
export async function openUrl(url: string): Promise<void> {
  try {
    await TauriService.openExternalUrl(url);
  } catch (error) {
    void stopAlert(`Lantenna couldn’t open “${url}”.`, explainError(errorMessage(error, 'Failed to open link')));
  }
}

const waking = writable<string | null>(null);

/** Send a Wake-on-LAN packet to the host's MAC (a stale favorite's is
 * its snapshot's). One wake at a time; without a MAC nothing happens
 * (the command is dimmed). */
export async function wakeHost(ip: string): Promise<void> {
  if (get(waking) !== null) return;

  const mac = findHost(ip)?.fingerprint?.mac_address;
  if (!mac) return;

  waking.set(ip);
  try {
    await TauriService.wakeHost(mac);
    setHostNote(ip, `Wake-up packet sent to ${mac} at ${formatClock(new Date())}.`);
  } catch (error) {
    // Failures are alerts, never status lines (5.3): drop the host's
    // older note, as a failed deep scan does, so the line doesn't show
    // a result from before this attempt.
    clearHostNote(ip);
    const raw = errorMessage(error, 'Failed to send Wake-on-LAN packet');
    void stopAlert('Lantenna couldn’t send the wake-up packet.', `${explainError(raw)} ${WAKE_ADVICE}`);
  } finally {
    waking.set(null);
  }
}

/** Deep scan the host. The store reports a race ("deep-scan-busy"), the
 * result and a failure as scan events; the pane follows the progress. */
export async function deepScan(ip: string): Promise<void> {
  await scanStore.refreshHostPorts(ip, 'deep');
}

function valueToCopy(what: 'ip' | 'name' | 'detectedName' | 'mac', host: Host): string | null {
  switch (what) {
    case 'ip':
      return host.ip;
    case 'name':
      return knownName(host, customName(host.ip));
    case 'detectedName':
      return host.name || null;
    case 'mac':
      return host.fingerprint?.mac_address || null;
  }
}

/** Copy one of the host's values. The Copy commands are dimmed without a
 * value, so a missing one does nothing. */
export async function copyValue(what: 'ip' | 'name' | 'detectedName' | 'mac', ip: string): Promise<void> {
  const host = findHost(ip);
  const value = host ? valueToCopy(what, host) : null;
  if (!value) return;

  await copyText(value);
}

/** Tabs and line breaks inside a value would break the TSV's shape. */
function cellText(text: string): string {
  return text.replace(/[\t\r\n]+/g, ' ');
}

function hostListLine(row: HostRow, now: number): string {
  return [
    row.listName,
    row.ip,
    row.status,
    row.kind,
    row.vendor,
    row.portsText,
    formatRelativeTime(row.host.last_seen, now)
  ]
    .map(cellText)
    .join('\t');
}

/** Edit > Copy Host List: the listed rows in display order as
 * tab-separated text, the cells as the list shows them. */
export async function copyHostList(): Promise<void> {
  const rows = get(hostModel).rows;
  if (rows.length === 0) return;

  const now = Date.now();
  const lines = [HOST_LIST_HEADER.join('\t'), ...rows.map((row) => hostListLine(row, now))];
  await copyText(lines.join('\n'));
}

async function copyText(value: string): Promise<void> {
  try {
    await writeClipboardText(value);
  } catch (error) {
    // The alert explains; the log keeps the system's reason (the cause).
    console.warn('Lantenna couldn’t copy to the Clipboard:', error);
    void stopAlert('Lantenna couldn’t copy to the Clipboard.', explainError(errorMessage(error, 'Failed to copy')));
  }
}

/**
 * The Clipboard API, falling back to execCommand('copy') when the API is
 * missing or refuses: Edit > Copy IP Address from the macOS native menu
 * runs outside a page user gesture, and WKWebView may refuse the API
 * there (unverified; a manual check).
 */
async function writeClipboardText(value: string): Promise<void> {
  /** Why the API refused, if it did: the failure's cause. */
  let refusal: unknown = undefined;
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch (error) {
      // Refused: try the fallback below.
      refusal = error;
    }
  }

  if (copyWithCopyEvent(value)) return;
  throw new Error('Clipboard write was blocked by the system', refusal === undefined ? undefined : { cause: refusal });
}

/**
 * execCommand('copy') fires a `copy` event, and a one-time listener puts
 * the value on its clipboard data. Nothing gets selected, so the keyboard
 * stays where it is: selecting a hidden text area would take it, and the
 * name field commits its draft when it loses the keyboard. Success is the
 * listener having run, not execCommand's result: WebKit returns false
 * without a selection even when it copied (checked in Chromium and
 * WebKitGTK).
 */
function copyWithCopyEvent(value: string): boolean {
  let copied = false;
  const onCopy = (e: ClipboardEvent) => {
    if (!e.clipboardData) return;

    e.clipboardData.setData('text/plain', value);
    e.preventDefault();
    copied = true;
  };

  document.addEventListener('copy', onCopy, true);
  try {
    document.execCommand('copy');
  } finally {
    document.removeEventListener('copy', onCopy, true);
  }
  return copied;
}

/** Get Info: show the pane and bring `tab` (default General) to the front. */
export function showInfo(tab: InfoTab = 'general'): void {
  expandWindow();
  ui.setInfoPane(true);
  ui.setInfoTab(tab);
}

/** Host > Rename…: show the pane, General tab, focus and select the name. */
export function beginRename(): void {
  showInfo('general');
  get(infoPaneApi)?.focusName();
}

/**
 * Favorites menu: make `ip` listed (Show: All Hosts; Find cleared if it
 * hides the host; hidden hosts shown if it is hidden), then select,
 * reveal and focus it. The view applies the new rows before revealing
 * (views.ts).
 */
export function revealHost(ip: string): void {
  const store = get(scanStore);
  const host = store.hosts.find((item) => item.ip === ip);
  if (!host) return;

  expandWindow();
  ui.setScope('all');
  if (!hostMatchesQuery(host, customName(ip) ?? '', store.query)) scanStore.setQuery('');
  if (store.hiddenIps.includes(ip) && !store.showHiddenEntries) scanStore.setShowHiddenEntries(true);
  scanStore.setSelectedHost(ip);

  const view = get(activeView);
  view?.reveal(ip);
  view?.focus();
}

/** The IP a wake-up packet is being sent to, or null. */
export const wakingIp: Readable<string | null> = { subscribe: waking.subscribe };
