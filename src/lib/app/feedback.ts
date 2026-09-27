// Owner: unit D (spec 8.4). Spec: 5.1 to 5.5.
//
// Where Lantenna tells you things, now that there are no toasts:
//
// - Failures open a movable stop alert over the window (stopAlert).
//   Alerts are queued: one at a time, an alert identical (message and
//   explanation) to one already queued or showing is dropped, and a
//   collapsed window is expanded before an alert opens. The disposer of
//   installFeedback closes what is still open.
// - Per-host results go to the host status line (hostNote, 5.3), one
//   note per IP. The line shows the selected host's note; selecting
//   another host drops the previous one's. Live states (a wake being
//   sent, a deep scan's progress) are not notes: the pane works them
//   out from wakingIp and scanProgress, so they can't go stale here.
// - lastError records which kind of failure set the store's error, for
//   the header's error line (5.2 rows 10 and 11).
//
// installFeedback() turns the scan store's events (scanEvents) into
// these. Import direction: this module imports scanStore and leaves,
// never commands, menus, keys or components.

import { get, writable, type Readable } from 'svelte/store';
import { showAlert } from 'osmium-ui';
import type {
  AlertButtons,
  AlertKind,
  AlertOptions,
  AlertResult,
  HostedWindow,
  OsmiumAlert
} from 'osmium-ui';
import { formatClock, plural } from '$lib/util/format';
import type { ScanEvent } from '$lib/util/scanEvents';
import { scanEvents } from '$lib/util/scanEvents';
import { scanStore } from '$lib/util/scanStore';
import { explainError } from './errorText';

// ---- alerts --------------------------------------------------------------

let hosted: HostedWindow | null = null;

/** The window alerts are centered on and drawn over. */
export function bindWindow(h: HostedWindow): void {
  hosted = h;
}

interface QueuedAlert {
  readonly key: string;
  readonly kind: AlertKind;
  readonly message: string;
  readonly explanation: string | undefined;
  readonly buttons: AlertButtons;
  readonly result: Promise<AlertResult>;
  readonly resolve: (r: AlertResult) => void;
  alert: OsmiumAlert | null;
}

/** Waiting alerts; the first one is showing when `showing` is set. */
let queue: QueuedAlert[] = [];
let showing: QueuedAlert | null = null;

function enqueue(
  kind: AlertKind,
  message: string,
  explanation: string | undefined,
  buttons: AlertButtons
): Promise<AlertResult> {
  const text = explanation || undefined;
  const key = `${message}\n${text ?? ''}`;
  const same = queue.find((q) => q.key === key);
  if (same) return same.result;

  let resolve!: (r: AlertResult) => void;
  const result = new Promise<AlertResult>((r) => {
    resolve = r;
  });
  queue.push({ key, kind, message, explanation: text, buttons, result, resolve, alert: null });
  showNext();
  return result;
}

function showNext(): void {
  if (showing !== null || queue.length === 0) return;

  const entry = queue[0];
  showing = entry;
  // An alert over a 23px collapsed window would hang off it; Osmium
  // re-centers the alert when the window grows back.
  if (hosted?.shaded) hosted.setShaded(false);

  // Before the page binds its window (never in practice), center on
  // the page instead.
  const place: Pick<AlertOptions, 'position' | 'parent'> = hosted
    ? { position: 'parent', parent: hosted.window }
    : { position: 'screen' };

  try {
    entry.alert = showAlert({
      kind: entry.kind,
      modality: 'movable',
      ...place,
      message: entry.message,
      explanation: entry.explanation,
      buttons: entry.buttons
    });
  } catch (error) {
    // showAlert throws only for a programming error; don't let one
    // bad alert hold up the ones behind it.
    console.error('Lantenna couldn’t show an alert:', error);
    finish(entry, 'dismissed');
    return;
  }

  void entry.alert.result.then((r) => finish(entry, r));
}

function finish(entry: QueuedAlert, r: AlertResult): void {
  const i = queue.indexOf(entry);
  if (i >= 0) queue.splice(i, 1);
  if (showing === entry) showing = null;
  entry.resolve(r);
  showNext();
}

/** Close the alert showing and drop the waiting ones ("dismissed"). */
function closeAlerts(): void {
  const waiting = queue.filter((q) => q !== showing);
  const open = showing;
  queue = [];
  showing = null;
  for (const entry of waiting) entry.resolve('dismissed');
  open?.alert?.close();
}

/** A movable stop alert with an OK button (5.1): something failed. */
export function stopAlert(message: string, explanation?: string): Promise<AlertResult> {
  return enqueue('stop', message, explanation, { ok: 'OK' });
}

/** A movable note alert, OK unless `buttons` says otherwise. */
export function noteAlert(o: {
  message: string;
  explanation?: string;
  buttons?: AlertButtons;
}): Promise<AlertResult> {
  return enqueue('note', o.message, o.explanation, o.buttons ?? { ok: 'OK' });
}

// ---- host status line ----------------------------------------------------

/** Each host's latest note. A deep scan of one host can report while
 * another is selected (and woken): one slot would lose a result. */
const notes = new Map<string, string>();
const shownNote = writable<{ ip: string; text: string } | null>(null);

/** The selected host's status line (5.3): one IP's latest per-host
 * result, cleared when another host is selected. */
export const hostNote: Readable<{ ip: string; text: string } | null> = { subscribe: shownNote.subscribe };

/** Publish the selected host's note, only when it changed. */
function showSelectedNote(selectedIp: string | null): void {
  const text = selectedIp === null ? undefined : notes.get(selectedIp);
  const next = selectedIp !== null && text !== undefined ? { ip: selectedIp, text } : null;
  const current = get(shownNote);
  if (current?.ip === next?.ip && current?.text === next?.text) return;
  shownNote.set(next);
}

/** Set `ip`'s status line (5.3 texts). An empty text removes it: a
 * failure is an alert, so "Sending a wake-up packet…" must not stay. */
export function setHostNote(ip: string, text: string): void {
  if (text === '') notes.delete(ip);
  else notes.set(ip, text);
  showSelectedNote(get(scanStore).selectedHostIp);
}

// ---- scan events -----------------------------------------------------------

type ErrorKind = 'init' | 'start' | 'scan';

const lastErrorStore = writable<{ kind: ErrorKind; message: string } | null>(null);

/** The kind of the last init-failed / start-failed / scan-error event,
 * for the header's error line (5.2 rows 10 and 11). */
export const lastError: Readable<{ kind: 'init' | 'start' | 'scan'; message: string } | null> = {
  subscribe: lastErrorStore.subscribe
};

/** 5.3: "5 open ports", "1 open port", "no open ports". */
function openPortsText(n: number): string {
  return n === 0 ? 'no open ports' : plural(n, 'open port');
}

function onScanEvent(e: ScanEvent): void {
  switch (e.type) {
    case 'init-failed':
      lastErrorStore.set({ kind: 'init', message: e.message });
      void stopAlert('Lantenna couldn’t start its scanner.', explainError(e.message));
      return;
    case 'start-failed':
      lastErrorStore.set({ kind: 'start', message: e.message });
      void stopAlert('The scan couldn’t start.', explainError(e.message));
      return;
    case 'scan-error':
      lastErrorStore.set({ kind: 'scan', message: e.message });
      void stopAlert('Lantenna couldn’t finish scanning the network.', explainError(e.message));
      return;
    case 'cancel-failed':
      void stopAlert('Lantenna couldn’t stop the scan.', explainError(e.message));
      return;
    case 'no-interface':
      void stopAlert(
        'Lantenna can’t scan without a network interface.',
        'Choose a network interface from the Interface pop-up menu, then click Scan.'
      );
      return;
    case 'deep-scan-busy':
      setHostNote(e.ip, 'A deep scan is already running.');
      return;
    case 'deep-scan-done':
      setHostNote(e.ip, `Deep scan finished at ${formatClock(new Date())}: ${openPortsText(e.openPorts)}.`);
      return;
    case 'deep-scan-failed':
      // Failures are alerts, never status lines: drop the host's older
      // note, which no longer describes it.
      setHostNote(e.ip, '');
      void stopAlert(`Lantenna couldn’t deep scan ${e.ip}.`, explainError(e.message));
      return;
    case 'scan-complete':
      // The header's idle sentence (5.2 row 15) says it.
      return;
  }
}

/** Subscribe to scanEvents; returns the disposer. Also drops a host's
 * note when another host is selected. The disposer closes open alerts,
 * drops waiting ones and forgets the window. */
export function installFeedback(): () => void {
  const unsubscribeEvents = scanEvents.subscribe(onScanEvent);

  let selectedIp = get(scanStore).selectedHostIp;
  const unsubscribeSelection = scanStore.subscribe(({ selectedHostIp }) => {
    if (selectedHostIp === selectedIp) return;
    if (selectedIp !== null) notes.delete(selectedIp);
    selectedIp = selectedHostIp;
    showSelectedNote(selectedHostIp);
  });

  return () => {
    unsubscribeEvents();
    unsubscribeSelection();
    closeAlerts();
    hosted = null;
  };
}
