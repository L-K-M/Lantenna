// Owner: unit D (spec 8.4). Spec: 5.1 to 5.5.
//
// SCAFFOLD STUB: alerts are logged with console.warn and resolve
// "dismissed" without showing anything; the host note and the last
// error stay null; installFeedback subscribes to nothing.
// Final contract: installFeedback() subscribes to scanEvents and turns
// them into stop alerts, host notes and lastError; alerts are movable
// stop/note alerts over the bound window, queued one at a time (an
// identical message+explanation already queued is dropped), the window
// unshaded first; the disposer closes alerts still open.

import { readable, type Readable } from 'svelte/store';
import type { AlertButtons, AlertResult, HostedWindow } from 'osmium-ui';

/** The window alerts are centered on and drawn over. */
export function bindWindow(h: HostedWindow): void {}

export function stopAlert(message: string, explanation?: string): Promise<AlertResult> {
  console.warn('Stop alert (feedback.ts is a stub):', message, explanation ?? '');
  return Promise.resolve('dismissed');
}

export function noteAlert(o: {
  message: string;
  explanation?: string;
  buttons?: AlertButtons;
}): Promise<AlertResult> {
  console.warn('Note alert (feedback.ts is a stub):', o.message, o.explanation ?? '');
  return Promise.resolve('dismissed');
}

/** The selected host's status line (5.3): one IP's latest per-host
 * result, cleared when another host is selected. */
export const hostNote: Readable<{ ip: string; text: string } | null> = readable(null);

export function setHostNote(ip: string, text: string): void {}

/** The kind of the last init-failed / start-failed / scan-error event,
 * for the header's error line (5.2 rows 10 and 11). */
export const lastError: Readable<{ kind: 'init' | 'start' | 'scan'; message: string } | null> =
  readable(null);

/** Subscribe to scanEvents; returns the disposer. */
export function installFeedback(): () => void {
  return () => {};
}
