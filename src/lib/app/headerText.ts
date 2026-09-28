// Owner: unit D (spec 8.4). Spec: 5.2, 5.6.
//
// Pure: what the Finder window header under the control strip says.
// The first matching row of table 5.2 decides the text, the busy flag
// and the progress bar.
//
// `announce` is what the header's visually hidden live region says
// (5.6). It changes when the kind of state changes (scan started, phase
// changed, stopping, finished, error), not with every count: during a
// phase it names the phase without its counts; idle, it is the unfiltered
// idle sentence (row 15), so typing in Find or changing Show: says
// nothing, while hiding a host is heard.

import type { BalloonHelpState } from 'osmium-ui';
import type { NetworkInterface, ScanProgress } from '$lib/types';
import type { ScanProgressState, ScanStoreState } from '$lib/util/scanStore';
import { formatCount, formatWhen, plural } from '$lib/util/format';
import { MAX_SCAN_HOSTS } from '$lib/util/scanLimits';
import { explainError } from './errorText';
import type { HostModel } from './hostModel';

export interface HeaderInput {
  store: ScanStoreState;
  progress: ScanProgressState;
  model: HostModel;
  lastError: { kind: 'init' | 'start' | 'scan'; message: string } | null;
  selectedInterface: NetworkInterface | null;
  balloons: BalloonHelpState;
}

/** The header's progress bar: scanned of total, or Mac OS 8's
 * indeterminate barber pole (Osmium N2) for a phase with no counts. */
export type HeaderBar =
  | { value: number; max: number; label: string }
  | { indeterminate: true; label: string };

export interface HeaderState {
  text: string;
  /** For the visually hidden live region; changes only on state-kind changes. */
  announce: string;
  /** The chasing arrows turn (Osmium N1). */
  busy: boolean;
  progress: HeaderBar | null;
  /** A small alert icon before the text (Osmium N3, not yet available):
   * stop for the error lines, caution for the interface problems. */
  icon: 'stop' | 'caution' | null;
  /** The end of `text` the header leaves out when the whole sentence
   * doesn't fit (row 14's Balloon Help hint, at the minimum width with a
   * long interface name); `announce` keeps it. */
  optional?: string;
}

/** The addresses a scan of `iface` probes: each of its subnet's host
 * addresses but this computer's own, which is always one of them and
 * which the backend never probes (scanner.rs, build_scan_targets); a
 * larger subnet is sampled down to MAX_SCAN_HOSTS (spec 3.1, 1.7). */
function scanTargets(iface: NetworkInterface): { count: number; sampled: boolean } {
  const others = Math.max(0, iface.host_count - 1);
  return others > MAX_SCAN_HOSTS ? { count: MAX_SCAN_HOSTS, sampled: true } : { count: others, sampled: false };
}

const BALLOON_HINT = ' For help, choose Show Balloons from the Help menu.';

type Bar = HeaderState['progress'];

/** A row whose visible text is also what the live region says. */
function row(text: string, busy: boolean, icon: HeaderState['icon'] = null): HeaderState {
  return { text, announce: text, busy, progress: null, icon };
}

function indeterminate(label: string): Bar {
  return { indeterminate: true, label };
}

/** scanned / total, or no bar before the phase knows its total. */
function bar(p: ScanProgress, label: string): Bar {
  if (p.total <= 0) return null;
  return { value: Math.min(Math.max(0, p.scanned), p.total), max: p.total, label };
}

/** Rows 3 to 8: a network scan, from its latest progress event. */
function scanRow(p: ScanProgress | null, iface: NetworkInterface | null): HeaderState {
  if (p === null || (p.phase === 'discovery' && p.total <= 0)) return row('Starting scan…', true);

  const scanned = formatCount(p.scanned);
  let text: string;
  let announce: string;
  switch (p.phase) {
    case 'discovery': {
      const sampled = iface !== null && scanTargets(iface).sampled;
      const of = sampled ? `${formatCount(p.total)} sampled addresses` : plural(p.total, 'address', 'addresses');
      text = `Looking for hosts: ${scanned} of ${of}, ${plural(p.found, 'host')} found.`;
      announce = 'Looking for hosts…';
      break;
    }
    case 'ping':
      text = `Pinging quiet addresses: ${scanned} of ${formatCount(p.total)}, ${plural(p.found, 'host')} found.`;
      announce = 'Pinging quiet addresses…';
      break;
    case 'ports':
      text = `Probing ports: ${scanned} of ${plural(p.total, 'host')}.`;
      announce = 'Probing ports…';
      break;
    case 'fingerprint': {
      // One event per scan with the host count and no per-host progress:
      // the indeterminate bar (Osmium N2).
      const identifying = p.total > 0 ? `Identifying ${plural(p.total, 'host')}…` : 'Finishing scan…';
      return { ...row(identifying, true), progress: indeterminate(`Scan progress: ${identifying}`) };
    }
  }

  return { text, announce, busy: true, progress: bar(p, `Scan progress: ${text}`), icon: null };
}

/** Row 2: the bar keeps what the phase showed. */
function stoppingRow(p: ScanProgress | null): HeaderState {
  const text = 'Stopping scan…';
  const label = `Scan progress: ${text}`;
  const shown = p === null ? null : p.phase === 'fingerprint' ? indeterminate(label) : bar(p, label);
  return { ...row(text, true), progress: shown };
}

/** Row 9: a deep scan while no network scan runs. */
function deepScanRow(p: ScanProgress): HeaderState {
  const ip = p.current_ip ?? '';
  const pending = ip ? `Deep scan of ${ip}…` : 'Deep scan…';
  if (p.total <= 0) return row(pending, true);

  const text = `Deep scan of ${ip}: ${formatCount(p.scanned)} of ${plural(p.total, 'port')}, ${formatCount(p.found)} open.`;
  const label = `Deep scan progress for ${ip}: ${formatCount(p.scanned)} of ${plural(p.total, 'port')}`;
  return { text, announce: pending, busy: true, progress: bar(p, label), icon: null };
}

/** " Last scan today at 3:42 PM." or " The last scan was stopped …",
 * nothing before the first scan (or for an unreadable date). */
function lastScanSentence(store: ScanStoreState, now: Date): string {
  if (store.lastScanAt === null || Number.isNaN(Date.parse(store.lastScanAt))) return '';

  const when = formatWhen(store.lastScanAt, now);
  return store.lastScanCancelled ? ` The last scan was stopped ${when}.` : ` Last scan ${when}.`;
}

/** Rows 15 and 16. */
function idleRow(input: HeaderInput, now: Date): HeaderState {
  const { model } = input;
  const counts = [plural(model.universe, 'host')];
  if (model.newCount > 0) counts.push(`${formatCount(model.newCount)} new`);
  if (model.hiddenCount > 0) counts.push(`${formatCount(model.hiddenCount)} hidden`);

  const last = lastScanSentence(input.store, now);
  const unfiltered = `${counts.join(', ')}.${last}`;
  // The Show scope or the Find query leaves hosts out.
  const narrowed = model.rows.length < model.universe;
  const text = narrowed
    ? `Showing ${formatCount(model.rows.length)} of ${plural(model.universe, 'host')}.${last}`
    : unfiltered;

  return { text, announce: unfiltered, busy: false, progress: null, icon: null };
}

export function headerState(input: HeaderInput, now: Date): HeaderState {
  const { store, progress } = input;
  const scan = progress.progress;

  if (store.loading) return row('Reading the last scan…', true);
  if (store.stopping) return stoppingRow(scan);
  if (store.scanning || scan?.running === true) return scanRow(scan, input.selectedInterface);

  const deep = progress.hostScanProgress;
  if (deep?.running === true) return deepScanRow(deep);

  if (store.error !== null) {
    const explanation = explainError(store.error);
    const lead =
      input.lastError?.kind === 'init' ? 'Lantenna couldn’t start its scanner.' : 'The last scan didn’t finish.';
    return row(explanation ? `${lead} ${explanation}` : lead, false, 'stop');
  }

  if (store.interfaces.length === 0) {
    return row('No network interface with an IPv4 subnet was found.', false, 'caution');
  }

  const iface = input.selectedInterface;
  if (iface !== null && iface.host_count === 0) {
    return row(
      `${iface.name} (${iface.subnet}) has no other addresses to scan. Choose another interface.`,
      false,
      'caution'
    );
  }

  if (iface !== null && store.lastScanAt === null && store.hosts.length === 0) {
    const hint = input.balloons === 'hidden' ? BALLOON_HINT : '';
    // The count row 4 will report; a larger subnet is sampled: say so,
    // as row 4 will (3.1, 1.7).
    const targets = scanTargets(iface);
    const addresses = targets.sampled
      ? `${formatCount(targets.count)} sampled addresses`
      : plural(targets.count, 'address', 'addresses');
    const state = row(
      `Click Scan to search ${addresses} on ${iface.name} (${iface.subnet}). This computer is ${iface.ip}.${hint}`,
      false
    );
    return hint ? { ...state, optional: hint } : state;
  }

  return idleRow(input, now);
}
