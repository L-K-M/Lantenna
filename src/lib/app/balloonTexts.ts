// Owner: unit E (spec 8.4). Spec: 4.5.
//
// Created by the scaffold with the texts of table 4.5, so units B, C and
// D attach balloons to their own controls (`use:balloon`) with one set of
// words. Constants for the fixed texts; functions for the ones that
// follow state. Pass a function's result, `use:balloon={scanBalloon(state)}`
// or a $derived of it, so Svelte hands each new text to the action,
// which updates the description and an open balloon. Osmium would re-run
// a content function only when the control's attributes change, so a
// dimmed control's reason would go stale while it stays dimmed. A
// `dimmedFor` argument names why the control is dimmed; null (enabled,
// or dimmed for another reason, such as no selection) adds nothing.

import type { ColumnId } from './columns';
import type { InfoTab } from './ui';
import { cmdName } from './platform';

function withNote(text: string, note: string | null): string {
  return note === null ? text : `${text}\n\n${note}`;
}

export function interfaceBalloon(dimmedFor: 'scanning' | null): string {
  return withNote(
    'Interface pop-up menu\n\nChooses the network connection to scan. Lantenna looks at every address in its subnet, such as 192.168.1.0/24. If two entries have the same name, choose the one with your subnet.',
    dimmedFor === 'scanning' ? 'Not available while a scan is running.' : null
  );
}

export const DEPTH_BALLOON =
  'Depth pop-up menu\n\nChooses how thoroughly to scan. Fast checks common ports and finds hosts over TCP only. Balanced (recommended) checks more ports and also pings quiet addresses. Thorough also checks every port from 1 to 2048 and takes longest.\n\nSubnets with more than 4,096 addresses are sampled evenly.';

/** The Scan/Stop button: "idle" also covers dimmed while loading. */
export type ScanButtonState = 'idle' | 'noInterface' | 'stop' | 'stopping';

export function scanBalloon(state: ScanButtonState): string {
  switch (state) {
    case 'idle':
      return `Scan button\n\nSearches the chosen network for computers and devices. Hosts appear as they are found. Keyboard: ${cmdName}-R.`;
    case 'noInterface':
      return 'Scan button\n\nNot available because no network interface was found.';
    case 'stop':
      return `Stop button\n\nStops the scan. Hosts found so far are kept and identified. Keyboard: ${cmdName}-period.`;
    case 'stopping':
      return 'Stop button\n\nLantenna is finishing the current step and identifying the hosts it found.';
  }
}

export const SHOW_BALLOON =
  'Show pop-up menu\n\nChooses which hosts the list shows: all of them, only your favorites, or only the hosts that are new since the previous scan.';

export function showHiddenBalloon(dimmedFor: 'noneHidden' | null): string {
  return withNote(
    'Show hidden hosts checkbox\n\nWhen checked, hosts you have hidden are listed too, in gray. To hide a host, select it and choose Hide Host from the Host menu.',
    dimmedFor === 'noneHidden' ? 'Not available because no hosts are hidden.' : null
  );
}

export const FIND_BALLOON =
  'Find field\n\nShows only the hosts that match what you type: a name, IP address, vendor, kind, MAC address, port number or service. Separate words to match all of them. To clear the field, press Escape.';

export const HEADER_BALLOON = 'Window header\n\nShows how many hosts the list holds and what the scan is doing.';

export const PROGRESS_BALLOON = 'Progress bar\n\nShows how far the current phase of the scan has come.';

/** Header title and the words for "sort the list by …". */
const SORT_WORDS: Readonly<Record<Exclude<ColumnId, 'favorite'>, readonly [string, string]>> = {
  name: ['Name', 'name'],
  ip: ['IP Address', 'IP address'],
  status: ['Status', 'status'],
  kind: ['Kind', 'kind'],
  vendor: ['Vendor', 'vendor'],
  ports: ['Ports', 'ports'],
  lastSeen: ['Last Seen', 'last seen']
};

/** A list column header's balloon; the star column's has its own text. */
export function columnBalloon(column: ColumnId): string {
  if (column === 'favorite') {
    return 'Favorites column\n\nClick here to list favorite hosts first. To make a host a favorite, click the star in its row, or select the host and press the Space bar.';
  }

  const [title, words] = SORT_WORDS[column];
  return `${title} column\n\nClick here to sort the list by ${words}. To reverse the order, click the sort order button above the scroll bar.`;
}

export const SORT_ORDER_BALLOON = 'Sort order button\n\nReverses the order of the list.';

/** The list's grid and the icon grid. */
export const HOST_LIST_BALLOON =
  'Host list\n\nThe computers and devices Lantenna found. To open a host, double-click it. For more commands, Control-click it.';

export const TAB_BALLOON: Readonly<Record<InfoTab, string>> = {
  general: 'General tab\n\nShows the host’s name, addresses and state.',
  ports: 'Ports tab\n\nShows the host’s open ports and the software they announced.',
  fingerprint: 'Fingerprint tab\n\nShows what Lantenna guessed about the device, and why.'
};

export const NAME_BALLOON =
  'Name\n\nType a name that is easier to remember than the host’s address, then press Return. To use the detected name again, delete the name and press Return.';

export const FAVORITE_BALLOON =
  'Favorite checkbox\n\nKeeps this host in the list even when a scan doesn’t find it, and lists it first.';

export const HIDDEN_BALLOON =
  'Hidden checkbox\n\nRemoves this host from the list. To see hidden hosts, check “Show hidden hosts”.';

export const PORTS_BALLOON =
  'Port list\n\nThe open ports Lantenna found on this host. To open a service, double-click it.';

export const NOTES_BALLOON =
  'Sources and notes\n\nWhere each fingerprint clue came from, and what Lantenna concluded.';

export const STATUS_BALLOON = 'Status\n\nThe result of the last Wake or Deep Scan for this host.';

export function wakeBalloon(dimmedFor: 'noMac' | null): string {
  return withNote(
    'Wake button\n\nSends a Wake-on-LAN packet to this host’s MAC address. The device wakes up only if Wake-on-LAN is turned on in its settings.',
    dimmedFor === 'noMac' ? 'Not available because this host’s MAC address is unknown.' : null
  );
}

export function deepScanBalloon(dimmedFor: 'busy' | null): string {
  return withNote(
    `Deep Scan button\n\nChecks every port from 1 to 2048 on this host, plus the Balanced ports above 2048, and updates its services and fingerprint. Keyboard: ${cmdName}-D.`,
    dimmedFor === 'busy' ? 'Not available while another deep scan is running.' : null
  );
}

export function openBalloon(dimmedFor: 'noTarget' | null): string {
  return withNote(
    `Open button\n\nOpens the host’s web page, file server, remote login or screen sharing, whichever it offers first. Keyboard: Return or ${cmdName}-O.`,
    dimmedFor === 'noTarget' ? 'Not available because this host offers no service Lantenna can open.' : null
  );
}
