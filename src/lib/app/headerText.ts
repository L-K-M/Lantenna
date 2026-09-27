// Owner: unit D (spec 8.4). Spec: 5.2, 5.6.
//
// SCAFFOLD STUB: headerState returns an empty, idle header.
// Final contract: pure; the first matching row of table 5.2 decides the
// text, busy flag and progress bar; `announce` changes only when the
// kind of state changes (5.6).

import type { BalloonHelpState } from 'osmium-ui';
import type { NetworkInterface } from '$lib/types';
import type { ScanProgressState, ScanStoreState } from '$lib/util/scanStore';
import type { HostModel } from './hostModel';

export interface HeaderInput {
  store: ScanStoreState;
  progress: ScanProgressState;
  model: HostModel;
  lastError: { kind: 'init' | 'start' | 'scan'; message: string } | null;
  selectedInterface: NetworkInterface | null;
  balloons: BalloonHelpState;
}

export interface HeaderState {
  text: string;
  /** For the visually hidden live region; changes only on state-kind changes. */
  announce: string;
  /** Chasing arrows would run (Osmium N1, not yet available). */
  busy: boolean;
  progress: { value: number; max: number; label: string } | null;
  icon: 'stop' | 'caution' | null;
}

export function headerState(input: HeaderInput, now: Date): HeaderState {
  return { text: '', announce: '', busy: false, progress: null, icon: null };
}
