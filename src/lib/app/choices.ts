// Owner: integration. Spec: 4.1 (Scan and View menus), 2.3 (the strip's
// pop-ups).
//
// The Depth and Show choices with their titles, in menu order: one table
// for the menus (commands.ts) and the strip's pop-ups (ControlStrip), so
// they can't disagree. A leaf module (types only), which both can import.

import type { ScanApproach } from '$lib/types';
import type { ShowScope } from './ui';

export const DEPTHS: readonly (readonly [ScanApproach, string])[] = [
  ['fast', 'Fast'],
  ['balanced', 'Balanced'],
  ['thorough', 'Thorough']
];

export const SCOPES: readonly (readonly [ShowScope, string])[] = [
  ['all', 'All Hosts'],
  ['favorites', 'Favorite Hosts'],
  ['new', 'New Hosts']
];
