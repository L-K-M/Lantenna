// Owner: unit C (spec 8.4). Spec: 2.7 (General: name field), 3.1 (1.12).
//
// The General tab's name field is the rename control (Finder Get Info).
// Pure rules: what the field shows for a host, and what committing its
// text does to the host's custom name. The component decides when to
// commit (Return, focusout, a selection change) and applies the result
// with scanStore.setCustomName.

import type { Host } from '$lib/types';

/** What committing the name field does to the custom name. */
export type NameCommit =
  | { readonly action: 'none' }
  | { readonly action: 'set'; readonly name: string }
  | { readonly action: 'clear' };

const NO_CHANGE: NameCommit = { action: 'none' };

/** The detected name as the field shows it: without a trailing ".local"
 * (as icon labels show it); empty when nothing was detected. */
export function detectedDisplayName(host: Host): string {
  return host.name?.replace(/\.local$/, '') ?? '';
}

/** The field's value: the custom name, else the detected display name,
 * else empty (no placeholder). */
export function nameFieldValue(host: Host, customName: string | null): string {
  return customName || detectedDisplayName(host);
}

/**
 * The commit rule of 2.7: the text is trimmed; empty clears the custom
 * name; the detected display name while no custom name exists changes
 * nothing (so focusing and leaving an untouched field never freezes the
 * detected name into a custom one); the current custom name changes
 * nothing; anything else becomes the custom name.
 */
export function commitName(text: string, host: Host, customName: string | null): NameCommit {
  const name = text.trim();

  if (!name) return customName ? { action: 'clear' } : NO_CHANGE;
  if (name === customName) return NO_CHANGE;
  if (!customName && name === detectedDisplayName(host)) return NO_CHANGE;

  return { action: 'set', name };
}
