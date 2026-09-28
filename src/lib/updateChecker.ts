import { invoke } from '@tauri-apps/api/core';
import { readString, writeString } from '$lib/util/storage';

/**
 * Lightweight in-app update check. Asks the Rust `check_self_update` command (which
 * queries GitHub's latest release) whether a newer release exists. It never downloads
 * or installs anything: `app/updates.ts` offers a found update in a note alert that
 * links to the GitHub release page.
 *
 * Reusable across the Tauri apps: the repo to check lives in the Rust `updates.rs`
 * (`OWNER`/`REPO`). Settings go through `storage.ts`, so an unavailable or full
 * localStorage never breaks a check.
 */
export interface UpdateInfo {
  version: string;
  url: string;
  notes: string | null;
}

const SKIP_KEY = 'updateChecker.skippedVersion';
const LAST_CHECK_KEY = 'updateChecker.lastCheck';
const ONE_DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Returns an update to show, or `null`. Throttled to once a day and silenced for a
 * version the user chose to skip. Network/availability failures resolve to `null`
 * (nothing is offered). Pass `{ force: true }` to ignore the throttle and the skip
 * list. A manual check that must tell failure from "up to date" uses
 * `checkForUpdateNow` instead.
 */
export async function checkForUpdate({ force = false } = {}): Promise<UpdateInfo | null> {
  if (!force) {
    const last = Number(readString(LAST_CHECK_KEY) ?? '0');
    if (Number.isFinite(last) && Date.now() - last < ONE_DAY_MS) return null;
  }

  let info: UpdateInfo | null;
  try {
    info = await invoke<UpdateInfo | null>('check_self_update');
  } catch (error) {
    console.warn('Update check failed:', error);
    return null; // leave lastCheck untouched so the next launch retries
  }
  writeString(LAST_CHECK_KEY, String(Date.now()));

  if (!info) return null;
  if (!force && readString(SKIP_KEY) === info.version) return null;
  return info;
}

/**
 * Check for Updates… (manual): the newer release, or `null` when this is the latest
 * version. Ignores the daily throttle and the skip list, and **rejects** when the
 * check fails (with the backend's message, such as `GitHub returned HTTP 503`), so
 * the caller can tell "up to date" from "couldn't check".
 */
export async function checkForUpdateNow(): Promise<UpdateInfo | null> {
  const info = await invoke<UpdateInfo | null>('check_self_update');
  writeString(LAST_CHECK_KEY, String(Date.now()));
  return info ?? null;
}

/** Don't surface this version again (the alert's "Skip This Version"). */
export function skipVersion(version: string): void {
  writeString(SKIP_KEY, version);
}

/**
 * Open the release page in the user's default browser (via the bundled Rust command).
 * Rejects with the backend's message when it can't (`Only http(s) URLs may be opened`,
 * or the OS's error), so the caller can say so.
 */
export async function openReleasePage(url: string): Promise<void> {
  await invoke('open_release_url', { url });
}
