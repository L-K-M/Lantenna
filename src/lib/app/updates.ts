// Owner: unit D (spec 8.4). Spec: 5.4 (Update timing, alerts), 4.1 (app.checkUpdates).
//
// The launch-time update check and Check for Updates…. A found update is
// offered in a note alert with View on GitHub (default: opens the
// release page), Later and Skip This Version (remembers the skip).
//
// Launch: once scanStore.init() has settled (the store's `loading` first
// reads false), checkForUpdate() runs as it always did (daily throttle,
// skip list, failures silent). A found update waits for the first moment
// the window is active, not collapsed, not scanning and has no alert up,
// so it never interrupts work, and is offered once per launch.
//
// Manual: checkForUpdateNow() ignores the throttle and the skip list and
// rejects on failure, so "up to date" (a note) and "couldn't check" (a
// stop alert) can be told apart.
//
// Import direction: imports ui, scanStore, feedback and leaves only.

import { get } from 'svelte/store';
import { getVersion } from '@tauri-apps/api/app';
import { isModal, onModalChange } from 'osmium-ui';
import {
  checkForUpdate,
  checkForUpdateNow,
  openReleasePage,
  skipVersion,
  type UpdateInfo
} from '$lib/updateChecker';
import { errorMessage } from '$lib/util/errors';
import { scanStore } from '$lib/util/scanStore';
import { explainError } from './errorText';
import { noteAlert, stopAlert } from './feedback';
import { ui } from './ui';

/** An update is offered at most once per launch, by either path. */
let offered = false;

/** This build's version (tauri.conf.json), or null if Tauri can't say. */
async function appVersion(): Promise<string | null> {
  try {
    return await getVersion();
  } catch (error) {
    console.warn('Lantenna couldn’t read its version:', error);
    return null;
  }
}

/** The offer waiting for its answer. The launch check and Check for
 * Updates… can both find the update while it waits; feedback shows the
 * identical alert once and hands both the same answer, so a second
 * offer joins this one rather than acting on that answer again (one
 * View on GitHub opens the page once). */
let pendingOffer: Promise<void> | null = null;

/** The Check for Updates… in progress; choosing it again joins it. */
let manualCheck: Promise<void> | null = null;

/** Offer `info`, or join the offer already waiting. */
function offerUpdate(info: UpdateInfo, current: string | null): Promise<void> {
  pendingOffer ??= askAboutUpdate(info, current).finally(() => {
    pendingOffer = null;
  });
  return pendingOffer;
}

/** The update note alert (5.4), then what its button asks for. */
async function askAboutUpdate(info: UpdateInfo, current: string | null): Promise<void> {
  offered = true;
  const whatsNew = 'The release page on GitHub describes what’s new.';
  const result = await noteAlert({
    message: `Lantenna ${info.version} is available.`,
    explanation: current ? `You have version ${current}. ${whatsNew}` : whatsNew,
    buttons: { ok: 'View on GitHub', cancel: 'Later', other: 'Skip This Version' }
  });

  if (result === 'other') {
    skipVersion(info.version);
    return;
  }
  if (result !== 'ok') return;

  try {
    await openReleasePage(info.url);
  } catch (error) {
    await stopAlert(
      `Lantenna couldn’t open “${info.url}”.`,
      explainError(errorMessage(error, 'Failed to open the release page'))
    );
  }
}

/** Whether an update may interrupt now. */
function quietMoment(): boolean {
  const { active, shaded } = get(ui);
  return active && !shaded && !get(scanStore).scanning && !isModal();
}

/** Start the launch-time check; returns the disposer. */
export function scheduleUpdateCheck(): () => void {
  let disposed = false;
  const cleanups: (() => void)[] = [];
  const dispose = () => {
    disposed = true;
    for (const cleanup of cleanups.splice(0)) cleanup();
  };

  /** Offer `info` at the first quiet moment. */
  const offerWhenQuiet = (info: UpdateInfo, current: string | null) => {
    // Subscribers run at once; check only once all three are in place.
    let armed = false;
    const check = () => {
      if (!armed) return;
      if (offered) return dispose();
      if (!quietMoment()) return;
      dispose();
      offered = true;
      // After the current turn: when the moment comes as an alert
      // closes, that alert first gives the keyboard back.
      queueMicrotask(() => void offerUpdate(info, current));
    };
    cleanups.push(ui.subscribe(check), scanStore.subscribe(check), onModalChange(check));
    armed = true;
    check();
  };

  const run = async () => {
    const info = await checkForUpdate();
    if (disposed || info === null) return;
    const current = await appVersion();
    if (disposed) return;
    offerWhenQuiet(info, current);
  };

  // The store's subscriber runs at once; the check starts on the first
  // state that isn't loading.
  let started = false;
  const unsubscribeLoading = scanStore.subscribe(({ loading }) => {
    if (loading || started) return;
    started = true;
    queueMicrotask(() => {
      unsubscribeLoading();
      if (!disposed) void run();
    });
  });
  cleanups.push(unsubscribeLoading);

  return dispose;
}

/** Check for Updates… (manual). Resolves when its alert is answered. */
export function checkForUpdatesNow(): Promise<void> {
  manualCheck ??= checkNow().finally(() => {
    manualCheck = null;
  });
  return manualCheck;
}

async function checkNow(): Promise<void> {
  let info: UpdateInfo | null;
  try {
    info = await checkForUpdateNow();
  } catch (error) {
    await stopAlert(
      'Lantenna couldn’t check for updates.',
      explainError(errorMessage(error, 'Failed to check for updates'))
    );
    return;
  }

  const current = await appVersion();
  if (info !== null) {
    await offerUpdate(info, current);
    return;
  }

  await noteAlert({ message: current ? `Lantenna ${current} is the latest version.` : 'Lantenna is up to date.' });
}
