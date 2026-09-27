// Owner: unit D (spec 8.4). Spec: 5.4 (Update timing), 4.1 (app.checkUpdates).
//
// SCAFFOLD STUB: no update check runs.
// Final contract: scheduleUpdateCheck() runs checkForUpdate() after
// scanStore.init() (daily throttle, skip list, silent failures) and
// shows a found update once per launch as a note alert, at the first
// moment the window is active, not shaded, not scanning and has no
// alert up. checkForUpdatesNow() is the Check for Updates… command:
// ignores throttle and skip list, reports "up to date" or a stop alert.

/** Start the launch-time check; returns the disposer. */
export function scheduleUpdateCheck(): () => void {
  return () => {};
}

/** Check for Updates… (manual). Resolves when its alert is answered. */
export function checkForUpdatesNow(): Promise<void> {
  return Promise.resolve();
}
