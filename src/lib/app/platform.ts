// Owner: scaffold (spec 8.3), complete. Spec: 0, 2.5, 3.2, 4.2, 4.3.
//
// Which host the page runs on. macOS gets the native menu bar and
// Command keys; Linux gets the Osmium menu bar inside the window and
// Control keys. Fixed for the page's lifetime.

export type Platform = 'mac' | 'linux';

/** Mock mode (vite dev --mode mock) accepts ?platform=mac|linux. */
function detectPlatform(): Platform {
  if (import.meta.env.MODE === 'mock') {
    const forced = new URLSearchParams(location.search).get('platform');
    if (forced === 'mac' || forced === 'linux') return forced;
  }

  return /Mac/.test(navigator.userAgent) ? 'mac' : 'linux';
}

export const platform: Platform = detectPlatform();
export const isMac: boolean = platform === 'mac';
/** The command modifier's name in balloon texts ("Command-R"). */
export const cmdName: 'Command' | 'Control' = isMac ? 'Command' : 'Control';
